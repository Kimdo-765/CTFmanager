import asyncio
import json
import os
import shutil
import subprocess
import traceback
from pathlib import Path
from typing import Optional

import anyio

from modules._common import (
    collect_outputs,
    extract_cost,
    job_dir,
    log_line,
    make_main_session_options,
    prior_work_dirs,
    read_meta,
    run_main_agent_session,
    run_pre_recon,
    scan_job_for_flags,
    soft_timeout_watchdog,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.pwn.prompts import SYSTEM_PROMPT, build_user_prompt, looks_heap_advanced
from modules.settings_io import apply_to_env, get_setting


def _build_pre_recon_prompt(
    *,
    binary_name: str,
    target: str | None,
    heap_advanced: bool,
    chal_unpacked: bool,
) -> str:
    """Build the prompt for the orchestrator-driven recon subagent that
    runs BEFORE main's first turn. Recon's job: static-map the binary
    so main starts with a 2 KB inventory instead of having to do its
    own objdump walk."""
    parts: list[str] = []
    parts.append(
        "STATIC TRIAGE REQUEST (pre-flight for the main exploit writer)."
    )
    parts.append(
        f"BINARY: ./bin/{binary_name}"
        + (f"   (cwd = work dir; ./.chal-libs/ holds the chal libs)"
           if chal_unpacked else "")
    )
    if target:
        parts.append(f"REMOTE: {target}")
    parts.append(
        "If `./decomp/` is missing, run `ghiant ./bin/" + binary_name + "` "
        "ONCE to populate it (the project is cached under "
        "./.ghidra_proj/ so subsequent reads are fast)."
    )
    parts.append(
        "REPLY in ≤2 KB, as compact bullets, with these sections:\n"
        "  ARCH         — `file` summary in one line\n"
        "  PROTECTIONS  — checksec: RELRO / Stack / NX / PIE\n"
        "  LIBC         — `./.chal-libs/libc_profile.json` version + "
        "any blacklisted_techniques (read libc_profile.json if present)\n"
        "  FUNCTIONS    — names + sizes of the user-controllable funcs "
        "(main, menu handlers, parsers). Ignore stdlib stubs.\n"
        "  CANDIDATES   — ranked HIGH/MED/LOW with bug class + file:line\n"
        "                 e.g. `HIGH heap.UAF — secure_free@b21 frees "
        "without unsetting the dangling ptr` (be specific)\n"
        "  PRIMITIVES   — for each HIGH: what the attacker writes / reads / "
        "controls (8 bytes at canary? full chunk? size field?)\n"
    )
    if heap_advanced:
        parts.append(
            "HEAP CHAL — ALSO report:\n"
            "  ALLOC/FREE SIG — secure_malloc / secure_free header layout "
            "(in-band size, canary location, freelist pointer mangling?)\n"
            "  HOOKS_ALIVE   — confirm libc_profile.json's `hooks_alive` "
            "matches the actual libc (cross-check on __free_hook offset).\n"
            "  RECOMMENDED CHAIN — pick ONE from libc_profile.json's "
            "recommended_techniques given the primitives above."
        )
    parts.append(
        "DO NOT propose exploit code. DO NOT speculate. Facts only. "
        "Cite file:line / file:addr for every claim."
    )
    return "\n\n".join(parts)


def _is_shared_lib(p: Path) -> bool:
    n = p.name.lower()
    return (
        n.startswith("libc")
        or n.startswith("ld-")
        or n.startswith("ld.")
        or ".so" in n
    )


def _find_elf_or_unzip(staged_bin: Path, work_dir: Path, log_fn) -> list[Path]:
    """Find ELF binaries in `staged_bin`. If only zip/tar bundles are
    present (the standard Dreamhack / HackTheBox shape), unzip the first
    bundle into <work_dir>/chal/ and rescan there. After a successful
    unpack the originating bundle is removed from ``staged_bin`` and the
    discovered ELFs are flattened into ``staged_bin`` (so the agent's
    ``./bin/<name>`` references resolve directly) and any glibc / ld /
    chal-supplied ``lib*.so*`` files are pre-staged into
    ``<work_dir>/.chal-libs/`` so the subsequent ``chal-libc-fix`` takes
    the "physical libs bundled" fast path instead of falling back to
    a docker-pull base image fetch.

    Returns the list of ELFs found at their final ``staged_bin`` paths.
    """
    elfs: list[Path] = []

    def _scan(d: Path) -> list[Path]:
        out: list[Path] = []
        try:
            for f in d.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    head = f.read_bytes()[:4]
                except Exception:
                    continue
                if head == b"\x7fELF":
                    out.append(f)
        except Exception as e:
            log_fn(f"[autoboot] scan {d} failed: {e}")
        return out

    found = _scan(staged_bin)
    if found:
        elfs.extend(found)
        return elfs

    # No raw ELF — look for archives and unpack one.
    bundles: list[Path] = []
    try:
        for f in staged_bin.iterdir():
            if not f.is_file():
                continue
            n = f.name.lower()
            if (n.endswith(".zip") or n.endswith(".tar")
                    or n.endswith(".tar.gz") or n.endswith(".tgz")
                    or n.endswith(".tar.xz") or n.endswith(".tar.bz2")):
                bundles.append(f)
    except Exception:
        pass
    if not bundles:
        log_fn("[autoboot] no ELF and no bundle found in ./bin/ — skipping")
        return []
    bundle = bundles[0]
    out_dir = work_dir / "chal"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_fn(f"[autoboot] unpacking {bundle.name} → {out_dir}")
    try:
        if bundle.name.lower().endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(bundle) as zf:
                zf.extractall(out_dir)
        else:
            import tarfile
            with tarfile.open(bundle) as tf:
                tf.extractall(out_dir)
    except Exception as e:
        log_fn(f"[autoboot] bundle unpack failed: {e}")
        return []
    # Bundle unpacked successfully → drop the archive so ``./bin/`` only
    # holds binaries the agent should look at. Otherwise the agent sees
    # the .zip on its first ``ls ./bin/`` and wastes 3-4 turns
    # re-extracting (observed live on 5963af004fdc).
    try:
        bundle.unlink()
        log_fn(f"[autoboot] removed bundle {bundle.name} from ./bin/")
    except OSError as e:
        log_fn(f"[autoboot] could not remove bundle: {e}")

    extracted_elfs = _scan(out_dir)
    if not extracted_elfs:
        log_fn(f"[autoboot] bundle {bundle.name} contained no ELF")
        return []

    # Split into challenge binaries (non-.so) and shared libs. Flatten
    # the binaries into staged_bin so the prompt's ./bin/<name> path
    # resolves; copy the .so / ld-* libs into .chal-libs so chal-libc-fix
    # can take the bundled-libs fast path without needing JOB_ID +
    # HOST_DATA_DIR for a docker-pull fallback.
    chal_libs_dir = work_dir / ".chal-libs"
    flattened: list[Path] = []
    for src in extracted_elfs:
        try:
            if _is_shared_lib(src):
                chal_libs_dir.mkdir(parents=True, exist_ok=True)
                # libc-2.23.so → keep as libc.so.6 alias the linker expects
                target_name = src.name
                if target_name.startswith("libc-") and target_name.endswith(".so"):
                    alias = chal_libs_dir / "libc.so.6"
                    if not alias.exists():
                        shutil.copy2(src, alias)
                        alias.chmod(0o755)
                dst = chal_libs_dir / target_name
                if not dst.exists():
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)
            else:
                dst = staged_bin / src.name
                if not dst.exists() or dst.stat().st_size != src.stat().st_size:
                    shutil.copy2(src, dst)
                    dst.chmod(0o755)
                flattened.append(dst)
        except Exception as e:
            log_fn(f"[autoboot] flatten {src.name} failed: {e}")

    if flattened:
        log_fn(
            f"[autoboot] flattened {len(flattened)} binary/binaries into "
            f"./bin/: {', '.join(p.name for p in flattened)}"
        )
    if chal_libs_dir.is_dir():
        libs = sorted(p.name for p in chal_libs_dir.iterdir() if p.is_file())
        if libs:
            log_fn(
                f"[autoboot] pre-staged libs into ./.chal-libs/: "
                f"{', '.join(libs)}"
            )

    elfs.extend(flattened or extracted_elfs)
    return elfs


def _autobootstrap_libc(
    staged_bin: Path,
    work_dir: Path,
    log_fn,
    *,
    job_id: str,
    timeout_s: int = 180,
) -> tuple[Path | None, str | None]:
    """Run `chal-libc-fix` against the first ELF in <staged_bin> BEFORE the
    agent starts, so ./.chal-libs/libc_profile.json is always on disk when
    the agent enters its first turn.

    Returns ``(profile_path, elf_basename)``:
      - ``profile_path`` — path to libc_profile.json on success, else None.
      - ``elf_basename`` — basename of the canonical chal ELF inside
        ``./bin/`` (e.g. ``chall``) so the caller can use it as
        ``binary_name`` in the agent prompt. Mismatched / missing means
        autoboot couldn't pick a canonical binary; caller falls back to
        the upload filename.

    Why: models repeatedly dove into decompile analysis and never
    looped back to step 5 of the workflow (chal-libc-fix). With the
    profile missing, the rest of the heap pipeline (scaffold templates,
    heap-probe, judge failure_code matrix) operates on absent data.
    Pre-baking it shifts the pipeline from model-action-dependent to
    deterministic.

    .zip / .tar bundles (Dreamhack standard) are auto-unpacked into
    <work_dir>/chal/ first; the discovered ELFs are flattened into
    ``./bin/`` and any chal-supplied libc/ld/.so files are pre-staged
    into ``./.chal-libs/`` (see ``_find_elf_or_unzip``).

    Best-effort: any failure is logged and swallowed; the agent can still
    try chal-libc-fix manually from its prompt.
    """
    elf_candidates = _find_elf_or_unzip(staged_bin, work_dir, log_fn)
    if not elf_candidates:
        log_fn("[autoboot] no ELF found in ./bin/ — skipping chal-libc-fix")
        return (None, None)
    # Pick the largest ELF inside ./bin/ as the canonical chal — small
    # auxiliary binaries (helpers, libsalloc-style wrappers) sort below
    # the real challenge by size.
    bin_elfs = [
        e for e in elf_candidates if e.parent.resolve() == staged_bin.resolve()
    ]
    if not bin_elfs:
        bin_elfs = elf_candidates
    bin_elfs.sort(key=lambda p: p.stat().st_size, reverse=True)
    elf = bin_elfs[0]
    elf_basename = elf.name if elf.parent.resolve() == staged_bin.resolve() else None

    prob = work_dir / "prob"
    try:
        if not prob.exists() or prob.stat().st_size != elf.stat().st_size:
            shutil.copy2(elf, prob)
            prob.chmod(0o755)
    except Exception as e:
        log_fn(f"[autoboot] could not stage ./prob: {e}")
        return (None, elf_basename)
    cmd = ["chal-libc-fix", str(prob)]
    log_fn(f"[autoboot] running: {' '.join(cmd)}")
    # Inherit worker env + force-set JOB_ID / HOST_DATA_DIR. chal-libc-fix
    # uses these to bind-mount the job dir into a sibling docker for
    # base-image extraction; without them it aborts before pulling and
    # the binary runs against the wrong libc. JOB_ID isn't in the worker
    # env at autoboot time because it's per-job, and HOST_DATA_DIR may
    # be absent if compose env_file is misconfigured — set both.
    env = os.environ.copy()
    env["JOB_ID"] = job_id
    host_data_dir = os.environ.get("HOST_DATA_DIR") or ""
    if host_data_dir:
        env["HOST_DATA_DIR"] = host_data_dir
    try:
        res = subprocess.run(
            cmd, cwd=str(work_dir), env=env,
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        log_fn(f"[autoboot] chal-libc-fix timed out after {timeout_s}s")
        return (None, elf_basename)
    except FileNotFoundError:
        log_fn("[autoboot] chal-libc-fix not on PATH (build is older than the patch)")
        return (None, elf_basename)
    except Exception as e:
        log_fn(f"[autoboot] chal-libc-fix spawn failed: {e}")
        return (None, elf_basename)
    for line in (res.stdout or "").splitlines()[-12:]:
        log_fn(f"[autoboot] {line}")
    for line in (res.stderr or "").splitlines()[-6:]:
        log_fn(f"[autoboot] STDERR: {line}")
    profile = work_dir / ".chal-libs" / "libc_profile.json"
    if profile.is_file():
        log_fn(f"[autoboot] libc_profile.json ready ({profile.stat().st_size} B)")
        return (profile, elf_basename)
    log_fn(
        f"[autoboot] chal-libc-fix exited {res.returncode} but no "
        f"libc_profile.json — likely musl/distroless. Agent falls back to "
        f"worker libc."
    )
    return (None, elf_basename)


async def _run_agent(
    job_id: str,
    binary_name: str,
    bin_dir: Path,
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    staged_bin = work_dir / "bin"
    if staged_bin.exists():
        shutil.rmtree(staged_bin)
    shutil.copytree(bin_dir, staged_bin)
    # Make sure the binary inside the staged dir is executable
    for f in staged_bin.iterdir():
        try:
            f.chmod(0o755)
        except Exception:
            pass

    # Pre-bake ./.chal-libs/libc_profile.json BEFORE the agent's first
    # turn. Models historically skipped this step and the rest of the
    # heap pipeline (scaffold templates, heap-probe, judge failure
    # matrix) became dead code as a result. Doing it here makes the
    # profile data deterministic; the agent only has to READ it.
    _profile, autoboot_elf_name = _autobootstrap_libc(
        staged_bin, work_dir, lambda s: log_line(job_id, s),
        job_id=job_id,
    )

    # If autoboot flattened a zip + discovered the real ELF, prefer that
    # name in the user prompt over the .zip filename the user uploaded.
    # ``./bin/<binary_name>`` references in the prompt then resolve to
    # the actual challenge instead of confusing the agent with a zip
    # path (observed live on 5963af004fdc).
    effective_binary_name = autoboot_elf_name or binary_name
    chal_unpacked = (work_dir / "chal").is_dir()

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    resume_sid = read_meta(job_id).get("resume_session_id")
    # Heap detection up-front so the orchestrator's scaffold-missing
    # trip-wire (SCAFFOLD_NUDGE in run_main_agent_session) can fire
    # only when relevant.
    heap_kw = looks_heap_advanced(description or "")
    summary: dict = {
        "messages": 0, "tool_calls": 0, "model": model,
        "heap_chal": True,                       # pwn module default
        "heap_chal_keyword_match": heap_kw,
    }
    options = make_main_session_options(
        job_id=job_id,
        work_dir=work_dir,
        model=model,
        system_prompt=SYSTEM_PROMPT,
        base_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        summary=summary,
        resume_sid=resume_sid,
    )
    user_prompt = build_user_prompt(
        effective_binary_name, target, description, auto_run,
        chal_unpacked=chal_unpacked,
    )

    # Auto-pre-recon — let recon do the static triage BEFORE main's
    # first turn so main starts with the 2 KB summary in its prompt
    # instead of having to decide "should I delegate?". Skip for
    # remote-only jobs (no binary to map) and for retries where main
    # is resuming a prior session (has its own context to lean on).
    if effective_binary_name and not resume_sid:
        recon_question = _build_pre_recon_prompt(
            binary_name=effective_binary_name,
            target=target,
            heap_advanced=heap_kw,
            chal_unpacked=chal_unpacked,
        )
        log_line(job_id, "[pre-recon] spawning static-triage recon subagent")
        recon_reply = await run_pre_recon(
            job_id=job_id,
            work_dir=work_dir,
            model=model,
            prompt=recon_question,
            log_fn=lambda s: log_line(job_id, s),
        )
        if recon_reply:
            user_prompt = (
                "PRE-RECON COMPLETED — the orchestrator already ran a "
                "recon subagent on your behalf. Its 2 KB summary is "
                "below. START from this; do not re-run the same triage "
                "yourself. Spawn recon AGAIN for follow-up "
                "questions if needed.\n\n"
                "==== RECON REPLY ===="
                f"\n{recon_reply}\n"
                "==== END RECON ====\n\n"
            ) + user_prompt
            log_line(
                job_id,
                f"[pre-recon] reply ready ({len(recon_reply)} chars) "
                f"— prepended to main user_prompt",
            )
        else:
            log_line(
                job_id,
                "[pre-recon] empty reply — main starts without "
                "pre-recon context (will need to delegate itself)",
            )

    log_line(job_id, f"Launching Claude agent (model={model})")
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        # attempt_sandbox_run is sync; the helper calls it via anyio.to_thread.
        return attempt_sandbox_run(
            job_id, script_name, target, lambda s: log_line(job_id, s),
        )

    try:
        sandbox_result = await run_main_agent_session(
            job_id,
            options=options,
            initial_prompt=user_prompt,
            summary=summary,
            work_dir=work_dir,
            artifact_names=("exploit.py",),
            auto_run=auto_run,
            sandbox_runner=_sandbox_for,
            log_fn=lambda s: log_line(job_id, s),
        )
    finally:
        watchdog.cancel()
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)
        # Carry artifacts up to the job dir. Runs in `finally` so any
        # abrupt exit (RQ stop / Stop&Resume / SIGTERM-with-grace) still
        # flushes the agent's exploit.py / report.md / findings.json /
        # THREAT_MODEL.md into <jobdir>/, where
        # the API's file links look. Wrapped in its own try/except so a
        # copy failure can't mask the real agent error in summary.
        try:
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir,
                ["exploit.py", "report.md", "findings.json", "THREAT_MODEL.md"],
                fallback_dirs=fallback_dirs,
            )
            summary["exploit_present"] = "exploit.py" in found
            summary["report_present"] = "report.md" in found
            summary["decomp_used"] = (work_dir / "decomp").exists()
            if summary["decomp_used"]:
                try:
                    summary["decomp_function_count"] = len(list((work_dir / "decomp").glob("*.c")))
                except Exception:
                    pass
            jd = job_dir(job_id)
            for name, src in found.items():
                target_path = jd / name
                if src.resolve() != target_path.resolve():
                    target_path.write_bytes(src.read_bytes())
                # Mirror into work_dir so the next /retry's carry step
                # picks up the freshest version, not the stale carry-copy.
                work_target = work_dir / name
                if src.resolve() != work_target.resolve():
                    work_target.write_bytes(src.read_bytes())
        except Exception as carry_err:
            log_line(job_id, f"CARRY_ERROR: {carry_err}")
    summary["sandbox"] = sandbox_result
    return summary


def run_job(
    job_id: str,
    binary_rel: Optional[str],
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    jd = job_dir(job_id)
    bin_dir = jd / "bin"
    binary_name = Path(binary_rel).name if binary_rel else None

    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, binary_name, bin_dir, target, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)

        # Sandbox+judge already happened inside the agent session loop;
        # the helper stashed the LAST sandbox_result on the summary.
        sandbox_result = agent_summary.pop("sandbox", None)

        flags = scan_job_for_flags(job_id)
        agent_err = agent_summary.get("agent_error")
        agent_err_kind = agent_summary.get("agent_error_kind")
        if agent_err and not agent_summary.get("exploit_present"):
            final_status = "failed"
        elif not flags:
            final_status = "no_flag"
        else:
            final_status = "finished"
        result = {
            "agent": agent_summary,
            "cost_usd": cost,
            "sandbox": sandbox_result,
            "flags": flags,
            "agent_error": agent_err,
            "agent_error_kind": agent_err_kind,
        }
        (jd / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                   model=agent_summary.get("model"),
                   flags=flags,
                   error=agent_err,
                   error_kind=agent_err_kind,
                   exploit_present=agent_summary.get("exploit_present", False),
                   decomp_used=agent_summary.get("decomp_used", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
