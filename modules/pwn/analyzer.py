import asyncio
import json
import os
import shutil
import subprocess
import traceback
from pathlib import Path
from typing import Optional

import anyio
from claude_agent_sdk import ClaudeAgentOptions

from modules._common import (
    build_recon_agents,
    collect_outputs,
    extract_cost,
    job_dir,
    log_line,
    make_spawn_subagent_mcp,
    prior_work_dirs,
    read_meta,
    run_main_agent_session,
    scan_job_for_flags,
    soft_timeout_watchdog,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.pwn.prompts import SYSTEM_PROMPT, build_user_prompt, looks_heap_advanced
from modules.settings_io import apply_to_env, get_setting


def _find_elf_or_unzip(staged_bin: Path, work_dir: Path, log_fn) -> list[Path]:
    """Find ELF binaries in `staged_bin`. If only zip/tar bundles are
    present (the standard Dreamhack / HackTheBox shape), unzip the first
    bundle into <work_dir>/chal/ and rescan there. Returns whatever ELFs
    were found across both passes.
    """
    elfs: list[Path] = []

    def _scan(d: Path) -> None:
        try:
            for f in d.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    head = f.read_bytes()[:4]
                except Exception:
                    continue
                if head == b"\x7fELF":
                    elfs.append(f)
        except Exception as e:
            log_fn(f"[autoboot] scan {d} failed: {e}")

    _scan(staged_bin)
    if elfs:
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
    _scan(out_dir)
    if not elfs:
        log_fn(f"[autoboot] bundle {bundle.name} contained no ELF")
    return elfs


def _autobootstrap_libc(
    staged_bin: Path, work_dir: Path, log_fn, *, timeout_s: int = 180,
) -> Path | None:
    """Run `chal-libc-fix` against the first ELF in <staged_bin> BEFORE the
    agent starts, so ./.chal-libs/libc_profile.json is always on disk when
    the agent enters its first turn.

    Why: jobs 9d58fe152fba / 011a6d486d53 (and the earlier OOM pair)
    skipped chal-libc-fix entirely because the model dove into decompile
    analysis and never looped back to step 5 of the workflow. With the
    profile missing, the rest of the heap pipeline (scaffold templates,
    heap-probe, judge failure_code matrix) operate on absent data.
    Pre-baking it shifts the pipeline from model-action-dependent to
    deterministic.

    .zip / .tar bundles (Dreamhack standard) are auto-unpacked into
    <work_dir>/chal/ first; the first ELF found anywhere under there
    becomes the chal target. Job 011a6d486d53 hit this case (zip in
    ./bin/) — autoboot stopped at the ELF magic check and main ended
    up doing the unpack + chal-libc-fix manually 48 s into the run.

    Best-effort: any failure is logged and swallowed; the agent can still
    try chal-libc-fix manually from its prompt.
    """
    elf_candidates = _find_elf_or_unzip(staged_bin, work_dir, log_fn)
    if not elf_candidates:
        log_fn("[autoboot] no ELF found in ./bin/ — skipping chal-libc-fix")
        return None
    # Patch the first ELF as the canonical chal target. The agent can
    # patch additional ones if needed. We copy it to ./prob first so the
    # original bin/ remains pristine for fall-back inspection.
    elf = elf_candidates[0]
    prob = work_dir / "prob"
    try:
        if not prob.exists() or prob.stat().st_size != elf.stat().st_size:
            shutil.copy2(elf, prob)
            prob.chmod(0o755)
    except Exception as e:
        log_fn(f"[autoboot] could not stage ./prob: {e}")
        return None
    cmd = ["chal-libc-fix", str(prob)]
    log_fn(f"[autoboot] running: {' '.join(cmd)}")
    env = os.environ.copy()
    try:
        res = subprocess.run(
            cmd, cwd=str(work_dir), env=env,
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        log_fn(f"[autoboot] chal-libc-fix timed out after {timeout_s}s")
        return None
    except FileNotFoundError:
        log_fn("[autoboot] chal-libc-fix not on PATH (build is older than the patch)")
        return None
    except Exception as e:
        log_fn(f"[autoboot] chal-libc-fix spawn failed: {e}")
        return None
    for line in (res.stdout or "").splitlines()[-12:]:
        log_fn(f"[autoboot] {line}")
    for line in (res.stderr or "").splitlines()[-6:]:
        log_fn(f"[autoboot] STDERR: {line}")
    profile = work_dir / ".chal-libs" / "libc_profile.json"
    if profile.is_file():
        log_fn(f"[autoboot] libc_profile.json ready ({profile.stat().st_size} B)")
        return profile
    log_fn(
        f"[autoboot] chal-libc-fix exited {res.returncode} but no "
        f"libc_profile.json — likely musl/distroless. Agent falls back to "
        f"worker libc."
    )
    return None


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
    # turn. The earlier OOM jobs (1d00be30d4e9 / a914ca943ed2 / 9d58fe152fba)
    # all skipped this step model-side and the rest of the heap pipeline
    # became dead code as a result. Doing it here makes the profile
    # data deterministic; the agent only has to READ it.
    _autobootstrap_libc(
        staged_bin, work_dir, lambda s: log_line(job_id, s),
    )

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    resume_sid = read_meta(job_id).get("resume_session_id")
    # Heap detection moved up so we can decide subagent-isolation
    # before constructing options.
    heap_kw = looks_heap_advanced(description or "")
    summary: dict = {
        "messages": 0, "tool_calls": 0, "model": model,
        "heap_chal": True,                       # pwn module default
        "heap_chal_keyword_match": heap_kw,
    }
    # Isolated subagent path. Each `spawn_subagent(...)` MCP call
    # launches a NEW `claude` CLI subprocess for the subagent and
    # discards it on return — main's heap never accumulates the
    # subagent's investigation context. Env var
    # `USE_ISOLATED_SUBAGENTS=0` reverts to the SDK's built-in
    # `Agent` tool path (one Node.js process, all conversations
    # share heap) for fast rollback.
    use_isolated = os.environ.get(
        "USE_ISOLATED_SUBAGENTS", "1") != "0"
    if use_isolated:
        mcp_server, spawn_tool = make_spawn_subagent_mcp(
            model=model,
            work_dir=work_dir,
            job_id=job_id,
            log_fn=lambda s: log_line(job_id, s),
            summary=summary,
        )
        options = ClaudeAgentOptions(
            system_prompt=SYSTEM_PROMPT,
            model=model,
            cwd=str(work_dir),
            allowed_tools=[
                "Read", "Write", "Edit", "Bash", "Glob", "Grep",
                spawn_tool,
            ],
            permission_mode="bypassPermissions",
            env={"JOB_ID": job_id, "USE_ISOLATED_SUBAGENTS": "1"},
            resume=resume_sid,
            fork_session=bool(resume_sid),
            mcp_servers={"team": mcp_server},
        )
        log_line(
            job_id,
            "[orchestrator] subagent isolation: ON "
            f"(tool={spawn_tool})",
        )
    else:
        options = ClaudeAgentOptions(
            system_prompt=SYSTEM_PROMPT,
            model=model,
            cwd=str(work_dir),
            allowed_tools=[
                "Read", "Write", "Edit", "Bash", "Glob", "Grep", "Agent",
            ],
            permission_mode="bypassPermissions",
            env={"JOB_ID": job_id, "USE_ISOLATED_SUBAGENTS": "0"},
            resume=resume_sid,
            fork_session=bool(resume_sid),
            agents=build_recon_agents(model),
        )
        log_line(
            job_id,
            "[orchestrator] subagent isolation: OFF (legacy in-process)",
        )
    user_prompt = build_user_prompt(binary_name, target, description, auto_run)

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
