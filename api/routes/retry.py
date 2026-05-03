"""Retry-with-hint endpoint.

Given an existing job whose exploit/solver failed (or finished without a
flag), spin up a quick Claude turn that:

1. Reads the original description, run.log, exploit.py / solver.py,
   their stdout/stderr, plus 1-2 key source files.
2. Writes ONE concise paragraph that pinpoints why the previous attempt
   failed and gives the next agent a sharp hint (e.g. "you must POST
   the payload to /upload, the server then triggers a headless bot to
   visit it") in <= 1500 characters.

Then enqueue a new job in the same module with that hint appended to
the original description. The user gets back the new job_id and can
watch it like any other job.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import anyio
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)
from fastapi import APIRouter, HTTPException

from api.queue import get_queue, resolve_timeout
from api.storage import JOBS_DIR, job_dir, new_job_id, read_job_meta, write_job_meta
from modules.settings_io import apply_to_env, get_setting

router = APIRouter()

LATEST_REVIEWER_MODEL = "claude-opus-4-7"

_REVIEWER_PROMPT = """\
You are reviewing a previous CTF-solving attempt that did NOT recover the
flag. The original challenge artifacts are below. Produce ONE concise
paragraph (<=1500 chars) that:

- Names the most likely reason the previous exploit failed (wrong attack
  surface, wrong sink, missing trigger step, missing OOB callback, etc.).
- Gives the next agent the SPECIFIC technical correction it needs:
  what endpoint to hit, what the bot/server actually does after upload,
  what attribute/event to use, which env var to read for OOB callbacks
  (COLLECTOR_URL is preferred; bot is firewalled from webhook.site), etc.
- Does NOT rewrite the exploit. Do NOT include code blocks. Just the
  English hint to add to the next job's description.

Reply with ONLY the hint paragraph — no preamble, no markdown headers.
"""


def _gather_context(jd: Path, max_per_file: int = 6000) -> str:
    """Bundle the prior job's evidence for the reviewer."""
    parts: list[str] = []

    def _read(name: str, label: str | None = None) -> None:
        p = jd / name
        if not p.is_file():
            return
        try:
            text = p.read_text(errors="replace")[:max_per_file]
        except Exception:
            return
        if not text.strip():
            return
        parts.append(f"=== {label or name} ===\n{text}")

    _read("meta.json")
    _read("run.log")
    _read("report.md")
    _read("exploit.py")
    _read("solver.py")
    _read("solver.sage")
    _read("exploit.py.stdout", "exploit stdout")
    _read("exploit.py.stderr", "exploit stderr")
    _read("solver.py.stdout", "solver stdout")
    _read("solver.py.stderr", "solver stderr")
    _read("callbacks.jsonl")

    # Top 2-3 source files (entry-point heuristic)
    src_root = jd / "src" / "extracted"
    if not src_root.is_dir():
        src_root = jd / "src"
    if src_root.is_dir():
        for cand in (
            "deploy/app.py", "app.py", "deploy/server.py", "server.py",
            "deploy/static/main.py", "deploy/templates/index.html",
            "Dockerfile", "deploy/Dockerfile", "docker-compose.yml",
        ):
            for p in src_root.rglob(cand):
                _read(p.relative_to(jd).as_posix(), f"src/{cand}")
                break

    return "\n\n".join(parts)


async def _ask_reviewer(context: str) -> str:
    model = LATEST_REVIEWER_MODEL
    work_dir = Path("/tmp")
    options = ClaudeAgentOptions(
        system_prompt=_REVIEWER_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=[],  # text-only review
        permission_mode="bypassPermissions",
    )
    hint_parts: list[str] = []
    async for msg in query(prompt=context, options=options):
        if isinstance(msg, AssistantMessage):
            for blk in msg.content:
                if isinstance(blk, TextBlock):
                    hint_parts.append(blk.text)
        elif isinstance(msg, ResultMessage):
            break
    hint = "\n".join(hint_parts).strip()
    return hint or "Previous attempt did not capture a flag; reconsider attack surface and OOB callback channel."


def _resubmit(prev_meta: dict, hint: str, prev_jd: Path) -> str:
    """Enqueue a new job in the same module with description + hint, copying
    over the original uploaded source/binary so the user doesn't re-upload.
    """
    module = prev_meta.get("module")
    if module not in ("web", "pwn", "crypto", "rev"):
        raise HTTPException(
            status_code=400,
            detail=f"retry-with-hint is only supported for web/pwn/crypto/rev (got {module})",
        )

    new_id = new_job_id()
    new_jd = job_dir(new_id)

    target = (prev_meta.get("target_url") or "").strip() or None
    description = (prev_meta.get("description") or "").strip()
    description = (description + "\n\n[retry-hint]\n" + hint).strip()
    auto_run = bool(prev_meta.get("auto_run"))
    job_timeout = resolve_timeout(prev_meta.get("job_timeout"))
    model = prev_meta.get("model")  # honor prior choice; user can override
    use_sage = bool(prev_meta.get("use_sage"))

    meta = {
        "id": new_id,
        "module": module,
        "status": "queued",
        "target_url": target,
        "description": description,
        "auto_run": auto_run,
        "job_timeout": job_timeout,
        "model": model,
        "retry_of": prev_meta.get("id"),
    }

    q = get_queue()

    if module in ("web", "crypto"):
        # Copy source dir
        src_extracted = prev_jd / "src" / "extracted"
        if src_extracted.is_dir():
            (new_jd / "src").mkdir(exist_ok=True)
            shutil.copytree(src_extracted, new_jd / "src" / "extracted")
            new_src_root = str(new_jd / "src" / "extracted")
        else:
            new_src_root = None
        meta["src_root"] = new_src_root
        meta["filename"] = prev_meta.get("filename")
        meta["remote_only"] = new_src_root is None
        write_job_meta(new_id, meta)
        if module == "web":
            q.enqueue(
                "modules.web.analyzer.run_job",
                new_id, new_src_root, target, description, auto_run, model,
                job_id=new_id, job_timeout=job_timeout,
            )
        else:
            q.enqueue(
                "modules.crypto.analyzer.run_job",
                new_id, new_src_root, target, description, auto_run, use_sage, model,
                job_id=new_id, job_timeout=job_timeout,
            )
    else:  # pwn / rev
        prev_bin = prev_jd / "bin"
        binary_name = None
        if prev_bin.is_dir():
            new_bin = new_jd / "bin"
            new_bin.mkdir(exist_ok=True)
            for f in prev_bin.iterdir():
                if f.is_file():
                    shutil.copy2(f, new_bin / f.name)
                    binary_name = binary_name or f.name
        meta["filename"] = binary_name or prev_meta.get("filename")
        meta["remote_only"] = binary_name is None
        write_job_meta(new_id, meta)
        if module == "pwn":
            q.enqueue(
                "modules.pwn.analyzer.run_job",
                new_id, binary_name, target, description, auto_run, model,
                job_id=new_id, job_timeout=job_timeout,
            )
        else:  # rev
            q.enqueue(
                "modules.rev.analyzer.run_job",
                new_id, binary_name, description, auto_run, model,
                job_id=new_id, job_timeout=job_timeout,
            )
    return new_id


@router.post("/{job_id}/retry")
def retry_with_hint(job_id: str):
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    if not jd.is_dir():
        raise HTTPException(status_code=404, detail="job not found")
    prev_meta = read_job_meta(safe) or {}
    if prev_meta.get("module") not in ("web", "pwn", "crypto", "rev"):
        raise HTTPException(
            status_code=400,
            detail="retry-with-hint only works for web/pwn/crypto/rev jobs",
        )

    apply_to_env()
    if not (str(get_setting("anthropic_api_key") or "")) and not Path(
        "/root/.claude/.credentials.json"
    ).is_file():
        raise HTTPException(
            status_code=400,
            detail="no Claude auth configured (set Settings → API key or claude login)",
        )

    context = _gather_context(jd)
    if not context.strip():
        raise HTTPException(status_code=400, detail="no context to review")

    hint = anyio.run(_ask_reviewer, context)
    new_id = _resubmit(prev_meta, hint, jd)
    return {"new_job_id": new_id, "hint": hint, "retry_of": safe}
