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

import asyncio
import json
import shutil
from pathlib import Path
from typing import AsyncIterator

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from api.queue import get_queue, resolve_timeout
from api.storage import JOBS_DIR, job_dir, new_job_id, read_job_meta, write_job_meta
from modules._common import classify_agent_error
from modules.settings_io import apply_to_env, get_setting


class ReviewerError(Exception):
    """Raised when the retry reviewer can't produce a usable hint.

    Carries a short `kind` tag (e.g. 'api_error', 'auth', 'rate_limit',
    'policy_refusal', 'empty') so the UI can present something friendlier
    than a raw exception string.
    """

    def __init__(self, message: str, kind: str = "api_error"):
        super().__init__(message)
        self.kind = kind


# Distinctive substrings that mark a Claude API error masquerading as a
# normal text response. Keep these specific — broad patterns like "api error"
# alone would false-positive on legitimate hints that mention error handling.
_API_ERROR_PATTERNS = (
    "api error: 4",
    "api error: 5",
    "your credit balance is too low",
    "rate_limit_exceeded",
    "authentication_error",
    "invalid_request_error",
    "permission_error",
    "overloaded_error",
    "internal_server_error",
    '"type":"error"',
)


def _looks_like_api_error(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(p in low for p in _API_ERROR_PATTERNS)


def _diagnose_reviewer_text(accumulated: str) -> tuple[str, str] | None:
    """Return (kind, message) if the reviewer's accumulated text is unusable
    (empty, or looks like a serialized API error), else None.
    """
    s = (accumulated or "").strip()
    if not s:
        return ("empty", "reviewer returned no hint")
    if _looks_like_api_error(s):
        return (classify_agent_error(s) or "api_error", s)
    return None

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
    """Synchronous reviewer call. Raises ReviewerError if the reviewer
    fails or returns unusable text — callers MUST NOT enqueue a new job
    when this raises.
    """
    model = LATEST_REVIEWER_MODEL
    work_dir = Path("/tmp")
    options = ClaudeAgentOptions(
        system_prompt=_REVIEWER_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=[],
        permission_mode="bypassPermissions",
    )
    hint_parts: list[str] = []
    try:
        async for msg in query(prompt=context, options=options):
            if isinstance(msg, AssistantMessage):
                for blk in msg.content:
                    if isinstance(blk, TextBlock):
                        hint_parts.append(blk.text)
            elif isinstance(msg, ResultMessage):
                if getattr(msg, "is_error", False):
                    detail = (
                        (getattr(msg, "result", None) or "").strip()
                        or "\n".join(hint_parts).strip()
                        or "reviewer call failed"
                    )
                    raise ReviewerError(
                        detail, classify_agent_error(detail) or "api_error"
                    )
                break
    except ReviewerError:
        raise
    except Exception as e:
        raw = str(e)
        raise ReviewerError(raw, classify_agent_error(raw) or "api_error") from e

    hint = "\n".join(hint_parts).strip()
    diag = _diagnose_reviewer_text(hint)
    if diag is not None:
        kind, message = diag
        raise ReviewerError(message, kind)
    return hint


async def _ask_reviewer_streaming(context: str) -> AsyncIterator[tuple[str, dict]]:
    """Yield ('event_kind', payload) tuples while the reviewer runs.

    event_kind one of:
      - 'token'  : partial hint chars  -> {"delta": "..."}
      - 'done'   : final hint          -> {"hint": "..."}
      - 'error'  : reviewer failed     -> {"message": "...", "kind": "..."}

    On 'error' the caller MUST stop and NOT enqueue a new job.
    """
    model = LATEST_REVIEWER_MODEL
    work_dir = Path("/tmp")
    options = ClaudeAgentOptions(
        system_prompt=_REVIEWER_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=[],
        permission_mode="bypassPermissions",
    )
    accumulated: list[str] = []
    last_emitted = 0
    try:
        async for msg in query(prompt=context, options=options):
            if isinstance(msg, AssistantMessage):
                for blk in msg.content:
                    if isinstance(blk, TextBlock):
                        accumulated.append(blk.text)
                        full = "".join(accumulated)
                        delta = full[last_emitted:]
                        if delta:
                            last_emitted = len(full)
                            yield "token", {"delta": delta}
            elif isinstance(msg, ResultMessage):
                if getattr(msg, "is_error", False):
                    detail = (
                        (getattr(msg, "result", None) or "").strip()
                        or "".join(accumulated).strip()
                        or "reviewer call failed"
                    )
                    yield "error", {
                        "message": detail,
                        "kind": classify_agent_error(detail) or "api_error",
                    }
                    return
                break
    except Exception as e:
        raw = str(e)
        yield "error", {
            "message": raw,
            "kind": classify_agent_error(raw) or "api_error",
        }
        return

    hint = "".join(accumulated).strip()
    diag = _diagnose_reviewer_text(hint)
    if diag is not None:
        kind, message = diag
        yield "error", {"message": message, "kind": kind}
        return
    yield "done", {"hint": hint}


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


_MAX_MANUAL_HINT = 4000


def _validate_retry(safe: str, *, require_claude_auth: bool = True) -> tuple[Path, dict]:
    jd = JOBS_DIR / safe
    if not jd.is_dir():
        raise HTTPException(status_code=404, detail="job not found")
    prev_meta = read_job_meta(safe) or {}
    if prev_meta.get("module") not in ("web", "pwn", "crypto", "rev"):
        raise HTTPException(
            status_code=400,
            detail="retry-with-hint only works for web/pwn/crypto/rev jobs",
        )
    if require_claude_auth:
        apply_to_env()
        if not (str(get_setting("anthropic_api_key") or "")) and not Path(
            "/root/.claude/.credentials.json"
        ).is_file():
            raise HTTPException(
                status_code=400,
                detail="no Claude auth configured (set Settings → API key or claude login)",
            )
    return jd, prev_meta


async def _read_manual_hint(request: Request) -> str | None:
    """Return a sanitized user-supplied hint from the request body, or None.

    Accepts JSON `{"hint": "..."}`. Empty / whitespace-only hints become None
    so callers can fall back to the reviewer path.
    """
    try:
        body = await request.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    raw = body.get("hint")
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    return cleaned[:_MAX_MANUAL_HINT]


@router.post("/{job_id}/retry/stream")
async def retry_with_hint_stream(job_id: str, request: Request):
    """SSE stream of retry progress.

    Events emitted:
      stage : {"name": "gathering" | "asking" | "submitting"}
      token : {"delta": "<partial reviewer output>"}
      done  : {"new_job_id": "...", "hint": "...", "retry_of": "...", "manual": bool}
      error : {"message": "..."}

    If the request body is JSON `{"hint": "<user-supplied>"}`, the reviewer
    call is skipped entirely and the user's hint goes straight to the new
    job. The 'gathering' / 'asking' stages and 'token' events are then
    omitted — only 'submitting' and 'done' fire.
    """
    safe = Path(job_id).name
    manual_hint = await _read_manual_hint(request)
    jd, prev_meta = _validate_retry(safe, require_claude_auth=manual_hint is None)

    async def event_gen():
        def sse(name: str, data: dict) -> bytes:
            return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

        hint = manual_hint or ""

        if manual_hint is None:
            yield sse("stage", {"name": "gathering"})
            await asyncio.sleep(0)
            try:
                context = _gather_context(jd)
                if not context.strip():
                    yield sse("error", {
                        "message": "no prior-job context found to review",
                        "kind": "no_context",
                    })
                    return
            except Exception as e:
                yield sse("error", {
                    "message": f"gather failed: {e}",
                    "kind": "gather",
                })
                return

            yield sse("stage", {"name": "asking"})
            try:
                async for kind, payload in _ask_reviewer_streaming(context):
                    if kind == "token":
                        yield sse("token", payload)
                    elif kind == "done":
                        hint = payload.get("hint", "")
                    elif kind == "error":
                        yield sse("error", payload)
                        return
            except Exception as e:
                raw = str(e)
                yield sse("error", {
                    "message": f"reviewer failed: {raw}",
                    "kind": classify_agent_error(raw) or "api_error",
                })
                return

        yield sse("stage", {"name": "submitting"})
        try:
            new_id = _resubmit(prev_meta, hint, jd)
        except HTTPException as he:
            yield sse("error", {
                "message": f"submit rejected: {he.detail}",
                "kind": "submit",
            })
            return
        except Exception as e:
            yield sse("error", {
                "message": f"submit failed: {e}",
                "kind": "submit",
            })
            return

        yield sse("done", {
            "new_job_id": new_id,
            "hint": hint,
            "retry_of": safe,
            "manual": manual_hint is not None,
        })

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{job_id}/retry")
async def retry_with_hint(job_id: str, request: Request):
    """Non-streaming form, kept for clients that don't want SSE.

    Request body (optional): JSON `{"hint": "..."}`. When provided, the
    reviewer call is skipped and the user's hint is appended to the new
    job's description directly.
    """
    safe = Path(job_id).name
    manual_hint = await _read_manual_hint(request)
    jd, prev_meta = _validate_retry(safe, require_claude_auth=manual_hint is None)

    if manual_hint is not None:
        hint = manual_hint
    else:
        context = _gather_context(jd)
        if not context.strip():
            raise HTTPException(status_code=400, detail="no context to review")
        try:
            hint = await _ask_reviewer(context)
        except ReviewerError as e:
            # 502 = upstream (Claude API) failure. The retry never reached
            # the queue, so the client knows nothing new was scheduled.
            raise HTTPException(
                status_code=502,
                detail={
                    "stage": "reviewer",
                    "kind": e.kind,
                    "message": str(e),
                    "submitted": False,
                },
            ) from e

    new_id = _resubmit(prev_meta, hint, jd)
    return {
        "new_job_id": new_id,
        "hint": hint,
        "retry_of": safe,
        "manual": manual_hint is not None,
    }
