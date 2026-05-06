"""Quality-gate judge for auto-run exploit/solver execution.

Three short, no-tools Claude calls wrap each `attempt_sandbox_run`:

* `prejudge_script(...)` — pre-flight static review of the script. Looks
  for the I/O patterns that historically cause hangs (recvuntil with no
  timeout, hard-coded prompt mismatches, wrong tube target, missing
  argv handling). Returns `{ok, severity, issues}`. If the runner
  caller decides the verdict is severe enough to abort, the container
  never starts and the failure is recorded as `prejudge_blocked`.

* `supervise_run_once(...)` — single one-shot decision when the running
  container has emitted no new stdout/stderr for `stall_seconds`. Judge
  reads the recent stdout / stderr tail + the script source, returns
  `{action: "kill"|"continue", reason}`. Called at most once per run
  (conservative mode A) so judge cost stays at ≤1 turn for hangs and
  0 for normal runs.

* `postjudge_run(...)` — post-mortem categorization once the container
  exits (either naturally or by supervise-kill). Returns
  `{verdict, summary, retry_hint}` where verdict ∈
  {success, partial, hung, parse_error, network_error, crash, timeout,
  unknown}.  `retry_hint` is non-empty whenever the verdict isn't
  "success", so the existing /retry flow can pick it up.

All three use `modules._common.LATEST_JUDGE_MODEL`. They are best-effort:
on judge failure (auth/rate/empty) the helper degrades to permissive
defaults (prejudge ok=True, supervise action=continue, postjudge
verdict=unknown) so the runner is never harder to use because the
judge itself misbehaved.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)

from modules._common import LATEST_JUDGE_MODEL


_PREJUDGE_PROMPT = """\
You are reviewing an auto-generated CTF exploit/solver script BEFORE
it runs in a sandboxed container. Look for issues that historically
cause hangs, parse mismatches, or wrong-target failures:

* recvuntil / recv / readuntil / readline with NO timeout argument
  (these block forever if the prompt does not match).
* Hard-coded prompt strings that don't match a typical service banner
  (e.g. expecting "cmd: " when the program prints "> ").
* Wrong tube target: process(...) on a local file when a remote
  target was provided, or remote(...) when there is no network egress.
* Missing or wrong sys.argv handling: the orchestrator passes the
  user-provided target (URL or host:port) as argv[1].
* Missing context.timeout default — recvuntil etc. block forever.
* Infinite while True loops with no exit condition or timeout.

Reply with EXACTLY ONE compact JSON object on the FIRST line, no
markdown, no commentary:
{"ok": true|false, "severity": "low"|"med"|"high", "issues": ["...", "..."]}

* ok=true means the script is safe to run as-is. ok=false means at
  least one likely-fatal issue was found.
* severity=high means do NOT run it (caller will abort).
* low / med are advisory; the run still proceeds.
* issues is a short list (up to 6) of one-line findings.
"""

_SUPERVISE_PROMPT_TMPL = """\
You are watching a CTF exploit/solver run in a sandboxed container.
The container has emitted no new stdout/stderr output for
{stall_s} seconds while still alive. Decide whether to keep waiting
or kill it.

Inputs: the last bytes of stdout and stderr, and the script source.

Reply with EXACTLY ONE compact JSON object on the FIRST line:
{{"action": "kill"|"continue", "reason": "<short>"}}

Choose "kill" if the script is clearly stuck on a recvuntil/parse
mismatch, an infinite loop, or otherwise will never produce output.
Choose "continue" if the silence looks legitimate (slow crypto,
network round-trip, sleep, or pwntools is just buffering before its
first prompt).
"""

_POSTJUDGE_PROMPT = """\
You are post-mortem analyzing a CTF exploit/solver run that has
finished (either naturally or because supervise killed it). Inputs:
exit_code, stdout tail, stderr tail, script source.

Categorize the run and produce a tight retry hint. Reply with EXACTLY
ONE JSON object on the FIRST line, no markdown:
{"verdict": "success"|"partial"|"hung"|"parse_error"|"network_error"|"crash"|"timeout"|"unknown",
 "summary": "<=200 chars",
 "retry_hint": "<=600 chars; empty string when verdict==success"}

Verdict guide:
* success — a flag was clearly captured (FLAG{...}/HTB{...}/DH{...}/
  picoCTF{...} or otherwise unambiguous).
* partial — a leak / intermediate result, no flag.
* hung — output stalled, supervise killed (exit_code negative or
  killed_by_supervise hint in the run).
* parse_error — recvuntil / format mismatch / wrong prompt assumption.
* network_error — connection refused / DNS / TLS failure.
* crash — unhandled Python exception or non-zero exit with traceback.
* timeout — the runner's own timeout fired.
* unknown — none of the above.

retry_hint MUST be a single paragraph the next agent can act on
without seeing this judgment.
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _ask_judge(
    user_prompt: str,
    system_prompt: str,
    *,
    max_chars: int = 4000,
) -> str:
    """Run a single Claude turn with no tools; return the assistant text.
    Empty string on failure — judge errors are NEVER fatal.
    """
    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        model=LATEST_JUDGE_MODEL,
        cwd="/tmp",
        allowed_tools=[],
        permission_mode="bypassPermissions",
    )
    parts: list[str] = []
    try:
        async for msg in query(prompt=user_prompt, options=options):
            if isinstance(msg, AssistantMessage):
                for blk in msg.content:
                    if isinstance(blk, TextBlock):
                        parts.append(blk.text)
            elif isinstance(msg, ResultMessage):
                if getattr(msg, "is_error", False):
                    return ""
                break
    except Exception:
        return ""
    return "".join(parts).strip()[:max_chars]


def _run_async(coro):
    """Run an async coroutine from sync code, even if a parent loop is alive.

    The runner code path is sync (docker-py is sync). Most of the time
    asyncio.run() works; if the worker is already inside a running loop
    (e.g. an analyzer that awaited us), we fall back to a thread-isolated
    new loop so we never deadlock.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        import threading

        result: dict[str, Any] = {}

        def _run():
            loop = asyncio.new_event_loop()
            try:
                result["v"] = loop.run_until_complete(coro)
            finally:
                loop.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join()
        return result.get("v", "")


def _parse_json(text: str) -> dict:
    """Best-effort JSON extraction from a judge reply.

    Tolerates:
      * a plain JSON object as the entire reply,
      * a JSON object on the first non-empty line,
      * a JSON object inside a ```json fenced block.
    Returns {} on failure.
    """
    s = (text or "").strip()
    if not s:
        return {}
    try:
        d = json.loads(s)
        if isinstance(d, dict):
            return d
    except json.JSONDecodeError:
        pass
    # Strip any leading code fence
    if s.startswith("```"):
        # drop first line + trailing ```
        body = s.split("\n", 1)[-1]
        if body.endswith("```"):
            body = body[:-3]
        try:
            d = json.loads(body.strip())
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass
    # First-line scan
    for line in s.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            continue
    return {}


def _read_tail(p: Path, *, max_bytes: int) -> str:
    """Read the last max_bytes of a file as utf-8 (with replacement). Empty
    string if the file doesn't exist or can't be read.
    """
    if not p.is_file():
        return ""
    try:
        data = p.read_bytes()
    except OSError:
        return ""
    if len(data) > max_bytes:
        data = data[-max_bytes:]
    return data.decode("utf-8", errors="replace")


def _truncate_tail(text: str, *, max_bytes: int) -> str:
    """Same as _read_tail but for an already-loaded string buffer."""
    if not text:
        return ""
    b = text.encode("utf-8", errors="replace")
    if len(b) > max_bytes:
        b = b[-max_bytes:]
    return b.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Stage 1 — prejudge
# ---------------------------------------------------------------------------


def prejudge_script(
    jd: Path,
    script_rel: str,
    target: str | None,
    log_fn: Callable[[str], None],
) -> dict:
    """Static review of the about-to-run script.

    Returns:
        {
          "ok": bool,             # default-True when the judge fails
          "severity": "low"|"med"|"high",
          "issues": list[str],    # up to 6, each <=200 chars
          "raw": str,             # raw judge text
        }
    """
    script = jd / script_rel
    if not script.is_file():
        log_fn(f"[judge] prejudge skipped — {script_rel} missing")
        return {"ok": True, "severity": "low", "issues": [], "raw": ""}

    src = _read_tail(script, max_bytes=12000)
    user_prompt = (
        f"target: {target or '(none)'}\n"
        f"script_filename: {script_rel}\n\n"
        f"=== {script_rel} ===\n{src}"
    )
    raw = _run_async(_ask_judge(user_prompt, _PREJUDGE_PROMPT))
    parsed = _parse_json(raw)

    if not parsed:
        log_fn("[judge] prejudge: judge returned no parseable JSON; running anyway")
        return {"ok": True, "severity": "low", "issues": [], "raw": raw}

    ok = bool(parsed.get("ok", True))
    sev = str(parsed.get("severity") or ("low" if ok else "med")).lower()
    if sev not in ("low", "med", "high"):
        sev = "med"

    raw_issues = parsed.get("issues") or []
    if not isinstance(raw_issues, list):
        raw_issues = [str(raw_issues)]
    issues = [str(x)[:200] for x in raw_issues][:6]

    log_fn(f"[judge] prejudge ok={ok} severity={sev} issues={len(issues)}")
    for it in issues:
        log_fn(f"[judge] prejudge issue: {it}")

    return {"ok": ok, "severity": sev, "issues": issues, "raw": raw}


# ---------------------------------------------------------------------------
# Stage 2 — supervise (one-shot when output stalls)
# ---------------------------------------------------------------------------


def supervise_run_once(
    jd: Path,
    script_rel: str,
    stall_seconds: int,
    stdout_tail: str,
    stderr_tail: str,
    log_fn: Callable[[str], None],
) -> dict:
    """One-shot stall decision.

    Returns:
        {
          "action": "kill"|"continue",   # default "continue" on judge fail
          "reason": str,
          "raw": str,
        }
    """
    script = jd / script_rel
    src = _read_tail(script, max_bytes=8000) if script.is_file() else ""

    user_prompt = (
        f"stall_s: {stall_seconds}\n\n"
        f"=== last stdout (tail) ===\n{stdout_tail or '(empty)'}\n\n"
        f"=== last stderr (tail) ===\n{stderr_tail or '(empty)'}\n\n"
        f"=== {script_rel} ===\n{src}"
    )
    sys_prompt = _SUPERVISE_PROMPT_TMPL.format(stall_s=stall_seconds)
    raw = _run_async(_ask_judge(user_prompt, sys_prompt))
    parsed = _parse_json(raw)

    action = str(parsed.get("action") or "continue").lower()
    if action not in ("kill", "continue"):
        action = "continue"
    reason = str(parsed.get("reason") or "")[:400]

    log_fn(f"[judge] supervise action={action} reason={reason[:200]}")
    return {"action": action, "reason": reason, "raw": raw}


# ---------------------------------------------------------------------------
# Stage 3 — postjudge
# ---------------------------------------------------------------------------


_VALID_VERDICTS = {
    "success", "partial", "hung", "parse_error",
    "network_error", "crash", "timeout", "unknown",
}


def postjudge_run(
    jd: Path,
    script_rel: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    log_fn: Callable[[str], None],
    *,
    extra_context: str = "",
) -> dict:
    """Categorize a finished run and produce a retry hint.

    Returns:
        {
          "verdict": str,        # see _VALID_VERDICTS
          "summary": str,        # <=200 chars
          "retry_hint": str,     # <=600 chars; "" when verdict == success
          "raw": str,
        }
    """
    script = jd / script_rel
    src = _read_tail(script, max_bytes=10000) if script.is_file() else ""
    out_t = _truncate_tail(stdout, max_bytes=8000)
    err_t = _truncate_tail(stderr, max_bytes=4000)

    user_prompt = (
        f"exit_code: {exit_code}\n"
        f"{extra_context}\n"
        f"=== stdout (tail) ===\n{out_t or '(empty)'}\n\n"
        f"=== stderr (tail) ===\n{err_t or '(empty)'}\n\n"
        f"=== {script_rel} ===\n{src}"
    )
    raw = _run_async(_ask_judge(user_prompt, _POSTJUDGE_PROMPT))
    parsed = _parse_json(raw)

    verdict = str(parsed.get("verdict") or "unknown").lower()
    if verdict not in _VALID_VERDICTS:
        verdict = "unknown"
    summary = str(parsed.get("summary") or "")[:400]
    retry_hint = str(parsed.get("retry_hint") or "")[:1200]
    if verdict == "success":
        retry_hint = ""  # no hint needed on success

    log_fn(f"[judge] postjudge verdict={verdict} summary={summary[:160]}")
    if retry_hint:
        log_fn(f"[judge] postjudge retry_hint={retry_hint[:200]}")

    return {
        "verdict": verdict,
        "summary": summary,
        "retry_hint": retry_hint,
        "raw": raw,
    }
