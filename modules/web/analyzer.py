import asyncio
import json
import os
import traceback
from pathlib import Path
from typing import Optional

import anyio
from claude_agent_sdk import (
    AssistantMessage,
    SystemMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)

from modules._common import (
    budget_exceeded,
    capture_session_id,
    classify_agent_error,
    collect_outputs,
    extract_cost,
    format_tool_result,
    job_dir,
    log_line,
    log_thinking,
    read_meta,
    scan_job_for_flags,
    soft_timeout_watchdog,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.settings_io import apply_to_env, get_setting
from modules.web.prompts import SYSTEM_PROMPT, build_user_prompt


async def _run_agent(
    job_id: str,
    src_root: Optional[str],
    target_url: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    add_dirs = [src_root] if src_root else []
    resume_sid = read_meta(job_id).get("resume_session_id")
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        add_dirs=add_dirs,
        resume=resume_sid,
        fork_session=bool(resume_sid),
    )
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    user_prompt = build_user_prompt(src_root, target_url, description, auto_run)
    log_line(job_id, f"Launching Claude agent (model={model})")
    log_line(job_id, f"Source root: {src_root or '(remote-only)'}")

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}
    try:
        async for msg in query(prompt=user_prompt, options=options):
            capture_session_id(msg, job_id)
            if isinstance(msg, AssistantMessage):
                summary["messages"] += 1
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        log_line(job_id, f"AGENT: {block.text[:500]}")
                    elif isinstance(block, ToolUseBlock):
                        summary["tool_calls"] += 1
                        args_preview = json.dumps(block.input)[:200]
                        log_line(job_id, f"TOOL {block.name}: {args_preview}")
                    elif isinstance(block, ThinkingBlock):
                        # Surfaces extended-thinking output so the live
                        # log doesn't go silent for minutes between tool
                        # calls when Claude is reasoning.
                        log_thinking(
                            lambda s: log_line(job_id, s),
                            "THINK", block.thinking,
                        )
            elif isinstance(msg, UserMessage):
                # ToolResultBlock comes back in the next user turn — without
                # logging it, the run.log goes silent for the entire tool
                # execution (long Bash commands, big Reads, ...).
                content = msg.content if isinstance(msg.content, list) else []
                for block in content:
                    if isinstance(block, ToolResultBlock):
                        log_line(
                            job_id,
                            format_tool_result(block.content, block.is_error),
                        )
            # Trip-wire: too many tool calls without producing exploit.py.
            # Better to abort cleanly here than let the SDK exhaust its
            # context window mid-thought ("Prompt is too long").
            if budget_exceeded(summary["tool_calls"], work_dir, ("exploit.py",)):
                log_line(
                    job_id,
                    "BUDGET_ABORT: investigation budget exceeded "
                    f"({summary['tool_calls']} tool calls, no exploit.py). "
                    "Stopping early — retry with a hint to push the agent "
                    "past the analysis loop.",
                )
                summary["agent_error"] = "investigation budget exceeded"
                summary["agent_error_kind"] = "budget"
                break
            if isinstance(msg, ResultMessage):
                summary["result"] = {
                    "duration_ms": msg.duration_ms,
                    "num_turns": msg.num_turns,
                    "total_cost_usd": msg.total_cost_usd,
                    "is_error": msg.is_error,
                }
                log_line(job_id, f"DONE: {summary['result']}")
    except Exception as e:
        msg_text = str(e)
        kind = classify_agent_error(msg_text)
        summary["agent_error"] = msg_text
        summary["agent_error_kind"] = kind
        log_line(job_id, f"AGENT_ERROR ({kind}): {msg_text[:400]}")
    finally:
        watchdog.cancel()
        # Clear the awaiting_decision flag if the watchdog already fired —
        # the job has finished and the user no longer needs to decide.
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)

    jd = job_dir(job_id)
    # Prefer the agent's cwd, but also check /root/ AND the job root in case
    # the agent wrote with an absolute path. collect_outputs handles cwd +
    # /root, then we additionally consider files already at the job root.
    found = collect_outputs(work_dir, ["exploit.py", "report.md"])
    if "exploit.py" not in found and (jd / "exploit.py").is_file():
        found["exploit.py"] = jd / "exploit.py"
    if "report.md" not in found and (jd / "report.md").is_file():
        found["report.md"] = jd / "report.md"
    summary["exploit_present"] = "exploit.py" in found
    summary["report_present"] = "report.md" in found
    for name, src in found.items():
        # Only copy if the file isn't already at the job root
        target = jd / name
        if src.resolve() != target.resolve():
            target.write_bytes(src.read_bytes())
    return summary


def run_job(
    job_id: str,
    src_root: Optional[str],
    target_url: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, src_root, target_url, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)

        sandbox_result = None
        if auto_run and agent_summary.get("exploit_present"):
            write_meta(job_id, stage="sandbox-run")
            sandbox_result = attempt_sandbox_run(
                job_id, "exploit.py", target_url, lambda s: log_line(job_id, s)
            )

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
        (job_dir(job_id) / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                   model=agent_summary.get("model"),
                   flags=flags,
                   error=agent_err,
                   error_kind=agent_err_kind,
                   exploit_present=agent_summary.get("exploit_present", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
