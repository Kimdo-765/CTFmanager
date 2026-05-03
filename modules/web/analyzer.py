import json
import os
import traceback
from pathlib import Path
from typing import Optional

import anyio
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

from modules._common import (
    classify_agent_error,
    extract_cost,
    job_dir,
    log_line,
    scan_job_for_flags,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.settings_io import apply_to_env, get_setting
from modules.web.prompts import SYSTEM_PROMPT, build_user_prompt


async def _run_agent(
    job_id: str,
    src_root: str,
    target_url: Optional[str],
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        add_dirs=[src_root],
    )

    user_prompt = build_user_prompt(src_root, target_url, description, auto_run)
    log_line(job_id, f"Launching Claude agent (model={model})")
    log_line(job_id, f"Source root: {src_root}")

    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}
    try:
        async for msg in query(prompt=user_prompt, options=options):
            if isinstance(msg, AssistantMessage):
                summary["messages"] += 1
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        log_line(job_id, f"AGENT: {block.text[:500]}")
                    elif isinstance(block, ToolUseBlock):
                        summary["tool_calls"] += 1
                        args_preview = json.dumps(block.input)[:200]
                        log_line(job_id, f"TOOL {block.name}: {args_preview}")
            elif isinstance(msg, ResultMessage):
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

    exploit_path = work_dir / "exploit.py"
    report_path = work_dir / "report.md"
    summary["exploit_present"] = exploit_path.exists()
    summary["report_present"] = report_path.exists()

    jd = job_dir(job_id)
    if exploit_path.exists():
        (jd / "exploit.py").write_bytes(exploit_path.read_bytes())
    if report_path.exists():
        (jd / "report.md").write_bytes(report_path.read_bytes())

    return summary


def run_job(
    job_id: str,
    src_root: str,
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
