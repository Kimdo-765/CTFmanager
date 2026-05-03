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
from modules.crypto.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting


async def _run_agent(
    job_id: str,
    src_root: str,
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    model = str(get_setting("claude_model") or "claude-opus-4-7")
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        add_dirs=[src_root],
    )
    user_prompt = build_user_prompt(src_root, target, description, auto_run)

    log_line(job_id, f"Launching Claude agent (model={model})")
    summary: dict = {"messages": 0, "tool_calls": 0}

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

    solver = work_dir / "solver.py"
    sage_solver = work_dir / "solver.sage"
    report = work_dir / "report.md"
    summary["solver_present"] = solver.exists() or sage_solver.exists()
    summary["sage_solver"] = sage_solver.exists() and not solver.exists()
    summary["report_present"] = report.exists()
    jd = job_dir(job_id)
    if solver.exists():
        (jd / "solver.py").write_bytes(solver.read_bytes())
    if sage_solver.exists():
        (jd / "solver.sage").write_bytes(sage_solver.read_bytes())
    if report.exists():
        (jd / "report.md").write_bytes(report.read_bytes())
    return summary


def run_job(
    job_id: str,
    src_root: str,
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    use_sage: bool = False,
) -> dict:
    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, src_root, target, description, auto_run,
        )
        cost = extract_cost(agent_summary)

        sandbox_result = None
        if auto_run and agent_summary.get("solver_present"):
            write_meta(job_id, stage="sandbox-run")
            script = "solver.sage" if (use_sage or agent_summary.get("sage_solver")) else "solver.py"
            sandbox_result = attempt_sandbox_run(
                job_id, script, target, lambda s: log_line(job_id, s),
                use_sage=(script.endswith(".sage")),
            )

        flags = scan_job_for_flags(job_id)
        agent_err = agent_summary.get("agent_error")
        agent_err_kind = agent_summary.get("agent_error_kind")
        if agent_err and not agent_summary.get("solver_present"):
            final_status = "failed"
        else:
            final_status = "finished"
        result = {
            "agent": agent_summary,
            "cost_usd": cost,
            "sandbox": sandbox_result,
            "use_sage": use_sage,
            "flags": flags,
            "agent_error": agent_err,
            "agent_error_kind": agent_err_kind,
        }
        (job_dir(job_id) / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status=final_status, stage="done", cost_usd=cost,
                   flags=flags,
                   error=agent_err,
                   error_kind=agent_err_kind,
                   solver_present=agent_summary.get("solver_present", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
