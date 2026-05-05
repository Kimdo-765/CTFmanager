import asyncio
import json
import shutil
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
    agent_heartbeat,
    agent_tag,
    budget_exceeded,
    build_recon_agents,
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
from modules.rev.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting


async def _run_agent(
    job_id: str,
    binary_name: str,
    bin_dir: Path,
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
    for f in staged_bin.iterdir():
        try:
            f.chmod(0o755)
        except Exception:
            pass

    model = model_override or str(get_setting("claude_model") or "claude-opus-4-7")
    resume_sid = read_meta(job_id).get("resume_session_id")
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep", "Agent"],
        permission_mode="bypassPermissions",
        # JOB_ID lets the `ghiant` Bash wrapper find the job dir for the
        # decompiler bind-mount.
        env={"JOB_ID": job_id},
        resume=resume_sid,
        fork_session=bool(resume_sid),
        agents=build_recon_agents(model),
    )
    user_prompt = build_user_prompt(binary_name, description, auto_run)

    log_line(job_id, f"Launching Claude agent (model={model})")
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")
    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    try:
        async for msg in query(prompt=user_prompt, options=options):
            capture_session_id(msg, job_id)
            agent_heartbeat(job_id, type(msg).__name__)
            if isinstance(msg, AssistantMessage):
                summary["messages"] += 1
                tag = agent_tag(msg)
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        log_line(job_id, f"[{tag}] AGENT: {block.text[:500]}")
                    elif isinstance(block, ToolUseBlock):
                        summary["tool_calls"] += 1
                        args_preview = json.dumps(block.input)[:200]
                        log_line(
                            job_id,
                            f"[{tag}] TOOL {block.name}: {args_preview}",
                        )
                    elif isinstance(block, ThinkingBlock):
                        log_thinking(
                            lambda s, _t=tag: log_line(job_id, f"[{_t}] {s}"),
                            "THINK", block.thinking,
                        )
            elif isinstance(msg, UserMessage):
                tag = agent_tag(msg)
                content = msg.content if isinstance(msg.content, list) else []
                for block in content:
                    if isinstance(block, ToolResultBlock):
                        log_line(
                            job_id,
                            f"[{tag}] " + format_tool_result(block.content, block.is_error),
                        )
            if budget_exceeded(summary["tool_calls"], work_dir, ("solver.py",)):
                log_line(
                    job_id,
                    "BUDGET_ABORT: investigation budget exceeded "
                    f"({summary['tool_calls']} tool calls, no solver.py). "
                    "Stopping early — retry with a hint to push past the "
                    "analysis loop.",
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
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)

    found = collect_outputs(work_dir, ["solver.py", "report.md"])
    summary["solver_present"] = "solver.py" in found
    summary["report_present"] = "report.md" in found
    summary["decomp_used"] = (work_dir / "decomp").exists()
    if summary["decomp_used"]:
        try:
            summary["decomp_function_count"] = len(list((work_dir / "decomp").glob("*.c")))
        except Exception:
            pass
    jd = job_dir(job_id)
    for name, src in found.items():
        (jd / name).write_bytes(src.read_bytes())
    return summary


def run_job(
    job_id: str,
    binary_rel: str,
    description: Optional[str],
    auto_run: bool,
    model_override: Optional[str] = None,
) -> dict:
    jd = job_dir(job_id)
    bin_dir = jd / "bin"
    binary_name = Path(binary_rel).name

    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, binary_name, bin_dir, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)

        sandbox_result = None
        if auto_run and agent_summary.get("solver_present"):
            write_meta(job_id, stage="sandbox-run")
            sandbox_result = attempt_sandbox_run(
                job_id, "solver.py", None, lambda s: log_line(job_id, s)
            )

        flags = scan_job_for_flags(job_id)
        agent_err = agent_summary.get("agent_error")
        agent_err_kind = agent_summary.get("agent_error_kind")
        if agent_err and not agent_summary.get("solver_present"):
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
                   solver_present=agent_summary.get("solver_present", False),
                   decomp_used=agent_summary.get("decomp_used", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
