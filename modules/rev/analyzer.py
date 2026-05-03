import json
import os
import shutil
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

from modules._common import extract_cost, job_dir, log_line, write_meta
from modules._runner import attempt_sandbox_run
from modules.pwn.decompile import run_decompiler
from modules.rev.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting


async def _run_agent(
    job_id: str,
    binary_name: str,
    bin_dir: Path,
    decomp_dir: Path,
    description: Optional[str],
    auto_run: bool,
) -> dict:
    work_dir = job_dir(job_id) / "work"
    work_dir.mkdir(exist_ok=True)

    staged_decomp = work_dir / "decomp"
    staged_bin = work_dir / "bin"
    if staged_decomp.exists():
        shutil.rmtree(staged_decomp)
    if staged_bin.exists():
        shutil.rmtree(staged_bin)
    shutil.copytree(decomp_dir, staged_decomp)
    shutil.copytree(bin_dir, staged_bin)

    model = str(get_setting("claude_model") or "claude-opus-4-7")
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        cwd=str(work_dir),
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
    )
    user_prompt = build_user_prompt(binary_name, description, auto_run)

    log_line(job_id, f"Launching Claude agent (model={model})")
    summary: dict = {"messages": 0, "tool_calls": 0}

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

    solver = work_dir / "solver.py"
    report = work_dir / "report.md"
    summary["solver_present"] = solver.exists()
    summary["report_present"] = report.exists()
    jd = job_dir(job_id)
    if solver.exists():
        (jd / "solver.py").write_bytes(solver.read_bytes())
    if report.exists():
        (jd / "report.md").write_bytes(report.read_bytes())
    return summary


def run_job(
    job_id: str,
    binary_rel: str,
    description: Optional[str],
    auto_run: bool,
) -> dict:
    jd = job_dir(job_id)
    bin_dir = jd / "bin"
    binary_name = Path(binary_rel).name

    apply_to_env()
    write_meta(job_id, status="running", stage="decompile")
    try:
        log_line(job_id, f"Running decompiler on bin/{binary_name}")
        decomp_dir, decomp_logs = run_decompiler(job_id, f"bin/{binary_name}")
        decomp_count = len(list(decomp_dir.glob("*.c")))
        log_line(job_id, f"Decompile produced {decomp_count} .c files")
        if decomp_logs:
            (jd / "decompile.log").write_text(decomp_logs)

        write_meta(job_id, stage="analyze")
        agent_summary = anyio.run(
            _run_agent, job_id, binary_name, bin_dir, decomp_dir, description, auto_run,
        )
        cost = extract_cost(agent_summary)

        sandbox_result = None
        if auto_run and agent_summary.get("solver_present"):
            write_meta(job_id, stage="sandbox-run")
            sandbox_result = attempt_sandbox_run(
                job_id, "solver.py", None, lambda s: log_line(job_id, s)
            )

        result = {
            "agent": agent_summary,
            "decomp_function_count": decomp_count,
            "cost_usd": cost,
            "sandbox": sandbox_result,
        }
        (jd / "result.json").write_text(json.dumps(result, indent=2))
        write_meta(job_id, status="finished", stage="done", cost_usd=cost,
                   solver_present=agent_summary.get("solver_present", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
