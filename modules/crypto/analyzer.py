import asyncio
import json
import os
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
    prior_work_dirs,
    read_meta,
    run_main_agent_session,
    scan_job_for_flags,
    soft_timeout_watchdog,
    write_meta,
)
from modules._runner import attempt_sandbox_run
from modules.crypto.prompts import SYSTEM_PROMPT, build_user_prompt
from modules.settings_io import apply_to_env, get_setting


async def _run_agent(
    job_id: str,
    src_root: Optional[str],
    target: Optional[str],
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
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep", "Agent"],
        permission_mode="bypassPermissions",
        add_dirs=add_dirs,
        # JOB_ID lets retry/resume preambles anchor the agent on the
        # current job's directory rather than the prior session's
        # baked-in absolute paths.
        env={"JOB_ID": job_id},
        resume=resume_sid,
        fork_session=bool(resume_sid),
        agents=build_recon_agents(model),
    )
    user_prompt = build_user_prompt(src_root, target, description, auto_run)

    log_line(job_id, f"Launching Claude agent (model={model})")
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")
    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        return attempt_sandbox_run(
            job_id, script_name, target, lambda s: log_line(job_id, s),
            use_sage=script_name.endswith(".sage"),
        )

    try:
        sandbox_result = await run_main_agent_session(
            job_id,
            options=options,
            initial_prompt=user_prompt,
            summary=summary,
            work_dir=work_dir,
            # solver.py first so a co-existent .sage doesn't take
            # priority unless the agent only produced .sage.
            artifact_names=("solver.py", "solver.sage"),
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
        # flushes solver.{py,sage} / report.md into <jobdir>/. Wrapped
        # in its own try/except so a copy failure can't mask the real
        # agent error in summary.
        try:
            jd = job_dir(job_id)
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir, ["solver.py", "solver.sage", "report.md"],
                fallback_dirs=fallback_dirs,
            )
            for name in ("solver.py", "solver.sage", "report.md"):
                if name not in found and (jd / name).is_file():
                    found[name] = jd / name
            summary["solver_present"] = ("solver.py" in found) or ("solver.sage" in found)
            summary["sage_solver"] = ("solver.sage" in found) and ("solver.py" not in found)
            summary["report_present"] = "report.md" in found
            for name, src in found.items():
                target_path = jd / name
                if src.resolve() != target_path.resolve():
                    target_path.write_bytes(src.read_bytes())
                work_target = work_dir / name
                if src.resolve() != work_target.resolve():
                    work_target.write_bytes(src.read_bytes())
        except Exception as carry_err:
            log_line(job_id, f"CARRY_ERROR: {carry_err}")
    summary["sandbox"] = sandbox_result
    return summary


def run_job(
    job_id: str,
    src_root: Optional[str],
    target: Optional[str],
    description: Optional[str],
    auto_run: bool,
    use_sage: bool = False,
    model_override: Optional[str] = None,
) -> dict:
    apply_to_env()
    write_meta(job_id, status="running", stage="analyze")
    try:
        agent_summary = anyio.run(
            _run_agent, job_id, src_root, target, description, auto_run,
            model_override,
        )
        cost = extract_cost(agent_summary)

        sandbox_result = agent_summary.pop("sandbox", None)

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
            "use_sage": use_sage,
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
                   solver_present=agent_summary.get("solver_present", False))
        return result
    except Exception as e:
        log_line(job_id, f"ERROR: {e}\n{traceback.format_exc()}")
        write_meta(job_id, status="failed", error=str(e))
        raise
