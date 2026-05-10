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
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep", "Agent"],
        permission_mode="bypassPermissions",
        add_dirs=add_dirs,
        # JOB_ID lets retry/resume preambles (and the agent) anchor on
        # the current job's directory rather than the prior session's
        # baked-in absolute paths.
        env={"JOB_ID": job_id},
        resume=resume_sid,
        fork_session=bool(resume_sid),
        agents=build_recon_agents(model),
    )
    if resume_sid:
        log_line(job_id, f"Forking prior Claude session {resume_sid[:8]}…")

    user_prompt = build_user_prompt(src_root, target_url, description, auto_run)
    log_line(job_id, f"Launching Claude agent (model={model})")
    log_line(job_id, f"Source root: {src_root or '(remote-only)'}")

    soft_timeout = int(read_meta(job_id).get("job_timeout") or 0)
    watchdog = asyncio.create_task(soft_timeout_watchdog(job_id, soft_timeout))

    summary: dict = {"messages": 0, "tool_calls": 0, "model": model}

    sandbox_result: Optional[dict] = None

    def _sandbox_for(script_name: str) -> Optional[dict]:
        return attempt_sandbox_run(
            job_id, script_name, target_url, lambda s: log_line(job_id, s),
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
        # Clear the awaiting_decision flag if the watchdog already fired —
        # the job has finished and the user no longer needs to decide.
        if read_meta(job_id).get("awaiting_decision"):
            write_meta(job_id, awaiting_decision=False)
        # Carry artifacts up to the job dir. Runs in `finally` so any
        # abrupt exit (RQ stop / Stop&Resume / SIGTERM-with-grace) still
        # flushes exploit.py / report.md into <jobdir>/, where the API's
        # file links look. Wrapped in its own try/except so a copy
        # failure can't mask the real agent error in summary.
        try:
            jd = job_dir(job_id)
            # Prefer the agent's cwd, but also check /root/, the job root, and
            # any prior-attempt work dirs (for retry/resume — the forked SDK
            # session sometimes re-uses absolute paths from the prior tool
            # history and silently writes into the OLD job dir).
            fallback_dirs = prior_work_dirs(job_id)
            found = collect_outputs(
                work_dir, ["exploit.py", "report.md"], fallback_dirs=fallback_dirs,
            )
            if "exploit.py" not in found and (jd / "exploit.py").is_file():
                found["exploit.py"] = jd / "exploit.py"
            if "report.md" not in found and (jd / "report.md").is_file():
                found["report.md"] = jd / "report.md"
            summary["exploit_present"] = "exploit.py" in found
            summary["report_present"] = "report.md" in found
            for name, src in found.items():
                target_path = jd / name
                if src.resolve() != target_path.resolve():
                    target_path.write_bytes(src.read_bytes())
                # Mirror into work_dir too — the next /retry uses
                # `<this_job>/work/` as its carry source via shutil.copytree,
                # so without this any fallback recovery (file actually written
                # to a stale absolute path) would be carried as a stale copy
                # AGAIN on the next retry.
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
