"""Sandboxed exploit/solver execution helper.

After a Claude agent has produced exploit.py / solver.py, the orchestrator
calls run_in_sandbox() to execute the script inside the hextech_ctf_tool-runner
container instead of the worker. This isolates network and resources from
the worker that holds the docker socket and the API key.

The runner image must be built once via:
    docker compose --profile tools build runner

When the `enable_judge` setting is on (default), each call to
attempt_sandbox_run() is wrapped by three short Claude judge calls
defined in modules._judge:

  pre   — review the script BEFORE the container starts. Severity=high
          aborts the run with a `prejudge_blocked` reason.
  during— ONE stall-detection call when the container has emitted no
          new output for 60s while still alive. Judge can decide to
          kill (parse-error / hung) or wait (legitimate slow work).
  post  — categorize the result (success / partial / hung /
          parse_error / network_error / crash / timeout / unknown)
          and produce a retry-ready hint.

Disabling `enable_judge` reverts to plain blocking wait + return.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

import docker

from modules import _judge
from modules.settings_io import get_setting

RUNNER_IMAGE = "hextech_ctf_tool-runner"
SAGE_IMAGE = "sagemath/sagemath:latest"
DEFAULT_TIMEOUT_S = 300
DEFAULT_MEM = "2g"

# How long can the container go without emitting any new stdout/stderr
# before we ask the judge whether to kill it. Single-shot: we ask at
# most once per run (conservative cost mode).
SUPERVISE_STALL_S = 60
# Polling cadence inside _wait_with_supervise. Cheap on docker-py.
_POLL_INTERVAL_S = 2.0


def _host_path(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError("HOST_DATA_DIR not set on worker")
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


def _judge_enabled() -> bool:
    """Default ON; off only if the user explicitly disabled it."""
    try:
        v = get_setting("enable_judge")
    except Exception:
        return True
    return bool(v) if v is not None else True


def _wait_with_supervise(
    container,
    *,
    timeout_s: int,
    job_dir_path: Path,
    script_rel: str,
    log_fn,
    enable_judge: bool,
) -> dict:
    """Block until the container exits, the timeout fires, or the
    supervise judge votes kill.

    Returns a dict matching docker-py's `container.wait()` plus optional
    fields:
      StatusCode             — container exit code, or -1 if unknown
      timeout (bool)         — True if timeout_s elapsed before exit
      killed_by_supervise    — True if the supervise judge killed it
      supervise              — dict from supervise_run_once when called
    """
    start = time.time()
    last_size = 0
    last_change = start
    supervised = False
    supervise_result: dict | None = None

    while True:
        # Has the container exited?
        try:
            container.reload()
            status = container.status
        except Exception:
            status = "unknown"

        if status == "exited":
            try:
                rc = container.wait(timeout=2)
            except Exception:
                rc = {"StatusCode": -1}
            if supervise_result is not None:
                rc["supervise"] = supervise_result
            return rc

        # Hard timeout — kill and return.
        elapsed = time.time() - start
        if elapsed > timeout_s:
            log_fn(f"[runner] timeout after {int(elapsed)}s — killing container")
            try:
                container.kill()
            except Exception:
                pass
            return {
                "StatusCode": -1,
                "timeout": True,
                "supervise": supervise_result,
            }

        # Stall detection on combined log byte-length. If the docker
        # socket hiccups and `container.logs()` raises, we have no
        # signal — treat it as "we don't know" by refreshing
        # `last_change`. Otherwise a string of fetch failures would
        # falsely register as a 60s stall and burn one supervise judge
        # call against an empty buffer.
        log_fetch_ok = True
        try:
            buf = container.logs(stdout=True, stderr=True)
        except Exception:
            buf = b""
            log_fetch_ok = False
        if not log_fetch_ok:
            last_change = time.time()
        elif len(buf) != last_size:
            last_size = len(buf)
            last_change = time.time()
        elif (
            enable_judge
            and not supervised
            and (time.time() - last_change) > SUPERVISE_STALL_S
        ):
            stall_real = int(time.time() - last_change)
            log_fn(
                f"[runner] no output for {stall_real}s while alive — "
                f"asking judge whether to kill"
            )
            try:
                out_tail = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                out_tail = ""
            try:
                err_tail = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                err_tail = ""
            try:
                supervise_result = _judge.supervise_run_once(
                    job_dir_path,
                    script_rel,
                    stall_real,
                    out_tail[-4096:],
                    err_tail[-4096:],
                    log_fn,
                )
            except Exception as e:
                log_fn(f"[judge] supervise failed: {e}")
                supervise_result = {"action": "continue", "reason": str(e)}
            supervised = True
            if supervise_result.get("action") == "kill":
                try:
                    container.kill()
                except Exception:
                    pass
                return {
                    "StatusCode": -1,
                    "killed_by_supervise": True,
                    "supervise": supervise_result,
                }

        time.sleep(_POLL_INTERVAL_S)


def run_in_sandbox(
    job_id: str,
    script_rel: str,
    args: list[str] | None = None,
    image: str = RUNNER_IMAGE,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    mem_limit: str = DEFAULT_MEM,
    network: str = "bridge",
    workdir: str = "/work",
    use_sage: bool = False,
    *,
    log_fn=None,
    enable_judge: bool = False,
) -> dict:
    """Execute /work/<script_rel> inside the runner container with the job
    directory bind-mounted at /work.

    When `enable_judge` is True the wait loop calls
    `modules._judge.supervise_run_once` after SUPERVISE_STALL_S of
    silence. Pre/post judge calls happen in attempt_sandbox_run, not
    here, so callers that want only "during" supervision can set this
    flag while still calling run_in_sandbox directly.

    Returns: {exit_code, stdout, stderr, stdout_truncated_to,
              timeout?, killed_by_supervise?, supervise?}.
    """
    args = args or []
    if use_sage:
        image = SAGE_IMAGE
        cmd = ["sage", f"{workdir}/{script_rel}", *args]
    else:
        cmd = ["python3", f"{workdir}/{script_rel}", *args]

    # Forward CALLBACK_URL + COLLECTOR_BASE so exploits have a stable
    # OOB channel. CALLBACK_URL is the operator-supplied tunnel
    # (ngrok / VPS); the agent should append `/api/collector/<JOB_ID>`
    # to it so the built-in collector endpoint receives the callback,
    # auto-extracts any flag in the URL, and updates the job status.
    env: dict[str, str] = {
        "PYTHONUNBUFFERED": "1",
        "JOB_ID": job_id,
    }
    cb = os.environ.get("CALLBACK_URL", "").strip()
    if cb:
        env["CALLBACK_URL"] = cb
        env["COLLECTOR_URL"] = f"{cb.rstrip('/')}/api/collector/{job_id}"

    client = docker.from_env()
    container = client.containers.run(
        image=image,
        command=cmd,
        volumes={_host_path(job_id): {"bind": workdir, "mode": "rw"}},
        working_dir=workdir,
        mem_limit=mem_limit,
        network_mode=network,
        environment=env,
        stdout=True,
        stderr=True,
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "runner"},
    )
    exit_code = -1
    out = b""
    err = b""
    timeout_hit = False
    killed_by_supervise = False
    supervise_payload: dict | None = None
    job_dir_path = Path(f"/data/jobs/{job_id}")
    _log = log_fn or (lambda _msg: None)

    try:
        result = _wait_with_supervise(
            container,
            timeout_s=timeout_s,
            job_dir_path=job_dir_path,
            script_rel=script_rel,
            log_fn=_log,
            enable_judge=enable_judge,
        )
        exit_code = int(result.get("StatusCode", -1))
        timeout_hit = bool(result.get("timeout", False))
        killed_by_supervise = bool(result.get("killed_by_supervise", False))
        supervise_payload = result.get("supervise")
        out = container.logs(stdout=True, stderr=False)
        err = container.logs(stdout=False, stderr=True)
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass

    out_s = out.decode("utf-8", errors="replace")
    err_s = err.decode("utf-8", errors="replace")
    MAX = 64 * 1024
    payload: dict = {
        "exit_code": exit_code,
        "stdout": out_s[-MAX:],
        "stderr": err_s[-MAX:],
        "truncated_to": MAX,
        "image": image,
    }
    if timeout_hit:
        payload["timeout"] = True
    if killed_by_supervise:
        payload["killed_by_supervise"] = True
    if supervise_payload:
        payload["supervise"] = supervise_payload
    return payload


def attempt_sandbox_run(
    job_id: str,
    script_filename: str,
    target: Optional[str],
    log_fn,
    use_sage: bool = False,
) -> dict | None:
    """Helper for orchestrators that always copy the produced script to the
    job root. Runs <jobdir>/<script_filename> with target as argv if given.

    When `enable_judge` is on (default), wraps the run with three judge
    stages:

      pre  — abort BEFORE the container starts if the judge flags a
             severity=high issue. Returned dict has keys
             {error, prejudge, judge_aborted=True} so the orchestrator
             can record a structured failure.
      during— stall watchdog inside run_in_sandbox.
      post — verdict + retry hint merged into the returned dict under
             the `judge` key.
    """
    work_dir = Path(f"/data/jobs/{job_id}")
    if not (work_dir / script_filename).exists():
        log_fn(f"[runner] {script_filename} missing, cannot auto-run")
        return None

    enable_judge = _judge_enabled()

    # The judge stages share one Claude session via session_id resume.
    # `prejudge_script` writes a sid into _judge._session_ids; postjudge
    # clears it on its happy path. If anything between the two raises
    # before postjudge fires, the sid would otherwise leak into the
    # module-level dict for the worker process's lifetime. Wrap in
    # try/finally so cleanup is unconditional.
    try:
        # ---------- Stage 1: prejudge (advisory) ----------
        # Decision power lives with the main agent — main is expected to
        # have called the judge subagent itself before finalizing (see the
        # JUDGE GATE block in mission_block). The orchestrator's prejudge
        # here is a paper-trail backstop: findings get recorded into
        # result.json so the retry reviewer can reference them, but the
        # severity of those findings does NOT block the runner. Hangs /
        # parse-error scripts are still caught by the supervise stall
        # watchdog and surfaced by postjudge.
        prejudge: dict | None = None
        if enable_judge:
            try:
                prejudge = _judge.prejudge_script(
                    work_dir, script_filename, target, log_fn,
                )
            except Exception as e:
                log_fn(f"[judge] prejudge failed: {e}")
                prejudge = {
                    "ok": True,
                    "severity": "low",
                    "issues": [],
                    "raw": "",
                    "error": str(e),
                }
            if prejudge and not prejudge.get("ok") and prejudge.get("severity") == "high":
                log_fn(
                    f"[runner] prejudge advisory: severity=high, "
                    f"{len(prejudge.get('issues') or [])} issues — "
                    f"running anyway (main owns the gate; supervise + "
                    f"postjudge will backstop)"
                )

        # ---------- Stage 2: actual run ----------
        args = [target] if target else []
        log_fn(
            f"[runner] executing {script_filename} "
            f"(target={target}, sage={use_sage}, judge={enable_judge}) ..."
        )
        try:
            res = run_in_sandbox(
                job_id, script_filename, args=args, use_sage=use_sage,
                log_fn=log_fn, enable_judge=enable_judge,
            )
        except Exception as e:
            log_fn(f"[runner] failed to spawn sandbox: {e}")
            return {"error": str(e), "prejudge": prejudge}

        log_fn(
            f"[runner] exit_code={res['exit_code']}; "
            f"stdout {len(res['stdout'])}B / stderr {len(res['stderr'])}B"
        )

        # Write logs to job dir (unchanged contract for downstream tools).
        (work_dir / f"{script_filename}.stdout").write_text(res["stdout"])
        (work_dir / f"{script_filename}.stderr").write_text(res["stderr"])

        # ---------- Stage 3: postjudge ----------
        if enable_judge:
            extra = ""
            if res.get("timeout"):
                extra = "(runner timeout fired before container exit)\n"
            elif res.get("killed_by_supervise"):
                extra = (
                    "(supervise judge killed the container due to stalled "
                    "output)\n"
                )
            try:
                post = _judge.postjudge_run(
                    work_dir,
                    script_filename,
                    res["exit_code"],
                    res["stdout"],
                    res["stderr"],
                    log_fn,
                    extra_context=extra,
                )
            except Exception as e:
                log_fn(f"[judge] postjudge failed: {e}")
                post = {
                    "verdict": "unknown",
                    "summary": "",
                    "retry_hint": "",
                    "raw": "",
                    "error": str(e),
                }
            res["judge"] = post
        if prejudge is not None:
            res["prejudge"] = prejudge
        return res
    finally:
        # postjudge_run already calls _forget_sid on its happy path —
        # this is the safety net for early-exit / exception paths.
        try:
            _judge._forget_sid(job_id)
        except Exception:
            pass
