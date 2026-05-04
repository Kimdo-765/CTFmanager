"""Sandboxed exploit/solver execution helper.

After a Claude agent has produced exploit.py / solver.py, the orchestrator
calls run_in_sandbox() to execute the script inside the hexttech_ctf_tool-runner
container instead of the worker. This isolates network and resources from
the worker that holds the docker socket and the API key.

The runner image must be built once via:
    docker compose --profile tools build runner
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import docker

RUNNER_IMAGE = "hexttech_ctf_tool-runner"
SAGE_IMAGE = "sagemath/sagemath:latest"
DEFAULT_TIMEOUT_S = 300
DEFAULT_MEM = "2g"


def _host_path(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError("HOST_DATA_DIR not set on worker")
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


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
) -> dict:
    """Execute /work/<script_rel> inside the runner container with the job
    directory bind-mounted at /work.

    Returns: {exit_code, stdout, stderr, stdout_truncated_to}.
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
        labels={"hexttech_ctf_tool_job_id": job_id, "hexttech_ctf_tool_role": "runner"},
    )
    exit_code = -1
    out = b""
    err = b""
    try:
        result = container.wait(timeout=timeout_s)
        exit_code = int(result.get("StatusCode", -1))
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
    return {
        "exit_code": exit_code,
        "stdout": out_s[-MAX:],
        "stderr": err_s[-MAX:],
        "truncated_to": MAX,
        "image": image,
    }


def attempt_sandbox_run(
    job_id: str,
    script_filename: str,
    target: Optional[str],
    log_fn,
    use_sage: bool = False,
) -> dict | None:
    """Helper for orchestrators that always copy the produced script to the
    job root. Runs <jobdir>/<script_filename> with target as argv if given."""
    work_dir = Path(f"/data/jobs/{job_id}")
    if not (work_dir / script_filename).exists():
        log_fn(f"[runner] {script_filename} missing, cannot auto-run")
        return None
    args = [target] if target else []
    log_fn(f"[runner] executing {script_filename} (target={target}, sage={use_sage}) ...")
    try:
        res = run_in_sandbox(job_id, script_filename, args=args, use_sage=use_sage)
    except Exception as e:
        log_fn(f"[runner] failed to spawn sandbox: {e}")
        return {"error": str(e)}
    log_fn(f"[runner] exit_code={res['exit_code']}; stdout {len(res['stdout'])}B / stderr {len(res['stderr'])}B")
    # Write logs to job dir
    (work_dir / f"{script_filename}.stdout").write_text(res["stdout"])
    (work_dir / f"{script_filename}.stderr").write_text(res["stderr"])
    return res
