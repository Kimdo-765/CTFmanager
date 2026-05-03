import json
import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from api.queue import get_queue, get_redis
from api.storage import JOBS_DIR, read_job_meta

router = APIRouter()


def _hard_stop_job(job_id: str) -> dict:
    """Try to actually halt work on a running job:
    1. Send STOP_JOB command to whichever worker is running it (RQ pub-sub).
    2. Find sibling docker containers labelled ctfmanager_job_id=<id> and
       force-remove them (decompiler / forensic / misc / runner).
    Errors are swallowed — best-effort.
    """
    info: dict = {"sent_stop": False, "containers_killed": 0, "rq_cancelled": False}
    conn = get_redis()
    # 1) Tell RQ to interrupt the running job. send_stop_job_command works only
    #    on running jobs; for queued ones, plain cancel() is enough.
    try:
        from rq.command import send_stop_job_command
        send_stop_job_command(conn, job_id)
        info["sent_stop"] = True
    except Exception:
        pass
    try:
        from rq.job import Job
        rq_job = Job.fetch(job_id, connection=conn)
        try:
            rq_job.cancel()
            info["rq_cancelled"] = True
        except Exception:
            pass
    except Exception:
        pass

    # 2) Kill any sibling containers spawned for this job
    try:
        import docker as _docker
        client = _docker.from_env()
        containers = client.containers.list(
            all=True,
            filters={"label": f"ctfmanager_job_id={job_id}"},
        )
        for c in containers:
            try:
                c.kill()
            except Exception:
                pass
            try:
                c.remove(force=True)
                info["containers_killed"] += 1
            except Exception:
                pass
    except Exception:
        pass

    return info


@router.get("")
def list_jobs():
    if not JOBS_DIR.exists():
        return {"jobs": []}
    out = []
    for d in sorted(JOBS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = read_job_meta(d.name)
        if meta:
            out.append(meta)
    return {"jobs": out}


@router.get("/queue")
def queue_info():
    """Live worker + queue status. Used by the UI to show concurrency."""
    from rq import Worker
    conn = get_redis()
    q = get_queue()
    workers = Worker.all(connection=conn)
    busy = []
    idle = []
    for w in workers:
        info = {"name": w.name, "state": w.get_state()}
        if w.get_current_job_id():
            info["job_id"] = w.get_current_job_id()
        if info["state"] == "busy":
            busy.append(info)
        else:
            idle.append(info)
    return {
        "queued": q.count,
        "started": q.started_job_registry.count,
        "failed": q.failed_job_registry.count,
        "workers_total": len(workers),
        "workers_busy": len(busy),
        "workers_idle": len(idle),
        "workers": busy + idle,
    }


@router.get("/stats")
def get_stats():
    """Aggregate cost and counts across all jobs."""
    if not JOBS_DIR.exists():
        return {"total_cost_usd": 0.0, "by_module": {}, "count": 0}
    total = 0.0
    by_module: dict[str, dict] = {}
    count = 0
    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta_path = d / "meta.json"
        result_path = d / "result.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        count += 1
        module = meta.get("module", "unknown")
        bucket = by_module.setdefault(module, {"count": 0, "cost_usd": 0.0})
        bucket["count"] += 1
        cost = float(meta.get("cost_usd") or 0.0)
        if cost == 0.0 and result_path.exists():
            try:
                result = json.loads(result_path.read_text())
                cost = float(result.get("cost_usd") or 0.0)
            except Exception:
                pass
        bucket["cost_usd"] += cost
        total += cost
    return {"total_cost_usd": round(total, 4), "by_module": by_module, "count": count}


@router.get("/{job_id}")
def get_job(job_id: str):
    meta = read_job_meta(job_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")

    rq_status = None
    try:
        q = get_queue()
        rq_job = q.fetch_job(job_id)
        if rq_job is not None:
            rq_status = rq_job.get_status(refresh=True)
    except Exception:
        pass

    return {**meta, "rq_status": rq_status}


@router.delete("")
def bulk_delete_jobs(
    status: str | None = None,
    module: str | None = None,
    all: bool = False,
):
    """Bulk delete jobs.

    Query params:
      - status: only delete jobs with this status (queued/running/finished/failed)
      - module: only delete jobs from this module
      - all=true: also cancel queued/running jobs (in addition to filesystem cleanup)

    Without any filter, deletes finished + failed only (safe default — leaves
    queued/running jobs alone).
    """
    if not JOBS_DIR.exists():
        return {"deleted": 0, "skipped": 0, "ids": []}

    safe_default_statuses = {"finished", "failed", "no_flag"}
    deleted_ids: list[str] = []
    skipped = 0

    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta = read_job_meta(d.name)
        if not meta:
            continue
        st = meta.get("status")
        mod = meta.get("module")
        # Filter
        if status and st != status:
            continue
        if module and mod != module:
            continue
        if not status and not all and st not in safe_default_statuses:
            skipped += 1
            continue
        # Halt running/queued jobs: stop the worker + kill sibling containers
        if st in ("queued", "running"):
            _hard_stop_job(d.name)
        try:
            shutil.rmtree(d)
            deleted_ids.append(d.name)
        except Exception:
            skipped += 1

    return {"deleted": len(deleted_ids), "skipped": skipped, "ids": deleted_ids}


@router.delete("/{job_id}")
def delete_job(job_id: str):
    safe = Path(job_id).name
    d = JOBS_DIR / safe
    if not d.exists():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe)
    halt_info = None
    if meta and meta.get("status") in ("queued", "running"):
        halt_info = _hard_stop_job(safe)
    shutil.rmtree(d)
    return {"deleted": safe, "halt": halt_info}


@router.get("/{job_id}/log", response_class=PlainTextResponse)
def get_job_log(job_id: str):
    log = JOBS_DIR / job_id / "run.log"
    if not log.exists():
        return PlainTextResponse("", status_code=200)
    return PlainTextResponse(log.read_text(errors="replace"))


@router.get("/{job_id}/file/{name}")
def get_job_file(job_id: str, name: str):
    safe = Path(name).name
    f = JOBS_DIR / job_id / safe
    if not f.exists():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(str(f))


@router.get("/{job_id}/result")
def get_job_result(job_id: str):
    f = JOBS_DIR / job_id / "result.json"
    if not f.exists():
        raise HTTPException(status_code=404, detail="not yet")
    return json.loads(f.read_text())


@router.post("/{job_id}/run")
def post_run_script(job_id: str, target: str | None = None):
    """Manually re-run the produced exploit/solver script in the runner
    sandbox. Useful when the user didn't enable auto-run, when the
    earlier auto-run failed, or when they want to retry against a
    different target.

    Request can supply `?target=...` to override the stored target.
    Returns the sandbox result (stdout/stderr/exit_code) and updated
    flag list. Updates meta.status accordingly.
    """
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    if not jd.exists():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe) or {}

    # Pick the script the agent produced
    script = None
    for name in ("exploit.py", "solver.py", "solver.sage"):
        if (jd / name).is_file():
            script = name
            break
    if not script:
        raise HTTPException(
            status_code=400,
            detail="no exploit.py / solver.py / solver.sage in this job",
        )
    use_sage = script.endswith(".sage")
    target = (target or meta.get("target_url") or "").strip() or None

    # Sandbox runner spawn (same path the orchestrators use)
    from modules._common import scan_job_for_flags, write_meta
    from modules._runner import attempt_sandbox_run

    def _log(line: str):
        log = jd / "run.log"
        ts = __import__("datetime").datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {line}\n")

    _log(f"[manual-run] executing {script} (target={target}, sage={use_sage})")
    try:
        res = attempt_sandbox_run(safe, script, target, _log, use_sage=use_sage)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"sandbox spawn failed: {e}")
    if res is None:
        raise HTTPException(status_code=500, detail="script missing at run time")

    flags = scan_job_for_flags(safe)
    new_status = "finished" if flags else "no_flag"
    write_meta(safe, status=new_status, flags=flags, manual_run=True)
    return {"sandbox": res, "flags": flags, "status": new_status}
