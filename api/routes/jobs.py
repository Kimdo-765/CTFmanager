import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

from api.queue import get_queue, get_redis
from api.storage import JOBS_DIR, read_job_meta, write_job_meta

router = APIRouter()


def _hard_stop_job(job_id: str) -> dict:
    """Try to actually halt work on a running job:
    1. Send STOP_JOB command to whichever worker is running it (RQ pub-sub).
    2. Find sibling docker containers labelled hextech_ctf_tool_job_id=<id> and
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
            filters={"label": f"hextech_ctf_tool_job_id={job_id}"},
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
            meta["runnable_script"] = _detect_runnable_script(d)
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


def _detect_runnable_script(job_dir: Path) -> str | None:
    for name in ("exploit.py", "solver.py", "solver.sage"):
        if (job_dir / name).is_file():
            return name
    return None


@router.get("/{job_id}")
def get_job(job_id: str):
    meta = read_job_meta(job_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")

    rq_status = None
    rq_worker_name = None
    rq_worker_heartbeat = None
    try:
        q = get_queue()
        rq_job = q.fetch_job(job_id)
        if rq_job is not None:
            rq_status = rq_job.get_status(refresh=True)
            rq_worker_name = rq_job.worker_name
    except Exception:
        pass

    # Pull the assigned worker's last_heartbeat directly from Redis so
    # the UI can tell "agent silent but worker alive" apart from
    # "worker process dead". RQ refreshes this every ~10s while the
    # worker is healthy.
    if rq_worker_name:
        try:
            conn = get_redis()
            hb = conn.hget(f"rq:worker:{rq_worker_name}", "last_heartbeat")
            if hb:
                rq_worker_heartbeat = hb.decode() if isinstance(hb, bytes) else hb
        except Exception:
            pass

    # Always derive a `runnable_script` field from the filesystem so the UI
    # can show the run-now button even on jobs whose meta was written before
    # the field existed (or whose orchestrator didn't set it).
    runnable_script = _detect_runnable_script(JOBS_DIR / Path(job_id).name)

    return {
        **meta,
        "rq_status": rq_status,
        "rq_worker_name": rq_worker_name,
        "rq_worker_heartbeat_at": rq_worker_heartbeat,
        "runnable_script": runnable_script,
    }


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
def get_job_log(job_id: str, tail: int | None = None):
    """Return run.log. With ?tail=N (bytes), returns at most the last N
    bytes — used by the polling UI so multi-MB logs don't get re-shipped
    every 2s after the agent does verbose Read/Bash output. The cut is
    aligned to the next newline so we never start mid-line.
    """
    log = JOBS_DIR / job_id / "run.log"
    if not log.exists():
        return PlainTextResponse("", status_code=200)
    if tail and tail > 0:
        try:
            size = log.stat().st_size
        except OSError:
            return PlainTextResponse("", status_code=200)
        if size > tail:
            with log.open("rb") as fp:
                fp.seek(size - tail)
                fp.readline()  # skip partial line
                data = fp.read()
            text = data.decode("utf-8", errors="replace")
            header = (
                f"…(showing last {len(data)} of {size} bytes — "
                f"download full log via /api/jobs/{job_id}/file/run.log)…\n"
            )
            return PlainTextResponse(header + text)
    return PlainTextResponse(log.read_text(errors="replace"))


@router.get("/{job_id}/file/{name}")
def get_job_file(job_id: str, name: str):
    safe = Path(name).name
    jd = JOBS_DIR / job_id
    # Primary location: <jobdir>/<name>, populated by the analyzer's
    # carry step at the end of _run_agent. If the run was killed mid-
    # flight (RQ stop / Stop&Resume / SIGKILL) the carry never ran but
    # the artifact is still in <jobdir>/work/<name>. Fall back there
    # so the UI's file links work for stopped jobs too.
    candidates = [jd / safe, jd / "work" / safe]
    for f in candidates:
        if f.is_file():
            return FileResponse(str(f))
    raise HTTPException(status_code=404, detail="file not found")


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
    from modules.settings_io import apply_to_env

    # Pull settings (CALLBACK_URL etc.) into this process's env so the
    # runner spawn picks them up, mirroring what worker run_job() does.
    apply_to_env()

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


@router.patch("/{job_id}/target")
async def patch_target(job_id: str, request: Request):
    """Update only `target_url` on an existing job's meta — no retry,
    no resume, no new job enqueued.

    The next manual `/run` (and the default of any future `/retry` /
    `/resume`) picks up the new value. Useful when the original target
    was wrong / the challenge moved / you want to point a finished
    job at a fresh remote without forking the conversation.

    Body (JSON): {"target": "<new>"} — pass the literal string
    "(none)" or an empty string to CLEAR the target.

    Returns: {"ok": true, "target_url": <new>, "prior": <old>}.
    """
    # `Path(job_id).name` strips path separators but doesn't reject
    # ".."/"."/"" — those would resolve to JOBS_DIR's parent or itself.
    # Be explicit so the audit-log open() can't punch out of the dir.
    safe = Path(job_id).name
    if safe in ("", ".", "..") or "/" in safe or "\\" in safe:
        raise HTTPException(status_code=400, detail="invalid job_id")
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    try:
        body = await request.json()
    except Exception:
        body = {}
    if "target" not in body and "target_url" not in body:
        raise HTTPException(
            status_code=400,
            detail='request body must include "target" (use "(none)" to clear)',
        )
    raw = body.get("target")
    if raw is None:
        raw = body.get("target_url")
    clean = ("" if raw is None else str(raw)).strip()
    if clean.lower() in ("(none)", "none", ""):
        new_target: str | None = None
    else:
        new_target = clean

    prior = meta.get("target_url")
    # IMPORTANT: use modules._common.write_meta (read-merge-write at
    # WRITE time), not api.storage.write_job_meta (which would overwrite
    # the entire file from this snapshot). The worker holds the meta
    # for in-flight jobs and writes heartbeat + cost + status updates
    # constantly; full overwrite from here would clobber any keys the
    # worker added between our read and our write.
    from modules._common import write_meta as _merge_write_meta
    _merge_write_meta(safe, target_url=new_target)

    # Audit trail in run.log so the change is visible to the reviewer
    # on a future retry and to anyone tailing the run.
    log = JOBS_DIR / safe / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    try:
        with log.open("a") as fp:
            fp.write(
                f"[{ts}] [meta] target_url updated by user: "
                f"{prior!r} -> {new_target!r}\n"
            )
    except OSError:
        pass

    return {"ok": True, "target_url": new_target, "prior": prior}


def _record_decision(safe: str, decision: str, log_msg: str) -> dict:
    """Clear the awaiting_decision flag and append a run.log line. Returns
    the merged meta on success."""
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    merged = {
        **meta,
        "awaiting_decision": False,
        "timeout_decision": decision,
    }
    write_job_meta(safe, merged)

    # Append to run.log so the user can see the decision in the live log
    from datetime import datetime
    log = JOBS_DIR / safe / "run.log"
    try:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {log_msg}\n")
    except Exception:
        pass
    return merged


@router.post("/{job_id}/timeout/continue")
def timeout_continue(job_id: str):
    """User chose to keep the job running past its soft timeout. The
    watchdog has already fired once and will NOT re-fire — the agent
    runs to natural completion (or hits RQ's hard kill ceiling)."""
    safe = Path(job_id).name
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    if not meta.get("awaiting_decision"):
        return {"ok": True, "noop": True, "decision": meta.get("timeout_decision")}
    _record_decision(
        safe, "continue",
        "User chose CONTINUE — job keeps running past the soft timeout.",
    )
    return {"ok": True, "decision": "continue"}


@router.post("/{job_id}/timeout/kill")
def timeout_kill(job_id: str):
    """User chose to halt the job. Runs the same hard-stop path as
    DELETE: signals RQ, kills sibling containers."""
    safe = Path(job_id).name
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    _record_decision(
        safe, "kill",
        "User chose STOP — halting the job at soft timeout.",
    )
    halt_info = _hard_stop_job(safe)
    # Reflect the cancellation in meta so list/detail endpoints don't
    # keep showing it as 'running'.
    final = read_job_meta(safe) or {}
    write_job_meta(safe, {**final, "status": "failed", "error": "Stopped by user at soft timeout"})
    return {"ok": True, "decision": "kill", "halt": halt_info}
