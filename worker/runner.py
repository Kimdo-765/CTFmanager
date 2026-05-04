import multiprocessing
import os
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/app")
from modules.settings_io import get_setting  # noqa: E402

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
JOBS_DIR = Path("/data/jobs")
CLEANUP_INTERVAL_S = 3600


def _resolve_concurrency() -> int:
    val = get_setting("worker_concurrency")
    try:
        n = int(val) if val is not None else 0
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        n = int(os.environ.get("WORKER_CONCURRENCY", "3") or 3)
    return max(1, n)


def cleanup_loop() -> None:
    while True:
        try:
            ttl = int(get_setting("job_ttl_days") or 0)
            if ttl <= 0:
                time.sleep(CLEANUP_INTERVAL_S)
                continue
            cutoff = datetime.now(timezone.utc) - timedelta(days=ttl)
            removed = 0
            if JOBS_DIR.exists():
                for d in JOBS_DIR.iterdir():
                    if not d.is_dir():
                        continue
                    mtime = datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc)
                    if mtime < cutoff:
                        try:
                            shutil.rmtree(d)
                            removed += 1
                        except Exception as e:
                            print(f"[cleanup] failed to rm {d}: {e}", flush=True)
            if removed:
                print(f"[cleanup] removed {removed} jobs older than {ttl}d", flush=True)
        except Exception as e:
            print(f"[cleanup] loop error: {e}", flush=True)
        time.sleep(CLEANUP_INTERVAL_S)


def run_one_worker(idx: int, scheduler: bool) -> None:
    """Worker process target. Reimport everything inside the child so
    state isn't shared across processes (cleaner for the SDK + docker-py
    clients which open file descriptors)."""
    from redis import Redis
    from rq import Queue, Worker

    conn = Redis.from_url(REDIS_URL)
    q = Queue("hexttech_ctf_tool", connection=conn)
    name = f"htct-w{idx}"
    print(f"[worker] {name} starting (scheduler={scheduler})", flush=True)
    Worker([q], connection=conn, name=name).work(with_scheduler=scheduler)


def main() -> int:
    n = _resolve_concurrency()
    print(f"[worker] launching {n} worker process(es)", flush=True)

    # Cleanup thread runs in the parent only.
    threading.Thread(target=cleanup_loop, daemon=True).start()

    # Use spawn (not fork) to avoid copying threading state and any FDs
    # that should not be shared (docker-py http client, redis pool, etc).
    ctx = multiprocessing.get_context("spawn")
    procs: list[multiprocessing.process.BaseProcess] = []
    for i in range(n):
        p = ctx.Process(
            target=run_one_worker,
            args=(i, i == 0),  # only worker 0 runs the RQ scheduler
            name=f"htct-w{i}",
        )
        p.start()
        procs.append(p)

    def _shutdown(signum, frame):
        print(f"[worker] shutdown signal {signum}, terminating children", flush=True)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # Reap children. If any dies unexpectedly, log and respawn.
    while procs:
        for i, p in enumerate(list(procs)):
            p.join(timeout=1)
            if not p.is_alive():
                print(f"[worker] {p.name} exited code={p.exitcode}; respawning", flush=True)
                np = ctx.Process(
                    target=run_one_worker,
                    args=(i, i == 0),
                    name=f"htct-w{i}",
                )
                np.start()
                procs[i] = np
    return 0


if __name__ == "__main__":
    sys.exit(main())
