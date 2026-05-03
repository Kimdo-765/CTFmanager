import os

from redis import Redis
from rq import Queue

from modules.settings_io import get_setting

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

_redis = Redis.from_url(REDIS_URL)


def _job_timeout() -> int:
    """Read job timeout from settings on each call so changes via the
    Settings tab apply to subsequent enqueues without an api restart."""
    try:
        return int(get_setting("job_timeout_seconds") or 900)
    except (TypeError, ValueError):
        return 900


def resolve_timeout(per_job: int | None) -> int:
    """Per-job override > global setting > 900s default."""
    if per_job and per_job > 0:
        return int(per_job)
    return _job_timeout()


def get_queue() -> Queue:
    return Queue("ctfmanager", connection=_redis, default_timeout=_job_timeout())


def get_redis() -> Redis:
    return _redis
