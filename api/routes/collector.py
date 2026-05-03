"""Built-in OOB callback collector.

Lets the operator skip webhook.site / requestbin entirely:

  1. Run `ngrok http 8000` (or any tunnel that exposes the api port).
  2. Settings → Callback URL = `https://<ngrok>/api/collector/<job_id>`
     OR set CALLBACK_URL to a sentinel like `__BUILTIN__/<job_id>` and
     have the exploit read `BUILTIN_COLLECTOR_BASE` from env.
  3. Anything the bot fetches under that path is logged to
     /data/jobs/<job_id>/callbacks.jsonl AND any flag-shaped string in
     the path/query/body is auto-extracted via scan_job_for_flags().

This route is exempt from auth so external bots can hit it. The token
is the job_id itself — the operator should keep job IDs secret if
they care about that.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from api.storage import JOBS_DIR, read_job_meta
from modules._common import scan_job_for_flags, write_meta

router = APIRouter()


@router.api_route(
    "/{job_id}/{tail:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
@router.api_route(
    "/{job_id}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
)
async def collect(request: Request, job_id: str, tail: str = ""):
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    if not jd.is_dir():
        return PlainTextResponse("ok", status_code=200)

    body = b""
    try:
        body = await request.body()
    except Exception:
        pass

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": "/" + tail if tail else "/",
        "query": dict(request.query_params),
        "headers": {k: v for k, v in request.headers.items()
                    if k.lower() not in ("authorization", "cookie")},
        "client": request.client.host if request.client else None,
        "body": body[:8192].decode("utf-8", errors="replace"),
        "body_truncated": len(body) > 8192,
    }
    log = jd / "callbacks.jsonl"
    with log.open("a") as f:
        f.write(json.dumps(record) + "\n")

    # Re-scan for flags now that the callback might contain one
    flags = scan_job_for_flags(safe, extra_files=["callbacks.jsonl"])
    meta = read_job_meta(safe) or {}
    if flags and set(flags) != set(meta.get("flags") or []):
        write_meta(safe, flags=flags, status="finished")

    return PlainTextResponse("ok", status_code=200)
