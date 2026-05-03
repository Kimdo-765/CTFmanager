from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, resolve_timeout
from api.storage import (
    extract_if_archive,
    new_job_id,
    save_upload,
    write_job_meta,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_crypto(
    file: UploadFile = File(...),
    target: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    use_sage: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="file required")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty file")

    job_id = new_job_id()
    saved = save_upload(job_id, file.filename, content)
    src_root = extract_if_archive(saved)

    timeout = resolve_timeout(job_timeout)
    meta = {
        "id": job_id,
        "module": "crypto",
        "status": "queued",
        "filename": file.filename,
        "target_url": target,
        "description": description,
        "auto_run": auto_run,
        "use_sage": use_sage,
        "job_timeout": timeout,
        "src_root": str(src_root),
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.crypto.analyzer.run_job",
        job_id,
        str(src_root),
        target,
        description,
        auto_run,
        use_sage,
        job_id=job_id,
        job_timeout=timeout,
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout}
