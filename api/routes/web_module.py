from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, resolve_timeout
from api.storage import (
    extract_if_archive,
    job_dir,
    new_job_id,
    save_upload,
    write_job_meta,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_web(
    file: UploadFile = File(...),
    target_url: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
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
    chosen_model = (model or "").strip() or None
    meta = {
        "id": job_id,
        "module": "web",
        "status": "queued",
        "filename": file.filename,
        "target_url": target_url,
        "description": description,
        "auto_run": auto_run,
        "job_timeout": timeout,
        "model": chosen_model,
        "src_root": str(src_root),
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.web.analyzer.run_job",
        job_id,
        str(src_root),
        target_url,
        description,
        auto_run,
        chosen_model,
        job_id=job_id,
        job_timeout=timeout,
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
