from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, resolve_timeout
from api.storage import job_dir, new_job_id, write_job_meta

router = APIRouter()


@router.post("/analyze")
async def analyze_pwn(
    file: UploadFile = File(...),
    target: Optional[str] = Form(None),
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
    bin_dir = job_dir(job_id) / "bin"
    bin_dir.mkdir(exist_ok=True)

    binary_name = Path(file.filename).name
    target_path = bin_dir / binary_name
    target_path.write_bytes(content)
    target_path.chmod(0o755)

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    meta = {
        "id": job_id,
        "module": "pwn",
        "status": "queued",
        "filename": binary_name,
        "target_url": target,
        "description": description,
        "auto_run": auto_run,
        "job_timeout": timeout,
        "model": chosen_model,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.pwn.analyzer.run_job",
        job_id,
        binary_name,
        target,
        description,
        auto_run,
        chosen_model,
        job_id=job_id,
        job_timeout=timeout,
    )

    return {"job_id": job_id, "status": "queued", "job_timeout": timeout, "model": chosen_model}
