from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue
from api.storage import job_dir, new_job_id, write_job_meta

router = APIRouter()


@router.post("/analyze")
async def analyze_rev(
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    auto_run: bool = Form(False),
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

    meta = {
        "id": job_id,
        "module": "rev",
        "status": "queued",
        "filename": binary_name,
        "description": description,
        "auto_run": auto_run,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.rev.analyzer.run_job",
        job_id,
        binary_name,
        description,
        auto_run,
        job_id=job_id,
    )

    return {"job_id": job_id, "status": "queued"}
