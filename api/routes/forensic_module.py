from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue
from api.storage import job_dir, new_job_id, write_job_meta

router = APIRouter()

CHUNK = 4 * 1024 * 1024  # 4 MiB


def _stream_to(path: Path, upload: UploadFile) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with path.open("wb") as out:
        while True:
            chunk = upload.file.read(CHUNK)
            if not chunk:
                break
            out.write(chunk)
            total += len(chunk)
    return total


@router.post("/collect")
async def collect_forensic(
    file: UploadFile = File(...),
    image_type: str = Form("auto"),  # auto/raw/qcow2/vmdk/memory
    target_os: str = Form("auto"),  # auto/linux/windows
    description: Optional[str] = Form(None),
    bulk_extractor: bool = Form(False),
    skip_claude: bool = Form(False),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="file required")

    job_id = new_job_id()
    image_name = Path(file.filename).name
    target = job_dir(job_id) / image_name
    size = _stream_to(target, file)
    if size == 0:
        raise HTTPException(status_code=400, detail="empty file")

    meta = {
        "id": job_id,
        "module": "forensic",
        "status": "queued",
        "filename": image_name,
        "image_type": image_type,
        "target_os": target_os,
        "description": description,
        "bulk_extractor": bulk_extractor,
        "skip_claude": skip_claude,
        "size_bytes": size,
    }
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules.forensic.orchestrator.run_job",
        job_id,
        image_name,
        image_type,
        target_os,
        description,
        bulk_extractor,
        skip_claude,
        job_id=job_id,
    )

    return {"job_id": job_id, "status": "queued", "size_bytes": size}
