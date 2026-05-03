import json
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"
UPLOADS_DIR = DATA_DIR / "uploads"


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_job_meta(job_id: str, meta: dict[str, Any]) -> None:
    meta = {**meta, "updated_at": datetime.now(timezone.utc).isoformat()}
    (job_dir(job_id) / "meta.json").write_text(json.dumps(meta, indent=2))


def read_job_meta(job_id: str) -> Optional[dict[str, Any]]:
    f = JOBS_DIR / job_id / "meta.json"
    if not f.exists():
        return None
    return json.loads(f.read_text())


def save_upload(job_id: str, filename: str, content: bytes) -> Path:
    src_dir = job_dir(job_id) / "src"
    src_dir.mkdir(exist_ok=True)
    target = src_dir / filename
    target.write_bytes(content)
    return target


def extract_if_archive(path: Path) -> Path:
    """If path is a zip, extract into a sibling dir and return that dir.
    Otherwise return the parent directory.
    """
    if path.suffix.lower() == ".zip":
        out = path.parent / "extracted"
        out.mkdir(exist_ok=True)
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(out)
        return out
    return path.parent


def cleanup_job(job_id: str) -> None:
    p = JOBS_DIR / job_id
    if p.exists():
        shutil.rmtree(p)
