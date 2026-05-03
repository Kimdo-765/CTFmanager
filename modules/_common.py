"""Shared helpers for module orchestrators."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Dict  # noqa: F401

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"


def job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def log_line(job_id: str, line: str) -> None:
    f = job_dir(job_id) / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    with f.open("a") as fp:
        fp.write(f"[{ts}] {line}\n")


def write_meta(job_id: str, **updates: Any) -> None:
    f = job_dir(job_id) / "meta.json"
    meta = {}
    if f.exists():
        meta = json.loads(f.read_text())
    meta.update(updates)
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    f.write_text(json.dumps(meta, indent=2))


def collect_outputs(work_dir: Path, names: list[str]) -> dict[str, Path]:
    """Find each requested filename. Looks in work_dir first, then falls
    back to /root/ (the agent's HOME — sometimes the agent ignores cwd
    and uses an absolute path under home).

    Returns a dict {name: actual_path} for files that were located.
    """
    found: dict[str, Path] = {}
    candidates_dirs = [work_dir, Path("/root")]
    for name in names:
        for d in candidates_dirs:
            p = d / name
            if p.is_file():
                found[name] = p
                break
    return found


def extract_cost(claude_summary: dict | None) -> float:
    """Pull total_cost_usd out of an agent summary dict, returning 0.0 if absent."""
    if not isinstance(claude_summary, dict):
        return 0.0
    res = claude_summary.get("result")
    if isinstance(res, dict):
        v = res.get("total_cost_usd")
        if isinstance(v, (int, float)):
            return float(v)
    return 0.0
