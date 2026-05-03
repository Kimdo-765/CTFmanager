"""Shared helpers for module orchestrators."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Dict  # noqa: F401

# Common CTF flag formats. The leading prefix can vary per event; cover the
# usual suspects + a generic short-prefix fallback.
FLAG_RE = re.compile(
    r"(?:FLAG|flag|CTF|ctf|HTB|htb|picoCTF|pico|DH|dreamhack|HACKTHEBOX|"
    r"BSidesCP|XCTF|KCTF|TWN|hcamp|hackcamp|samsung|N0PSctf|CCE)\{[^\s}]{1,200}\}",
    re.IGNORECASE,
)
LIBERAL_FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,16}\{[!-~]{2,200}\}")

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


def extract_flags_from_text(text: str, liberal: bool = False) -> list[str]:
    """Return unique CTF-style flags found in `text`."""
    if not text:
        return []
    found = set(FLAG_RE.findall(text))
    if liberal:
        # Add weaker matches (e.g. PROJECT{...}) that didn't trigger the strict prefix list
        found |= set(LIBERAL_FLAG_RE.findall(text)) - found
    return sorted(found)


def scan_job_for_flags(job_id: str, extra_files: list[str] | None = None) -> list[str]:
    """Scan known job artifacts for flag candidates.

    Default scan set: report.md, exploit.py.stdout, solver.py.stdout,
    summary.json (forensic), findings.json (misc), and the run.log.
    `extra_files` can supply additional filenames to scan (relative to the
    job dir).
    """
    jd = job_dir(job_id)
    candidates = [
        "report.md",
        "exploit.py.stdout",
        "exploit.py.stderr",
        "solver.py.stdout",
        "solver.py.stderr",
        "summary.json",
        "findings.json",
        "result.json",
        "run.log",
    ]
    if extra_files:
        candidates.extend(extra_files)

    flags: set[str] = set()
    for name in candidates:
        p = jd / name
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="replace")
        except Exception:
            continue
        flags.update(FLAG_RE.findall(text))
    return sorted(flags)


REFUSAL_HINTS = (
    "usage policy",
    "unable to respond to this request",
    "violates our usage policy",
)


def classify_agent_error(message: str) -> str | None:
    """Return a short error_kind tag for known SDK / Claude failure modes."""
    if not message:
        return None
    low = message.lower()
    if any(h in low for h in REFUSAL_HINTS):
        return "policy_refusal"
    if "rate" in low and "limit" in low:
        return "rate_limit"
    if "timeout" in low or "timed out" in low:
        return "timeout"
    if "auth" in low or "401" in low or "credential" in low:
        return "auth"
    return "unknown"


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
