#!/usr/bin/env python3
"""ghiant — agent-callable Ghidra decompiler wrapper.

Invokes the hextech_ctf_tool-decompiler sibling container against a binary inside
the current job's directory and stages the per-function .c files locally.

Usage (called by the Claude agent via Bash):
    ghiant <binary>          # writes ./decomp/*.c
    ghiant <binary> <outdir> # writes <outdir>/*.c

Requires JOB_ID in env (set by the orchestrator before launching the agent).
The binary path may be absolute (must be under /data/jobs/<JOB_ID>/) or
relative to cwd; the wrapper resolves it.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "/app")

from modules.pwn.decompile import run_decompiler


USAGE = "usage: ghiant <binary> [outdir]\n"


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.stderr.write(USAGE)
        return 2

    job_id = os.environ.get("JOB_ID", "")
    if not job_id:
        sys.stderr.write("JOB_ID env not set; ghiant must be run inside an agent job.\n")
        return 2

    job_root = Path(f"/data/jobs/{job_id}").resolve()
    if not job_root.is_dir():
        sys.stderr.write(f"job dir not found: {job_root}\n")
        return 2

    raw = Path(sys.argv[1])
    binary = (raw if raw.is_absolute() else (Path.cwd() / raw)).resolve()
    if not binary.is_file():
        sys.stderr.write(f"binary not found: {binary}\n")
        return 2

    try:
        binary_rel = binary.relative_to(job_root)
    except ValueError:
        sys.stderr.write(
            f"binary must be under job dir ({job_root}); got {binary}\n"
        )
        return 2

    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else (Path.cwd() / "decomp")
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[ghiant] decompiling {binary_rel} (this can take 1–3 min) ...", file=sys.stderr, flush=True)
    try:
        decomp_dir, _logs = run_decompiler(job_id, str(binary_rel))
    except Exception as e:
        sys.stderr.write(f"[ghiant] decompiler failed: {e}\n")
        return 1

    count = 0
    for f in decomp_dir.glob("*.c"):
        shutil.copy(f, out_dir / f.name)
        count += 1
    if count == 0:
        sys.stderr.write("[ghiant] no .c files produced\n")
        return 1

    print(f"[ghiant] {count} functions decompiled to {out_dir}", flush=True)
    print("[ghiant] tip: grep for sinks, e.g.:", flush=True)
    print(f"  grep -lE 'gets|strcpy|sprintf|scanf' {out_dir}/*.c", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
