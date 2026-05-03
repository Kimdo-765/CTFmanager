#!/usr/bin/env python3
"""Forensic collector entrypoint.

Invoked by the worker via:
    docker run --rm -v <hostjob>:/job ctfmanager-forensic <image_path> \
        [--type auto|raw|qcow2|vmdk|memory] [--os auto|linux|windows] \
        [--bulk-extractor]

Outputs (written into /job):
    artifacts/                 — extracted files, paths preserved
    summary.json               — structured finding list
    volatility/<plugin>.json   — present for memory dumps
    collect.log                — stdout/stderr trace
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from disk import process_disk
from memory import process_memory


def detect_kind(image: Path) -> str:
    """Return one of: qcow2, vmdk, vhd, vhdx, e01, raw_disk, memory."""
    out = subprocess.run(["file", "-b", str(image)], capture_output=True, text=True).stdout.lower()
    suffix = image.suffix.lower()
    if "qcow" in out:
        return "qcow2"
    if "vmware" in out or "vmdk" in out:
        return "vmdk"
    if "vhd" in out and "x" in out:
        return "vhdx"
    if "vhd" in out or suffix in (".vhd",):
        return "vhd"
    if "expert witness" in out or "ewf" in out or suffix in (".e01", ".ex01"):
        return "e01"
    if suffix in (".vhdx",):
        return "vhdx"
    # Try mmls — if succeeds, it's a disk image with a partition table
    rc = subprocess.run(
        ["mmls", str(image)], capture_output=True, text=True
    ).returncode
    if rc == 0:
        return "raw_disk"
    return "memory"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("image", help="Path to image inside container (typically /job/image.bin)")
    p.add_argument("--type", default="auto",
                   choices=["auto", "raw", "qcow2", "vmdk", "vhd", "vhdx", "e01", "memory"])
    p.add_argument("--os", dest="target_os", default="auto",
                   choices=["auto", "linux", "windows"])
    p.add_argument("--bulk-extractor", action="store_true",
                   help="Run bulk_extractor for unstructured carving (slow)")
    p.add_argument("--out", default="/job", help="Output dir (default /job)")
    args = p.parse_args()

    image = Path(args.image).resolve()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    log = (out / "collect.log").open("w")
    def L(msg):
        print(msg, file=sys.stderr); log.write(msg + "\n"); log.flush()

    if not image.is_file():
        L(f"image not found: {image}")
        return 2

    kind = args.type
    if kind == "auto":
        kind = detect_kind(image)
    L(f"detected kind: {kind}")

    summary = {"image": str(image), "kind": kind, "target_os": args.target_os}

    try:
        if kind == "memory":
            mem_summary = process_memory(image, out, args.target_os, log_fn=L)
            summary["memory"] = mem_summary
        else:
            disk_summary = process_disk(
                image, kind, out, args.target_os,
                bulk_extractor=args.bulk_extractor, log_fn=L,
            )
            summary["disk"] = disk_summary
    except Exception as e:
        import traceback
        L(f"ERROR: {e}\n{traceback.format_exc()}")
        summary["error"] = str(e)
        (out / "summary.json").write_text(json.dumps(summary, indent=2))
        return 1

    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    L("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
