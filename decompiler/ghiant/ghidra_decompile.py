#!/usr/bin/env python3
"""Run Ghidra in headless mode to decompile every function in a binary,
then bundle the .c files into a zip archive."""

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="Headless Ghidra decompile -> zip of per-function .c files"
    )
    p.add_argument("ghidra_path", help="Ghidra install root (contains support/analyzeHeadless)")
    p.add_argument("binary", help="Binary to analyze")
    p.add_argument(
        "-o", "--output",
        help="Output zip path (default: <binary>_decompiled.zip next to the binary)",
    )
    p.add_argument(
        "--keep-project", action="store_true",
        help="Preserve the Ghidra project directory next to the binary",
    )
    return p.parse_args()


def find_headless(ghidra_root: Path) -> Path:
    candidate = ghidra_root / "support" / "analyzeHeadless"
    if candidate.is_file():
        return candidate
    sys.exit("analyzeHeadless not found at {}".format(candidate))


def run_headless(headless: Path, project_dir: Path, binary: Path,
                 script_dir: Path, script_name: str, decomp_dir: Path,
                 keep_project: bool) -> None:
    cmd = [
        str(headless),
        str(project_dir),
        "decomp_proj",
        "-import", str(binary),
        "-scriptPath", str(script_dir),
        "-postScript", script_name, str(decomp_dir),
    ]
    if not keep_project:
        cmd.append("-deleteProject")

    print("[*] running:", " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        sys.exit("Ghidra headless failed (exit {})".format(rc))


def make_zip(src_dir: Path, zip_path: Path) -> int:
    files = sorted(src_dir.glob("*.c"))
    if not files:
        sys.exit("no decompiled .c files were produced")
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, arcname=f.name)
    return len(files)


def main():
    args = parse_args()

    ghidra_root = Path(args.ghidra_path).expanduser().resolve()
    binary = Path(args.binary).expanduser().resolve()
    if not binary.is_file():
        sys.exit("binary not found: {}".format(binary))

    headless = find_headless(ghidra_root)

    output_zip = (
        Path(args.output).expanduser().resolve()
        if args.output
        else binary.with_name(binary.name + "_decompiled.zip")
    )

    script_dir = Path(__file__).resolve().parent
    export_script = script_dir / "ExportDecompiled.py"
    if not export_script.is_file():
        sys.exit("missing companion script: {}".format(export_script))

    with tempfile.TemporaryDirectory(prefix="ghidra_decomp_") as tmp:
        tmp_path = Path(tmp)
        project_dir = tmp_path / "project"
        decomp_dir = tmp_path / "decompiled"
        project_dir.mkdir()
        decomp_dir.mkdir()

        run_headless(
            headless, project_dir, binary,
            script_dir, export_script.name, decomp_dir,
            args.keep_project,
        )

        if args.keep_project:
            saved = binary.parent / (binary.name + "_ghidra_project")
            if saved.exists():
                shutil.rmtree(saved)
            shutil.copytree(project_dir, saved)
            print("[*] project preserved at {}".format(saved))

        count = make_zip(decomp_dir, output_zip)

    print("[+] {} functions -> {}".format(count, output_zip))


if __name__ == "__main__":
    main()
