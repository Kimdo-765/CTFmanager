#!/usr/bin/env python3
"""chal-libc-fix — make a CTF binary load the same libc/ld-linux it
will run against on the remote, by patchelf'ing its interpreter +
RUNPATH to a copy of the chal's own libraries.

Why: dynamic analysis on the worker container's system libc (Debian
glibc 2.41 at the time of writing) gives misleading offsets for any
challenge built against a different libc. Heap layout, FSOP vtable
addresses, one_gadget offsets, even basic struct sizes shift between
glibc versions. The remote service ships its own libc + ld.so via
Dockerfile / docker-compose / a `lib/` directory bundled with the
challenge — we want the debugger session to use those.

What it does:
  1. Locates the chal's libc.so.6 + ld-linux-* by walking the
     challenge bundle. Hints in priority order:
       - Dockerfile `COPY libc-X.YZ.so /...` lines
       - docker-compose.yml volume mounts of a libs/ dir
       - any `lib/` or `libs/` or `glibc/` directory containing both
         libc.so.6 (or libc-*.so) and ld-linux-*
       - any directory with libc.so.6 + ld-linux-* siblings
  2. Stages those libs under <jobdir>/work/.chal-libs/ if not already
     there. Worker has the source dir read-only via stage_bin step.
  3. patchelf's the binary in place:
       --set-interpreter <staged ld-linux>
       --set-rpath        <staged libs dir>     (replaces RUNPATH)
  4. Prints a summary: detected libc version, paths, gdb-ready cmd.

Idempotent: if the binary's interpreter already points at the staged
ld and the libs dir is on RUNPATH, it just reports the current state
and exits 0.

Usage (called by the debugger subagent from Bash):
    chal-libc-fix <binary>                   # auto-detect from cwd
    chal-libc-fix <binary> --libs <dir>      # explicit libs dir
    chal-libc-fix <binary> --keep-original   # backs up to <bin>.orig

Exit codes:
    0   success (or already patched)
    1   no libc/ld pair found anywhere
    2   patchelf failed
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


STAGE_DIRNAME = ".chal-libs"


def _run(cmd: list[str], check: bool = True) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        sys.stderr.write(f"[chal-libc-fix] cmd failed: {' '.join(cmd)}\n")
        sys.stderr.write(res.stderr)
        sys.exit(2)
    return res.stdout


def detect_libc_version(libc: Path) -> str | None:
    try:
        out = subprocess.run(
            ["strings", str(libc)], capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return None
    for line in out.splitlines():
        m = re.search(r"GNU C Library .*?(?:GLIBC|version)\s*([\d.]+)", line)
        if m:
            return m.group(1)
        m = re.match(r"GLIBC ([\d.]+)$", line.strip())
        if m:
            return m.group(1)
    return None


def find_pair(root: Path) -> tuple[Path, Path] | None:
    """Walk root looking for a directory that contains BOTH libc.so.6
    (or libc-*.so) AND a ld-linux-*.so.*. Return (libc, ld) on hit.
    Skips well-known noisy dirs.
    """
    skip = {".git", "__pycache__", "node_modules", ".chal-libs"}
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in skip]
        names = set(files)
        libc = None
        ld = None
        for n in files:
            if n == "libc.so.6" or re.fullmatch(r"libc-[\d.]+\.so", n):
                libc = Path(d) / n
            if re.match(r"ld-linux", n) or re.match(r"ld-[\d.]+\.so", n):
                ld = Path(d) / n
        if libc and ld:
            return libc, ld
    return None


def parse_dockerfile_from(root: Path) -> str | None:
    """Return the first non-`scratch` FROM image found in any Dockerfile
    under root (e.g. 'ubuntu:18.04', 'python:3.10-slim',
    'gcr.io/distroless/cc'). Used as a last-resort source when the
    chal bundle ships a Dockerfile but no physical libc + ld pair.
    """
    for d, _, files in os.walk(root):
        for n in files:
            if n.lower() != "dockerfile" and not n.lower().startswith("dockerfile."):
                continue
            try:
                txt = (Path(d) / n).read_text(errors="replace")
            except Exception:
                continue
            for m in re.finditer(
                r"^\s*FROM\s+(?:--\S+\s+)?(\S+)",
                txt, re.MULTILINE | re.IGNORECASE,
            ):
                img = m.group(1).strip()
                if img.lower() == "scratch":
                    continue
                # Skip lines whose target is a multi-stage alias
                # ("FROM build AS final" — `build` isn't a real image).
                # Heuristic: real image refs have a `:` (tag) or `/`
                # (registry/repo) or are in a small set of canonical
                # tagless names. Plain unqualified words like "build"
                # almost never are real image refs in CTF chals.
                if (":" in img) or ("/" in img):
                    return img
                if img.lower() in {
                    "alpine", "ubuntu", "debian", "fedora", "centos",
                    "python", "node", "golang", "rust", "openjdk",
                    "busybox", "archlinux",
                }:
                    return img
    return None


def binary_needed(binary: Path) -> list[str]:
    """DT_NEEDED entries (the .so SONAMES the binary directly links
    against). Order is preserved from readelf output.
    """
    try:
        out = subprocess.run(
            ["readelf", "-d", str(binary)],
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return []
    needed: list[str] = []
    for line in out.splitlines():
        m = re.search(r"\(NEEDED\)\s+Shared library:\s*\[([^\]]+)\]", line)
        if m:
            needed.append(m.group(1))
    return needed


def binary_interpreter(binary: Path) -> str | None:
    """PT_INTERP — the path the binary expects ld.so to live at."""
    try:
        out = subprocess.run(
            ["readelf", "-l", str(binary)],
            capture_output=True, text=True, check=False,
        ).stdout
    except Exception:
        return None
    m = re.search(r"\[Requesting program interpreter:\s*([^\]]+)\]", out)
    return m.group(1).strip() if m else None


# Strict shell-safety filters so a malicious SONAME / interp path can't
# break out of the docker run script we hand to the chal image.
_SAFE_LIB_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9./_+\-]+$")


def extract_from_image(image: str, binary: Path, stage_dir: Path) -> bool:
    """Pull the Dockerfile's FROM image and copy libc + ld + every
    DT_NEEDED .so the binary references INTO `stage_dir` (which is
    bind-mounted to the chal container as /out via the host docker
    socket). Returns True on success.

    Layout assumption: stage_dir lives under
    /data/jobs/<JOB_ID>/... so we can translate it to a host path via
    HOST_DATA_DIR for the bind mount.
    """
    host_root = os.environ.get("HOST_DATA_DIR", "").rstrip("/")
    job_id = os.environ.get("JOB_ID", "")
    if not host_root or not job_id:
        sys.stderr.write(
            "[chal-libc-fix] HOST_DATA_DIR / JOB_ID not set on worker — "
            "cannot bind-mount into chal container. Image extraction "
            "skipped.\n"
        )
        return False

    job_root = Path(f"/data/jobs/{job_id}")
    try:
        rel = stage_dir.resolve().relative_to(job_root.resolve())
    except ValueError:
        sys.stderr.write(
            f"[chal-libc-fix] stage_dir {stage_dir} not under "
            f"{job_root} — cannot translate to host path; image "
            "extraction skipped.\n"
        )
        return False
    host_stage = f"{host_root}/jobs/{job_id}/{rel}"
    stage_dir.mkdir(parents=True, exist_ok=True)

    needed = binary_needed(binary)
    if "libc.so.6" not in needed:
        # Always grab libc explicitly even if the binary's NEEDED list
        # somehow elides it (some odd toolchains).
        needed.append("libc.so.6")
    interp = binary_interpreter(binary) or "/lib64/ld-linux-x86-64.so.2"

    bad = [n for n in needed if not _SAFE_LIB_RE.match(n)]
    if bad:
        sys.stderr.write(
            f"[chal-libc-fix] suspicious lib names {bad}; aborting "
            "extraction.\n"
        )
        return False
    if not _SAFE_PATH_RE.match(interp):
        sys.stderr.write(
            f"[chal-libc-fix] suspicious interpreter path "
            f"{interp!r}; aborting extraction.\n"
        )
        return False

    # Multi-arch interpreter fallbacks. We try the binary's own
    # PT_INTERP first; if the chal image has it at a different path,
    # walk a small list of conventional locations.
    interp_candidates = [
        interp,
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/lib/ld-linux-armhf.so.3",
        "/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3",
        "/lib/ld-linux.so.2",
        "/lib/i386-linux-gnu/ld-linux.so.2",
    ]
    interp_csv = " ".join(interp_candidates)
    libs_csv = " ".join(needed)

    # Shell script that runs inside the chal image. Uses ldconfig to
    # resolve each SONAME → real path; falls back to a small list of
    # conventional multiarch dirs if ldconfig isn't present (e.g.
    # alpine/musl, distroless). `cp -L` follows symlinks so we get
    # the actual binary, named with its SONAME so DT_NEEDED resolves.
    script = (
        "set -e\n"
        "mkdir -p /out\n"
        "echo \"[image] /etc/os-release:\"\n"
        "head -3 /etc/os-release 2>/dev/null || true\n"
        f"for libname in {libs_csv}; do\n"
        "  p=$(ldconfig -p 2>/dev/null | awk -v lib=\"$libname\" '$1==lib {print $NF; exit}')\n"
        "  if [ -z \"$p\" ]; then\n"
        "    for d in /lib/x86_64-linux-gnu /lib64 /lib /usr/lib/x86_64-linux-gnu /usr/lib /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu /lib/arm-linux-gnueabihf /usr/lib/arm-linux-gnueabihf /lib/i386-linux-gnu /usr/lib/i386-linux-gnu; do\n"
        "      if [ -e \"$d/$libname\" ]; then p=\"$d/$libname\"; break; fi\n"
        "    done\n"
        "  fi\n"
        "  if [ -n \"$p\" ] && [ -e \"$p\" ]; then\n"
        "    cp -L \"$p\" \"/out/$libname\" 2>/dev/null || cp \"$p\" \"/out/$libname\"\n"
        "    echo \"[image] copied $libname  <-  $p\"\n"
        "  else\n"
        "    echo \"[image] WARN: $libname not found in image\" 1>&2\n"
        "  fi\n"
        "done\n"
        f"for ld in {interp_csv}; do\n"
        "  if [ -e \"$ld\" ]; then\n"
        "    bn=$(basename \"$ld\")\n"
        "    cp -L \"$ld\" \"/out/$bn\" 2>/dev/null || cp \"$ld\" \"/out/$bn\"\n"
        "    echo \"[image] copied interpreter $ld -> /out/$bn\"\n"
        "    break\n"
        "  fi\n"
        "done\n"
        "ls -la /out\n"
    )

    print(f"[chal-libc-fix] pulling image: {image}", flush=True)
    pull = subprocess.run(
        ["docker", "pull", image], capture_output=True, text=True,
    )
    if pull.returncode != 0:
        # The image might already be local; print the error and try
        # `docker run` anyway. If neither works we'll exit cleanly.
        sys.stderr.write(
            "[chal-libc-fix] docker pull failed (image may still be "
            f"locally cached — trying anyway): "
            f"{pull.stderr.strip()[:200]}\n"
        )

    print(
        f"[chal-libc-fix] extracting libc/ld/NEEDED libs from {image} "
        f"into {stage_dir} ...",
        flush=True,
    )
    res = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{host_stage}:/out",
            "--entrypoint", "sh",
            image,
            "-c", script,
        ],
        capture_output=True, text=True,
    )
    if res.stdout:
        sys.stdout.write(res.stdout)
    if res.stderr:
        sys.stderr.write(res.stderr)
    if res.returncode != 0:
        sys.stderr.write(
            f"[chal-libc-fix] docker run exited {res.returncode}; "
            "extraction failed.\n"
        )
        return False
    return True


def parse_dockerfile_libc(root: Path) -> tuple[Path, Path] | None:
    """Best-effort parse of any Dockerfile in `root` for a `COPY` line
    naming the libc the chal runs against. Returns the resolved
    (libc, ld) pair when both can be found relative to the Dockerfile,
    otherwise None.
    """
    candidates: list[Path] = []
    for d, _, files in os.walk(root):
        for n in files:
            if n.lower() in ("dockerfile",) or n.lower().startswith("dockerfile."):
                candidates.append(Path(d) / n)
    for df in candidates:
        try:
            txt = df.read_text(errors="replace")
        except Exception:
            continue
        # Heuristic: scan for `COPY <src> ...` of *.so / libc / ld file.
        copy_re = re.compile(r"^\s*COPY\s+(?:--\S+\s+)?(\S+)\s+(\S+)", re.MULTILINE)
        srcs = []
        for m in copy_re.finditer(txt):
            src = m.group(1)
            if any(tok in src for tok in ("libc", "ld-", "ld.so", "lib/", "libs/", "glibc")):
                srcs.append(src)
        if not srcs:
            continue
        # Resolve src paths relative to the Dockerfile directory.
        df_dir = df.parent
        for src in srcs:
            cand_dir = (df_dir / src).resolve()
            if cand_dir.is_dir():
                pair = find_pair(cand_dir)
                if pair:
                    return pair
            elif cand_dir.is_file() and "libc" in cand_dir.name:
                # Single libc file copied; look for ld-* next to it.
                ld_pair = None
                for sib in cand_dir.parent.iterdir():
                    if re.match(r"ld-linux|ld-[\d.]+\.so", sib.name):
                        ld_pair = sib
                        break
                if ld_pair:
                    return cand_dir, ld_pair
    return None


def stage_libs(libc: Path, ld: Path, jobdir: Path) -> tuple[Path, Path, Path]:
    """Copy libc + ld + every .so from libc's directory into a stable
    staging dir under <jobdir>/work/.chal-libs/. Returns
    (staged_libs_dir, staged_libc, staged_ld).
    """
    work = jobdir / "work"
    if not work.is_dir():
        work = jobdir
    stage = work / STAGE_DIRNAME
    stage.mkdir(parents=True, exist_ok=True)
    # Copy every .so* sibling of libc — common in Dreamhack style
    # bundles where libpthread, libdl, libm etc all need to come along.
    src_dir = libc.parent
    for sib in src_dir.iterdir():
        if sib.is_file() and (sib.suffix == ".so"
                              or ".so." in sib.name
                              or sib.name.startswith(("libc", "ld-"))):
            dst = stage / sib.name
            if not dst.exists() or dst.stat().st_size != sib.stat().st_size:
                shutil.copy2(sib, dst)
    # ld can live in a different dir (sometimes /lib64/) — copy explicitly.
    if not (stage / ld.name).exists():
        shutil.copy2(ld, stage / ld.name)
    return stage, stage / libc.name, stage / ld.name


def already_patched(binary: Path, staged_ld: Path, stage_dir: Path) -> bool:
    interp = _run(["patchelf", "--print-interpreter", str(binary)], check=False).strip()
    rpath = _run(["patchelf", "--print-rpath", str(binary)], check=False).strip()
    return interp == str(staged_ld) and str(stage_dir) in rpath


def patch_binary(binary: Path, staged_ld: Path, stage_dir: Path) -> None:
    _run(["patchelf", "--set-interpreter", str(staged_ld), str(binary)])
    _run(["patchelf", "--set-rpath", str(stage_dir), str(binary)])


def main() -> int:
    ap = argparse.ArgumentParser(prog="chal-libc-fix")
    ap.add_argument("binary")
    ap.add_argument("--libs", help="Explicit directory containing libc + ld")
    ap.add_argument(
        "--root",
        help="Where to search for the chal's bundled libs (default: cwd)",
    )
    ap.add_argument(
        "--keep-original", action="store_true",
        help="Backup the binary to <binary>.orig before patching",
    )
    ap.add_argument(
        "--no-image", action="store_true",
        help="Skip the Dockerfile FROM image extraction fallback "
             "(when no physical libs are bundled in the chal). Use "
             "this if you want to fail fast instead of pulling images.",
    )
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        sys.stderr.write(f"binary not found: {binary}\n")
        return 1

    job_id = os.environ.get("JOB_ID", "")
    if job_id:
        jobdir = Path(f"/data/jobs/{job_id}")
    else:
        jobdir = Path.cwd()
    search_root = Path(args.root).resolve() if args.root else jobdir

    # Compute the stage dir up front — image-extraction path drops files
    # directly into it, then the stage_libs step at the bottom is a no-op
    # when we detect that.
    work = jobdir / "work"
    if not work.is_dir():
        work = jobdir
    stage_target = work / STAGE_DIRNAME

    if args.libs:
        libs_dir = Path(args.libs).resolve()
        pair = find_pair(libs_dir) or None
        if not pair:
            sys.stderr.write(
                f"--libs {libs_dir} did not contain libc.so.6 + ld-linux-*; "
                "nothing to patch.\n"
            )
            return 1
        libc, ld = pair
    else:
        # Priority 1: Dockerfile COPY → physical libs in bundle.
        pair = parse_dockerfile_libc(search_root)
        # Priority 2: any libc+ld pair anywhere under search root.
        if not pair:
            pair = find_pair(search_root)
        # Priority 3 (NEW): pull the Dockerfile's FROM image and copy
        # libc/ld + the binary's NEEDED libs out of it. This is the
        # common Dreamhack / HackTheBox case: bundle = Dockerfile +
        # binary, libs only exist inside the base image.
        if not pair and not args.no_image:
            base_image = parse_dockerfile_from(search_root)
            if base_image:
                print(
                    f"[chal-libc-fix] no physical libs bundled — falling "
                    f"back to base-image extraction (FROM {base_image})",
                    flush=True,
                )
                if extract_from_image(base_image, binary, stage_target):
                    pair = find_pair(stage_target)
                    if not pair:
                        sys.stderr.write(
                            "[chal-libc-fix] image extraction completed "
                            "but no libc.so.6 + ld-linux pair found in "
                            f"{stage_target}. Likely a musl/distroless "
                            "base; not patching.\n"
                        )
                        return 1
        if not pair:
            sys.stderr.write(
                f"[chal-libc-fix] no libc.so.6 + ld-linux pair found "
                f"under {search_root} and no base image to fall back "
                "on. Binary will run against the worker's system libc "
                "— heap/FSOP offsets may be wrong. Pass --libs <dir> "
                "if the chal supplies a libc somewhere unconventional.\n"
            )
            return 1
        libc, ld = pair

    version = detect_libc_version(libc)
    print(f"[chal-libc-fix] detected libc: {libc}", flush=True)
    print(f"[chal-libc-fix] detected ld:   {ld}", flush=True)
    if version:
        print(f"[chal-libc-fix] glibc version: {version}", flush=True)

    # If image extraction already populated stage_target, skip the
    # stage_libs copy step (libs are already in the right place).
    if libc.parent.resolve() == stage_target.resolve():
        stage = stage_target
        staged_libc, staged_ld = libc, ld
        print(f"[chal-libc-fix] using pre-staged libs at: {stage}", flush=True)
    else:
        stage, staged_libc, staged_ld = stage_libs(libc, ld, jobdir)
        print(f"[chal-libc-fix] staged at: {stage}", flush=True)

    if already_patched(binary, staged_ld, stage):
        print(f"[chal-libc-fix] {binary} already patched; nothing to do", flush=True)
    else:
        if args.keep_original:
            backup = binary.with_suffix(binary.suffix + ".orig")
            if not backup.exists():
                shutil.copy2(binary, backup)
                print(f"[chal-libc-fix] backed up to {backup}", flush=True)
        patch_binary(binary, staged_ld, stage)
        print(
            f"[chal-libc-fix] patched: interpreter -> {staged_ld}, "
            f"rpath -> {stage}",
            flush=True,
        )

    # The patched binary's DT_RUNPATH points at `stage`, so plain
    # invocation just works — no LD_LIBRARY_PATH needed (and exporting
    # it would also redirect /bin/sh, which gdb spawns internally,
    # breaking the session).
    print("[chal-libc-fix] gdb-ready (no env tweaks needed):", flush=True)
    print(f"  gdb {binary}", flush=True)
    print(f"  ./{binary.name}     # runs against staged libc directly", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
