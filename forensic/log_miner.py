"""Log-mining pass for forensic captures.

After collect.py extracts log/history artifacts (auth.log, syslog, bash_history,
HTTP access logs, …), this module scans every text artifact line-by-line and
extracts:

    * passwords        — credentials leaked in URL params, CLI args, or
                         "Failed password for <user>" lines whose user field
                         is itself a typed-in password.
    * sqli_attempts    — classic injection signatures (UNION SELECT,
                         ' OR 1=1, sleep(), information_schema, …).
    * xss_attempts     — <script>, javascript:, on{event}=, …
    * lfi_attempts     — ../, /etc/passwd, php://filter, …
    * rce_attempts     — `;cat`, `|nc`, `$(…)`, `\`…\``, system(), …
    * auth_events      — sshd Accepted/Failed/Invalid-user lines.
    * flag_candidates  — anything matching the project's FLAG_RE.

Lines are URL-decoded once before matching so payloads obfuscated as
`%27%20OR%201%3D1` still trigger.

Output: log_findings.json next to summary.json. Each section caps at 200
entries to keep the file sane on noisy production logs.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import unquote, unquote_plus


# ---------- file-selection heuristics ----------

# Filenames or path fragments that almost always contain mineable text.
_LOG_NAME_HINTS = (
    "auth.log", "syslog", "messages", "secure",
    "kern.log", "dmesg", "audit.log",
    "access.log", "access_log", "error.log", "error_log",
    "access.", "error.",  # rotated apache/nginx (access.1, error.1.gz)
    "history", ".bash_history", ".zsh_history",
    ".sh_history", ".mysql_history", ".psql_history",
    "consolehost_history",
    "wtmp", "btmp", "lastlog",  # binary, but we still try text mode
)

# Don't waste cycles on these — keep miner I/O bounded.
_MAX_FILE_BYTES = 16 * 1024 * 1024     # 16 MiB per file
_MAX_LINE_BYTES = 8192                  # truncate stupendously long lines
_MAX_FINDINGS_PER_KIND = 200


def _looks_minable(p: Path) -> bool:
    name_low = p.name.lower()
    if any(h in name_low for h in _LOG_NAME_HINTS):
        return True
    # Also pick up files under any */log/* directory regardless of name.
    parts = [s.lower() for s in p.parts]
    if any(s in ("log", "logs", "var") for s in parts):
        return True
    return False


def _iter_lines(path: Path) -> Iterable[tuple[int, str]]:
    """Yield (line_no, decoded_line). Reads up to _MAX_FILE_BYTES, decodes
    latin-1 for binary safety, and URL-decodes once so encoded payloads
    are matchable. Skips files that are larger than the limit OR that
    look like compressed blobs the user did not gunzip."""
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size == 0 or size > _MAX_FILE_BYTES:
        return
    # gzip detection: first two bytes 1f 8b. Skip — we don't gunzip here
    # to keep the miner free of extra deps; collect.py can be extended
    # later to gunzip rotated logs before mining.
    try:
        with path.open("rb") as fp:
            head = fp.read(2)
            if head == b"\x1f\x8b":
                return
            fp.seek(0)
            for i, raw in enumerate(fp, start=1):
                if len(raw) > _MAX_LINE_BYTES:
                    raw = raw[:_MAX_LINE_BYTES]
                line = raw.decode("latin-1", errors="replace").rstrip("\r\n")
                if not line.strip():
                    continue
                # Two-pass decode so doubly-encoded payloads still register.
                decoded = unquote_plus(unquote(line))
                yield i, decoded if decoded != line else line
    except OSError:
        return


# ---------- pattern catalogue ----------

# Each entry: (kind, compiled_regex, capture_group_for_payload_or_None)
_PASSWORD_PATTERNS = [
    # URL / form params
    re.compile(
        r"[?&#](password|passwd|pwd|pass|secret|token|api[_-]?key|auth[_-]?token|"
        r"session|sid|access[_-]?token|client[_-]?secret|jwt)=([^\s&'\"<>]{1,256})",
        re.IGNORECASE,
    ),
    # mysql/psql -p<password> (no space — actual password right after -p)
    re.compile(r"\b(mysql|mariadb|psql)\s+[^\n]*?-p([^\s]{1,128})", re.IGNORECASE),
    # curl -u user:pass / wget --user=...--password=...
    re.compile(r"\b(curl|wget|http(?:ie)?)[^\n]*?-u\s+([^\s]+:[^\s]+)", re.IGNORECASE),
    re.compile(r"--password[= ]([^\s]{1,128})", re.IGNORECASE),
    # Authorization Basic <base64> — record the b64 token, user can decode
    re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,256})", re.IGNORECASE),
    # JSON-style  "password":"value"
    re.compile(
        r'"(password|passwd|pwd|secret|token|api_key|auth_token)"\s*:\s*"([^"]{1,256})"',
        re.IGNORECASE,
    ),
]

# SQL injection signatures. Matching one is suspicious; matching two on
# the same line is "almost certainly injection".
_SQLI_PATTERNS = [
    re.compile(r"(?i)\bunion\s+(all\s+)?select\b"),
    re.compile(r"(?i)('|\")\s*or\s+\d+\s*=\s*\d+"),
    re.compile(r"(?i)('|\")\s*or\s+('|\")?[^\s'\")]+('|\")?\s*=\s*('|\")?[^\s'\")]+"),
    re.compile(r"(?i)\bsleep\s*\(\s*\d+(\.\d+)?\s*\)"),
    re.compile(r"(?i)\bbenchmark\s*\(\s*\d+\s*,"),
    re.compile(r"(?i)\binformation_schema\."),
    re.compile(r"(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b"),
    re.compile(r"(?i)/\*!\d+"),
    re.compile(r"(?i)\bextractvalue\s*\(|\bupdatexml\s*\("),
    re.compile(r"(?i)\bconcat(_ws)?\s*\("),
    re.compile(r"(?i)\bgroup_concat\s*\("),
    re.compile(r"(?i)\bsubstring(_index)?\s*\("),
    re.compile(r"--\s*$"),
    re.compile(r"(?i)\bxp_cmdshell\b"),
    re.compile(r"(?i)\bwaitfor\s+delay\b"),
    re.compile(r"(?i)';\s*(drop|insert|update|delete)\b"),
]

_XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script[\s>]"),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)\bon(error|load|click|mouseover|focus|submit)\s*="),
    re.compile(r"(?i)<\s*svg[^>]*on\w+\s*="),
    re.compile(r"(?i)<\s*img[^>]*on(error|load)\s*="),
    re.compile(r"(?i)\beval\s*\("),
    re.compile(r"(?i)\bdocument\.cookie\b"),
    re.compile(r"(?i)alert\s*\("),
]

_LFI_PATTERNS = [
    re.compile(r"(?:\.\./){2,}"),
    re.compile(r"(?i)/etc/passwd"),
    re.compile(r"(?i)/etc/shadow"),
    re.compile(r"(?i)/proc/self/(environ|status|cmdline)"),
    re.compile(r"(?i)\bphp://(filter|input|expect)"),
    re.compile(r"(?i)\bdata:[^,]*base64,"),
    re.compile(r"(?i)\bfile://"),
    re.compile(r"(?i)\bzip://"),
]

_RCE_PATTERNS = [
    re.compile(r"[;|&]\s*(cat|wget|curl|ls|id|whoami|uname|nc|bash|sh|python|perl)\b"),
    re.compile(r"\$\([^)]{1,200}\)"),
    re.compile(r"`[^`\n]{1,200}`"),
    re.compile(r"(?i)\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\(|\bshell_exec\s*\("),
    re.compile(r"(?i)\b(?:nc|netcat|ncat)\s+\S+\s+\d+"),
    re.compile(r"(?i)\bbash\s+-i\b"),
]

_AUTH_PATTERNS = [
    # sshd
    re.compile(r"sshd\[\d+\]:\s+(Accepted|Failed)\s+password\s+for(?:\s+invalid\s+user)?\s+(\S+)\s+from\s+(\S+)"),
    re.compile(r"sshd\[\d+\]:\s+Invalid\s+user\s+(\S+)\s+from\s+(\S+)"),
    re.compile(r"sshd\[\d+\]:\s+Accepted\s+publickey\s+for\s+(\S+)\s+from\s+(\S+)"),
    # sudo
    re.compile(r"sudo:\s+(\S+)\s+:\s+(\S+)\s+;\s+TTY="),
    re.compile(r"sudo:\s+pam_unix\(sudo:auth\):\s+authentication\s+failure"),
    # generic linux PAM
    re.compile(r"pam_unix\([^)]+\):\s+(authentication\s+failure|session\s+(opened|closed))"),
]

# Project-wide flag pattern (kept in sync with modules/_common.py FLAG_RE).
_FLAG_RE = re.compile(
    r"(?:FLAG|flag|CTF|ctf|HTB|htb|picoCTF|pico|DH|dreamhack|HACKTHEBOX|"
    r"BSidesCP|XCTF|KCTF|TWN|hcamp|hackcamp|samsung|N0PSctf|CCE)\{[^\s}]{1,200}\}",
    re.IGNORECASE,
)


def _trim(s: str, n: int = 280) -> str:
    s = s.strip()
    return s if len(s) <= n else s[:n] + "…"


def _record(bucket: list, file_rel: str, lineno: int, line: str, **extra) -> None:
    if len(bucket) >= _MAX_FINDINGS_PER_KIND:
        return
    bucket.append({
        "file": file_rel,
        "line_no": lineno,
        "context": _trim(line),
        **extra,
    })


def _scan_one_file(path: Path, root: Path, findings: dict) -> None:
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)
    for lineno, line in _iter_lines(path):
        # Passwords
        for pat in _PASSWORD_PATTERNS:
            for m in pat.finditer(line):
                groups = m.groups()
                # Last non-None capture group is the credential payload.
                cred = next((g for g in reversed(groups) if g), None)
                key = groups[0] if groups and groups[0] else "credential"
                _record(
                    findings["passwords"], rel, lineno, line,
                    key=str(key), value=_trim(cred or "", 128),
                )

        # SQL injection
        for pat in _SQLI_PATTERNS:
            m = pat.search(line)
            if m:
                _record(
                    findings["sqli_attempts"], rel, lineno, line,
                    signature=m.group(0)[:64],
                )
                break  # one signature per line is enough

        # XSS
        for pat in _XSS_PATTERNS:
            m = pat.search(line)
            if m:
                _record(
                    findings["xss_attempts"], rel, lineno, line,
                    signature=m.group(0)[:64],
                )
                break

        # LFI
        for pat in _LFI_PATTERNS:
            m = pat.search(line)
            if m:
                _record(
                    findings["lfi_attempts"], rel, lineno, line,
                    signature=m.group(0)[:64],
                )
                break

        # RCE
        for pat in _RCE_PATTERNS:
            m = pat.search(line)
            if m:
                _record(
                    findings["rce_attempts"], rel, lineno, line,
                    signature=m.group(0)[:64],
                )
                break

        # Auth events
        for pat in _AUTH_PATTERNS:
            m = pat.search(line)
            if m:
                _record(findings["auth_events"], rel, lineno, line)
                break

        # Flags
        for m in _FLAG_RE.finditer(line):
            _record(
                findings["flag_candidates"], rel, lineno, line,
                flag=m.group(0),
            )


def scan_logs(
    roots: list[Path],
    out_file: Path,
    log_fn: Callable[[str], None] | None = None,
) -> dict:
    """Walk each root, mine every log-shaped file underneath, and write a
    consolidated `log_findings.json` to `out_file`. Returns the same dict.
    """
    L = log_fn or (lambda _msg: None)

    findings = {
        "passwords": [],
        "sqli_attempts": [],
        "xss_attempts": [],
        "lfi_attempts": [],
        "rce_attempts": [],
        "auth_events": [],
        "flag_candidates": [],
        "scanned_files": 0,
    }

    seen: set[Path] = set()
    for root in roots:
        if not root or not Path(root).exists():
            continue
        root = Path(root)
        for p in sorted(root.rglob("*")):
            if not p.is_file() or p in seen:
                continue
            seen.add(p)
            if not _looks_minable(p):
                continue
            try:
                _scan_one_file(p, root, findings)
                findings["scanned_files"] += 1
            except Exception as e:
                L(f"log_miner: skipped {p} ({e})")

    # Convenience flat stats so the orchestrator / Claude prompt can quote
    # them without re-counting.
    findings["counts"] = {
        k: len(v) if isinstance(v, list) else v
        for k, v in findings.items()
        if k != "counts"
    }

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(findings, indent=2, default=str))
    L(
        f"log_miner: scanned {findings['scanned_files']} files, "
        f"passwords={len(findings['passwords'])}, "
        f"sqli={len(findings['sqli_attempts'])}, "
        f"auth={len(findings['auth_events'])}, "
        f"flags={len(findings['flag_candidates'])}"
    )
    return findings
