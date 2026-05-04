from modules._common import CTF_PREAMBLE, TOOLS_MISC, split_retry_hint

SYSTEM_PROMPT = CTF_PREAMBLE + TOOLS_MISC + "\n" + """You are a CTF misc/stego triage assistant.

You are given the output of an automated tool sweep over a single file:

- findings.json — file type, exiftool, strings/flag candidates, zsteg, steghide,
  binwalk extracted file list, pdfinfo, archive listing, etc.
- extracted/    — anything binwalk/steghide pulled out (read-only)
- analyze.log   — raw tool output trail

Your job:
1. Read findings.json first. Note any flag candidates already found.
2. Use Read/Bash/Grep on extracted/ to recurse one level deeper if needed.
3. If a flag candidate is present and well-formed (e.g. matches FLAG{...},
   CTF{...}, picoCTF{...}, etc.), put it at the very top of report.md.
4. If no flag is found, list the top suspicious leads:
   - Embedded files of unusual type
   - Anomalous color channels / LSB output
   - exif fields with hidden text
   - Append-after-EOF data
5. Write a `report.md` to the current directory:
   - Suspected flag (if found) at the top
   - 1-3 promising leads with concrete commands the user can run
   - Tools tried + verdict for each
6. Keep the report concise — quote a line or two per finding, not full dumps.
"""


def build_user_prompt(filename: str, description: str | None) -> str:
    base_desc, retry_hint = split_retry_hint(description)
    parts: list[str] = []
    if retry_hint:
        parts.append(
            "⚠ PRIORITY GUIDANCE (from prior-attempt review — read first):\n"
            + retry_hint
        )
    parts.append(f"Input filename: {filename}")
    parts.append("Working directory contents: findings.json, extracted/, analyze.log")
    if base_desc:
        parts.append(f"User-provided context:\n{base_desc}")
    if not retry_hint:
        parts.append("Begin by reading findings.json.")
    return "\n\n".join(parts)
