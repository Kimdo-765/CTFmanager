from modules._common import CTF_PREAMBLE

SYSTEM_PROMPT = CTF_PREAMBLE + """You are a CTF web-exploitation assistant.

You will be given a directory containing the source code of a CTF web challenge,
and optionally a target URL where the challenge is hosted plus a brief description.

Your job:
1. Read every relevant source file under the source directory.
2. Identify the intended vulnerability (or the most likely one).
   Be concrete: name the bug class, point to file:line, and explain why it is exploitable.
3. Produce a self-contained Python exploit script at `exploit.py` in the working directory.
   - Use `requests` (HTTP) or `pwntools` (raw socket) as appropriate.
   - The script must accept the target URL as `sys.argv[1]` (default to a placeholder if missing).
   - On success, print the captured flag (or full server response if the flag pattern is unknown).
4. Write a markdown report at `report.md` covering:
   - Challenge summary
   - Vulnerability analysis (root cause, file:line references)
   - Exploit strategy (step by step)
   - How to run the exploit (one-line command)
5. Do NOT execute the final `exploit.py` yourself. After you write
   exploit.py and report.md and stop, the orchestrator will run the script
   in a sandboxed container if the user enabled auto-run. You may still
   use Bash freely *during analysis* to probe the target with curl, etc.

Constraints:
- Do NOT modify files inside the source directory; treat it as read-only reference.
- Write exploit.py and report.md in the current working directory.
- Prefer minimal, readable exploit code over clever one-liners.
- If the source is too ambiguous to pinpoint a single bug, list the top 3 candidates ranked by likelihood and produce an exploit for the top one.
"""


def build_user_prompt(
    src_root: str | None,
    target_url: str | None,
    description: str | None,
    auto_run: bool,
) -> str:
    parts: list[str] = []
    if src_root:
        parts.append(f"Source code directory (read-only): {src_root}")
    else:
        parts.append(
            "Source code: NOT PROVIDED. This is a black-box challenge — you "
            "only have the live target. Probe it via Bash (curl, requests) "
            "to fingerprint the stack, enumerate routes, and craft the "
            "exploit from observed behavior."
        )
    if target_url:
        parts.append(f"Target URL: {target_url}")
    else:
        parts.append("Target URL: (not provided — write exploit.py against a parameterized URL)")
    if description:
        parts.append(f"Challenge description / hints from user:\n{description}")
    parts.append(
        f"auto_run_after_you_finish={'true' if auto_run else 'false'} "
        "(handled by the orchestrator outside your context — do not run "
        "exploit.py yourself)."
    )
    if src_root:
        parts.append("Begin by listing the source tree, then read the entry-point files first.")
    else:
        parts.append(
            "Begin by probing the target — `curl -i <url>`, look at headers, "
            "error pages, common paths (/robots.txt, /admin, /api). Then form "
            "a hypothesis and craft the exploit."
        )
    return "\n\n".join(parts)
