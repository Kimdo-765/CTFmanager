# HexTech_CTF_TOOL

Docker-based web UI toolset for CTF problem solving. Six modules covering Web, Pwn,
Forensic, Misc, Crypto, and Reversing — each combines automated tooling with a
Claude Code agent that reads the challenge, identifies the vulnerability or
flag, and generates a runnable exploit/solver script.

Three Claude-driven roles split by responsibility:

- **reviewer** — Opus 4.7, no tools. Lives in the api container. Reads
  the prior job's `run.log` / exploit / stdout-stderr / source on
  `/retry` and `/resume` and writes ONE 1500-char paragraph hint that
  is hoisted to the next agent's prompt as `⚠ PRIORITY GUIDANCE`.
- **main worker** — RQ process in the worker container. Drives the
  module pipeline and runs the main Claude agent (writer) that
  produces `exploit.py` / `solver.py` / `report.md`.
- **sub worker** — read-only `recon` subagent (in-process under main)
  + transient sibling sandbox containers (decompiler / forensic /
  misc / runner / sage) spawned per job and removed when done.

See [Architecture](#architecture) and [Agent architecture](#agent-architecture).

Failed jobs (or finished-without-flag) can be **retried** with an automatic
reviewer-written hint, a hand-written hint, or stop-and-resume mid-run —
all four paths fork the prior Claude SDK conversation and carry over the
working directory. See [Retry / Resume](#retry--resume).

## Modules

| Module | Pipeline | Output |
|---|---|---|
| **Web** | Claude reads source zip → identifies vuln → writes `exploit.py` (requests/pwntools) | exploit.py + report.md |
| **Pwn** | ghiant (Ghidra headless) decompile → Claude analysis → `exploit.py` (pwntools) | exploit.py + report.md |
| **Forensic** | sleuthkit + qemu-img + Volatility 3 artifact sweep → optional Claude summary | summary.json + artifacts/ + report.md |
| **Misc** | binwalk + foremost + exiftool + steghide + zsteg + pngcheck + qpdf → Claude triage | findings.json + extracted/ + report.md |
| **Crypto** | Claude analyzes source → writes `solver.py` using gmpy2/sympy/z3/pycryptodome (or `solver.sage` with optional SageMath sandbox) | solver.py + report.md |
| **Reversing** | ghiant decompile → Claude reverses logic → `solver.py` | solver.py + report.md |

For Web/Pwn/Crypto/Rev, an optional `auto_run` checkbox executes the produced
script in a sandboxed `runner` container (network-isolated unless a remote
target is given).

## Architecture

Four Claude-driven roles, each with its own context window:

| Role | Where it runs | Tools | Purpose |
|---|---|---|---|
| **reviewer** | `api` container, inline in `/retry` & `/resume` handlers | none (diagnostic only) | Reads the failed prior job and writes a 1-paragraph hint, streamed to the browser |
| **main worker** | `worker` container, one RQ process per concurrency slot | `Read` `Write` `Edit` `Bash` `Glob` `Grep` `Agent` | Runs the module pipeline; writes `exploit.py` / `solver.py` / `report.md` |
| **sub worker** | in-process under main (recon) **or** sibling docker container (sandbox) | recon: `Read` `Bash` `Glob` `Grep` (read-only) · sandboxes: shell | Heavy investigation + isolated tool execution |
| **judge** | `worker` container, around every `auto_run` execution | none (3 short turns, latest model) | Pre-flight script review · stall watchdog · post-mortem verdict for the runner sandbox |

```
   browser :8000
        │  HTTP + SSE
        ▼
   ┌─── api  (FastAPI) ────┐         ┌────── redis ──────┐
   │  uploads · /retry     │ ◄─────► │  RQ queue +       │
   │  /resume · /timeout   │         │  worker liveness  │
   │  /api/collector       │         └───────────────────┘
   │                       │
   │  ┌── reviewer ──┐     │   inline · no tools · SSE stream
   │  │  Opus 4.7    │     │
   │  └──────────────┘     │
   └──────────┬────────────┘
              │ RQ
              ▼
   ┌──── main worker  (N RQ procs) ────┐
   │  main Claude agent → deliverables │
   │  + heartbeat + token/cost meter   │
   └──────┬───────────────────┬────────┘
          │ Task("recon")     │ docker.sock
          ▼                   ▼
   ┌── recon subagent ──┐  ┌── sibling sandboxes ──────┐
   │  in-process,       │  │  decompiler · forensic ·  │
   │  read-only,        │  │  misc · runner · sage     │
   │  ≤2 KB summary     │  │  (per-job, removed)       │
   └────────────────────┘  └───────────────────────────┘
```

### reviewer (`api/routes/retry.py`)

- Triggered by `/retry/stream` and `/resume/stream` when no manual hint is supplied.
- `_gather_context()` bundles the prior job's `meta.json`, `run.log`, `report.md`, `exploit.py` / `solver.py`, std{out,err}, `callbacks.jsonl`, and 2–3 entry-point source files.
- Replies with ONE ≤1500-char paragraph diagnosing the failure. Streams to the browser over SSE, then is hoisted into the next job's prompt as `⚠ PRIORITY GUIDANCE`.
- Auth / rate / credit / policy errors surface in the panel and **block** the new job from being enqueued.

### main worker (`worker/runner.py`)

- Forks `WORKER_CONCURRENCY` (default 3) independent RQ processes named `htct-w0..N`. On boot, sweeps stale `rq:worker:htct-w*` keys from a SIGKILL'd previous life, then registers afresh.
- Each process picks a job from redis, runs the module pipeline, and drives the **main Claude agent** (writer) which produces deliverables in `/data/jobs/<id>/work/`.
- Liveness signals consumed by the browser:
  - `agent_heartbeat()` → `meta.last_agent_event_at` per SDK message (5 s throttle).
  - RQ worker key `rq:worker:<name>` (~10 s heartbeat).
  - Token + cost meter — `result.usage` summed across every turn.
  - Soft-timeout watchdog → `meta.awaiting_decision` banner.

### sub worker — two flavors, both transient to the job

- **recon subagent** — in-process under main. Same model, **separate context window**. Read-only (`Read` / `Bash` / `Glob` / `Grep`); cannot `Write` or `Edit`. Returns a ≤2 KB compact summary so heavy disasm / source greps / ghiant decompilation never pollute main's history. See [Agent architecture](#agent-architecture).
- **sibling sandboxes** — `decompiler` (Ghidra), `forensic` (TSK + qemu-img + Vol3), `misc` (binwalk + steghide + …), `runner` (exec exploit.py / solver.py), `sage` (optional Coppersmith / LLL). Built once via `--profile tools`, never started by `compose up`. The worker `docker run`s them per job and removes them when done.

### judge (`modules/_judge.py`)

Quality-gate agent around every `auto_run` exploit/solver execution.
Pinned to `LATEST_JUDGE_MODEL` (currently `claude-opus-4-7` — shared
with the retry reviewer). Judge is a peer to recon: same read-only
tool set (`Read` / `Bash` / `Glob` / `Grep`) plus `Agent` so it can
delegate heavy investigation to recon. **No `Write` / `Edit`** —
judge cannot patch the script.

**main ↔ judge ↔ sub** triangle:

```
            ┌──────────────── main (writer) ────────────────┐
            │  Read · Write · Edit · Bash · Glob · Grep ·   │
            │  Agent(subagent_type="recon" | "judge")       │
            └────────┬───────────────────────────┬──────────┘
                     │                           │
       Agent("recon", ...)                Agent("judge", ...)
                     │                           │
                     ▼                           ▼
            ┌── recon ──────────┐       ┌── judge ──────────────┐
            │  read-only        │       │  read-only + Agent    │
            │  ≤2 KB summary    │       │  pinned to latest     │
            └───────────────────┘       │  model                │
                     ▲                  └────────┬──────────────┘
                     │                           │
                     │       Agent("recon", ...) │
                     └───────────────────────────┘
```

Three orchestrator-driven stages, **all sharing one Claude session**
(prejudge captures `session_id`; supervise + postjudge resume via
`fork_session=False` — judge's verdict in post can reference what it
flagged in pre):

- **prejudge** — runs **before** the runner container starts. Judge
  Reads the script directly, may run a quick `python3 -m py_compile`
  via Bash, optionally delegates to recon for binary-protocol
  verification. Returns `{ok, severity, issues}`. `severity=high`
  aborts the run before spawning the container; the failure is
  recorded as `judge_aborted: true` with the issue list.
- **supervise** — runs **once** if the container has emitted no new
  stdout/stderr for **60 s** while still alive. Same session, fast
  path (no recon delegation): `{action: kill|continue, reason}`.
  Single-shot per run so a legitimate slow operation never racks up
  repeat judge calls.
- **postjudge** — runs **after** the container exits (either naturally
  or by supervise-kill). Categorizes the result as one of `success` /
  `partial` / `hung` / `parse_error` / `network_error` / `crash` /
  `timeout` / `unknown`, and produces a `retry_hint` paragraph the
  existing /retry flow can pick up directly.

Main can also invoke judge **proactively** mid-write via the standard
`Agent` tool:
```python
Agent(
    description="prejudge exploit",
    subagent_type="judge",
    prompt="review ./exploit.py for hang/parse risks; list specific
            line numbers + the fix in one short paragraph",
)
```
This is a separate one-shot invocation independent of the
orchestrator's pre/super/post lifecycle (different SDK session, same
agent definition).

Each judge stage is best-effort: a judge auth/rate/empty failure
degrades to permissive defaults (prejudge ok, supervise continue,
postjudge unknown) so the runner is never harder to use because of a
flaky judge call. All output prefixed `[judge]` in `run.log`.

Toggle in **Settings → Enable judge for auto-run** (default on); off
reverts to plain blocking wait + bare `exit_code`. The `judge`
subagent stays registered for main — the toggle only gates the
orchestrator's pre/super/post lifecycle wrapping.

## Agent architecture

For web / pwn / crypto / rev jobs, the **main worker** spins up a
two-tier Claude agent team — main agent (writer) + `recon` subagent
(read-only sub worker):

```
   main agent (writer)                  recon subagent (read-only)
   ──────────────────                   ──────────────────────────
   • drives reasoning                   • answers ONE specific
   • writes exploit.py /                  question per Task call
     solver.py / report.md              • Read / Bash / Glob / Grep
   • Read / Write / Edit /              • CANNOT Write / Edit
     Bash / Glob / Grep / Agent         • returns ≤2 KB summary
              │                                    ▲
              │  Task("recon", "<q>") ─────────────┘
              ▼
        compact summary
```

Same model on both sides — `recon` exists purely so heavy disasm / symbol
walks / source-tree greps don't pollute the main agent's conversation
context. The main agent keeps the only Write/Edit hand on the produced
files, and only the subagent's compact summary lands in main's context.

`recon` shares the same Bash environment as `main`, so anything in the
worker image is reachable: cross-arch binutils (`aarch64-linux-gnu-objdump`,
`-readelf`, `-nm`, plus the `arm-linux-gnueabi-*` family), `qemu-aarch64-
static` / `qemu-arm-static` (for running foreign-arch ELFs and
`qemu-aarch64-static -g 1234` gdbserver), `gdb -batch`, `strace`,
`ltrace`, `patchelf`, `cpio`, `ROPgadget` with `capstone>=5` (ARM64
gadgets work), `pwntools` (`ELF`, `cyclic`, `asm`, `ROP`), `ghiant`
(Ghidra-headless wrapper that writes `./decomp/<func>_<addr>.c`), plus
`jq` / `xxd` / `7z`. The `recon` system prompt ships a copy-pasteable
invocation guide grouped by intent (ELF/disasm, symbol/offset lookup,
gadgets, decompilation, cross-arch execution, dynamic analysis, archive
unpack, source triage), with two end-to-end Q/A format examples so the
return shape is consistent.

Decompiler output is treated as a first-class input: when `./decomp/`
is empty and raw disasm is dense, the main agent delegates a single
`Task("recon", "run ghiant on ./bin/<name> and summarize main / vuln /
read_input / proc_init in ≤12 lines with file:line + key constants")`,
and re-greps `./decomp/*.c` itself only for the call site recon points
at — never opening the whole tree.

Each turn the main agent emits an `init` SystemMessage whose `session_id`
the worker captures into `meta.claude_session_id`. On retry / resume
`_resubmit()` propagates that into `meta.resume_session_id` and copies
the prior `~/.claude/projects/<project_key>/<sid>.jsonl` (and any
`subagents/`) into the new job's project-key directory, so SDK
`fork_session=True` actually finds the prior conversation.

An optional **trip-wire** in each analyzer (`INVESTIGATION_BUDGET`,
default `0` = disabled) can abort a job cleanly if the agent has burned
that many tool calls without producing `exploit.py` / `solver.py` —
useful when you want a hard ceiling instead of letting the SDK exhaust
its context window with `Prompt is too long`. Set
`INVESTIGATION_BUDGET=<positive int>` in `.env` to enable.

Each module's SYSTEM_PROMPT opens with a 5-line **MISSION** stanza
(`mission_block()` in `modules/_common.py`) that tells the model up
front: write the deliverables to cwd, delegate heavy investigation
to recon, write a draft within ~10 tool calls, never disassemble
libc/framework internals, never re-slice saved disasm. Long tool
catalogues and module-specific workflows follow the mission stanza,
so the highest-signal guidance lands in the first few hundred
tokens of context.

## Prerequisites

- Docker Engine 24+ or Docker Desktop with WSL Integration enabled
- 6+ GB free disk for tool images (Ghidra alone is ~1.4 GB)
- Either:
  - **Claude Code OAuth** (recommended): Pro/Max claude.ai subscription, run
    `claude login` once on the host so `~/.claude/.credentials.json` exists, OR
  - **Anthropic API key**: set in `.env` or via the Settings tab

## Quick start

```bash
git clone <this-repo> HexTech_CTF_TOOL && cd HexTech_CTF_TOOL
cp .env.example .env

# Edit .env: set HOST_DATA_DIR to absolute path of <repo>/data
# (Auth: leave ANTHROPIC_API_KEY empty to use Claude Code OAuth instead.)

# Core services
docker compose up -d --build

# Tool images (one-time, pulled lazily)
docker compose --profile tools build decompiler forensic misc runner

# (Optional) SageMath solver sandbox for crypto module
docker compose --profile tools-sage pull sage
```

Open <http://localhost:8000>.

## Configuration

All knobs live in two places:

1. **`.env`** — read at container startup, applied to compose substitution:

   | Variable | Default | Purpose |
   |---|---|---|
   | `HOST_DATA_DIR` | `./data` | absolute host path for sibling-container bind mounts |
   | `WORKER_CONCURRENCY` | `3` | parallel job slots |
   | `JOB_TTL_DAYS` | `7` | auto-delete jobs older than N days (`0`=keep) |
   | `JOB_TIMEOUT` | `6000` | soft job timeout in seconds — see [Timeout & soft-deadline decision](#timeout--soft-deadline-decision) |
   | `WEB_PORT` | `8000` | host port |
   | `GHIDRA_VERSION` / `GHIDRA_BUILD_DATE` | `12.0.4` / `20260303` | Ghidra release used by decompiler image |
   | `ANTHROPIC_API_KEY` | empty | leave empty for OAuth |
   | `AUTH_TOKEN` | empty | shared token; empty = no auth (dev) |
   | `HOST_CLAUDE_HOME` | `${HOME}/.claude` | host path of Claude Code config |
   | `CLAUDE_CODE_MAX_OUTPUT_TOKENS` | `999999` | per-turn SDK output cap (the model's own ceiling, ~64k for Sonnet/Opus, becomes the effective limit) |
   | `INVESTIGATION_BUDGET` | `0` | tool-call budget after which a web/pwn/crypto/rev job aborts cleanly if no `exploit.py` / `solver.py` was produced. `0` (default) disables the trip-wire; set to a positive int to enable. |
   | `ENABLE_JUDGE` | `1` | wrap every `auto_run` runner execution with the 3-stage judge (pre / stall-supervise / post). Set to `0` to skip judge calls entirely. See [judge](#judge-modules_judgepy). |

2. **Settings tab** in the UI — writes to `/data/settings.json`, overrides `.env`
   without restart for: Anthropic API key, Claude model, Auth token, Job TTL,
   Job timeout, Worker concurrency, Callback URL, **Enable judge**.
   (Concurrency change requires `docker compose restart worker`.)

Precedence: `settings.json` > `.env` > defaults.

## Authentication options

- **Claude Code OAuth** (default): host's `~/.claude/` is bind-mounted into the
  worker (rw) and api (ro). The bundled `claude` CLI uses the existing OAuth
  token from `claude login`. Settings tab shows `✓ Claude Code OAuth detected`.
- **Anthropic API key**: paste into Settings → Anthropic API Key (or set
  `ANTHROPIC_API_KEY` in `.env`). Overrides OAuth when present.

UI access can additionally be gated by a shared **Auth Token** (`/login`,
cookie-based). Empty = no auth (dev mode).

## Concurrency

The worker container forks `WORKER_CONCURRENCY` independent RQ worker
processes, all subscribed to the same Redis queue. Jobs distribute
automatically. Each job can launch its own sibling sandbox container, so the
practical upper bound is host RAM/CPU (5–8 is usually fine).

The UI header shows `<busy>/<total> workers · <queued>` in real time.

## Job lifecycle

```
upload ──► /data/jobs/<id>/         ─► RQ enqueue
                 │
                 ▼
       worker process picks up
                 │
                 ▼
       (per module pipeline)
       e.g. Pwn:
        decompiler container ──► decomp.zip
                 │
                 ▼
       Claude Agent SDK (in worker)
       reads source, writes exploit.py + report.md
                 │
                 ▼
       (if auto_run) runner container
       executes exploit.py with the target as argv,
       captures stdout/stderr to <id>/exploit.py.std{out,err}
                 │
                 ▼
       result.json + meta.json updated
       UI polls /api/jobs/<id> every 2s
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | health probe |
| GET | `/api/modules` | module catalog |
| GET | `/api/jobs` | list all jobs |
| GET | `/api/jobs/{id}` | job meta |
| GET | `/api/jobs/{id}/log[?tail=N]` | run log (text). `?tail=N` returns only the trailing N bytes (newline-aligned, used by the polling UI). |
| GET | `/api/jobs/{id}/result` | result JSON |
| GET | `/api/jobs/{id}/file/{name}` | any artifact under the job dir |
| DELETE | `/api/jobs/{id}` | delete one job (cancels queued/running) |
| DELETE | `/api/jobs?status=…&module=…&all=…` | bulk delete (default: finished+failed only) |
| GET | `/api/jobs/queue` | live worker + queue snapshot |
| GET | `/api/jobs/stats` | aggregate cost + counts |
| GET / PUT | `/api/settings` | settings view + patch |
| POST | `/api/modules/web/analyze` | upload source zip → enqueue |
| POST | `/api/modules/pwn/analyze` | upload binary → enqueue |
| POST | `/api/modules/forensic/collect` | upload disk/memory image → enqueue |
| POST | `/api/modules/misc/analyze` | upload file → enqueue |
| POST | `/api/modules/crypto/analyze` | upload zip → enqueue |
| POST | `/api/modules/rev/analyze` | upload binary → enqueue |
| POST | `/api/jobs/{id}/run` | re-run produced exploit/solver in a fresh sandbox |
| POST | `/api/jobs/{id}/retry` | regenerate the job. JSON body fields all optional: `hint` (skip reviewer if present), `target` (override prior target_url; sentinel `(none)` clears it). Empty body = auto reviewer + keep prior target. |
| POST | `/api/jobs/{id}/retry/stream` | same as `/retry` but Server-Sent Events stream the reviewer text live |
| POST | `/api/jobs/{id}/resume` | hard-stop a queued/running job, then enqueue a fresh one with the same body shape as `/retry`; `hint` required here. Carries `./work/` + forks the prior SDK session. |
| POST | `/api/jobs/{id}/resume/stream` | SSE-streamed resume. With `{"hint":"…"}` works exactly like `/resume`. With an empty body, calls the reviewer to write the hint first. Both modes carry `./work/`, fork the prior session, and prepend the `[RESUMING]` preamble. |
| POST | `/api/jobs/{id}/timeout/continue` | acknowledge the soft timeout — let the agent keep running |
| POST | `/api/jobs/{id}/timeout/kill` | acknowledge the soft timeout — hard-stop the job |

## File layout

```
HexTech_CTF_TOOL/
├── docker-compose.yml
├── .env  /  .env.example
├── api/                 # FastAPI app
│   ├── auth.py          # Token middleware
│   ├── main.py
│   ├── queue.py         # RQ helpers
│   ├── routes/          # one router per module + jobs + settings
│   └── storage.py
├── worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── runner.py        # multi-process RQ worker + cleanup loop
├── modules/             # mounted into both api & worker (live-edit)
│   ├── _common.py       # shared helpers (cost, paths, meta)
│   ├── _runner.py       # sandbox container helper
│   ├── settings_io.py   # /data/settings.json read/write + OAuth detection
│   ├── web/             # SYSTEM_PROMPT + analyzer.run_job
│   ├── pwn/             # SYSTEM_PROMPT + decompile + analyzer
│   ├── crypto/
│   ├── rev/
│   ├── forensic/
│   └── misc/
├── decompiler/          # Ghidra image (ghiant scripts vendored)
├── forensic/            # sleuthkit + qemu-utils + Volatility 3
├── misc/                # binwalk + foremost + steghide + zsteg + ...
├── runner/              # Python + crypto libs + pwntools (sandbox)
├── web-ui/              # static HTML/CSS/JS
└── data/                # job uploads + outputs (gitignored)
```

## Module-specific notes

### Web
- Accepts a zip of source code or a single file.
- Optionally a `target_url` to test against.
- Auto-run runs the produced `exploit.py <url>` in a sandboxed runner.

### Pwn
- Requires the `decompiler` image (Ghidra 12.0.4 by default; override
  `GHIDRA_VERSION`/`GHIDRA_BUILD_DATE` in `.env`).
- Per-job timeline: ~2–3 min decompile + Claude analysis time.
- Worker container ships cross-arch CLIs the agent expects from Bash:
  `aarch64-linux-gnu-{objdump,nm,readelf}`, `arm-linux-gnueabi-*`,
  `qemu-aarch64-static` / `qemu-arm-static`, `gdb`, `gdb-multiarch`,
  `strace`, `ltrace`, `patchelf`, `cpio`, `ROPgadget` (with
  `capstone>=5` so ARM64 gadget search actually returns hits),
  `one_gadget`, `pwn checksec`.
- Dynamic analysis is reachable for foreign-arch ELFs too:
  `qemu-aarch64-static -g 1234 ./bin/x &` followed by
  `gdb-multiarch -batch -ex 'set arch aarch64' -ex 'target remote
  :1234' -ex 'b *0x...' -ex 'continue' …` lets the recon subagent
  break/inspect inside QEMU-user without needing a full system VM.

### Forensic
- Auto-detects qcow2 / vmdk / vhd / vhdx / e01 / raw / memory / **log**.
- E01 is converted to raw via `ewfexport`; vmdk/qcow2/vhd via `qemu-img`.
- Memory dumps run a curated Volatility 3 plugin set per detected OS.
- **Image type `log`** is a fast path for raw log uploads: skip
  disk/memory analysis and run only the log-mining stage. Accepts a
  single text file (`.log`, `.txt`, …), a `.gz` of one, or any
  `.zip` / `.tar` / `.tar.gz` / `.tgz` of logs. The archive is unpacked
  into `artifacts/logs/` and `log_miner` mines every text file
  underneath (`force=True` — name hints are ignored). Auto-detect picks
  this kind for plain `.log/.txt/.csv/.json/...` uploads or anything
  the `file(1)` command labels as ASCII/UTF-8 text.
- After artifacts are extracted, `log_miner` scans every log/history file
  (Apache/Nginx access + error logs, `auth.log`, `syslog`, `bash_history`,
  PowerShell `ConsoleHost_history.txt`, Volatility `linux.bash` output, …)
  and writes `log_findings.json` with categorized hits:
  - **passwords** — credentials leaked in URL params, JSON bodies,
    `mysql -p<pw>`, `curl -u user:pass`, HTTP `Authorization: Basic …`.
  - **sqli_attempts / xss_attempts / lfi_attempts / rce_attempts** —
    classic web-attack signatures (`UNION SELECT`, `' OR 1=1`, `<script>`,
    `../../etc/passwd`, ``$(…)`` , …). Lines are URL-decoded before
    matching so encoded payloads register.
  - **auth_events** — sshd Accepted/Failed/Invalid-user lines and sudo
    auth events. Useful for spotting brute-force-then-success sequences.
  - **flag_candidates** — anything matching the project's CTF flag regex.

  The job detail panel shows category counts as colored chips; the full
  report is one click away (`log_findings.json`). The Claude summarizer
  is told to read `log_findings.json` first since it's the highest-signal
  source for web-CTF disk images.

### Misc
- Unifies binwalk extraction, exiftool, zsteg LSB, steghide, pngcheck, pdf
  parsing. Common flag patterns are auto-extracted.
- bulk_extractor is **not** included (Ubuntu 22.04 dropped the package).

### Crypto
- Solver runs in the worker by default; check **Use SageMath sandbox** to
  execute via the `sagemath/sagemath` image (supports lattice/Coppersmith).
- Available libs in the runner sandbox: pycryptodome, gmpy2, sympy, z3-solver,
  ecdsa, pwntools.

### Reversing
- Reuses the `decompiler` image.
- Solver auto-runs in the runner container if requested.

## Operational commands

```bash
docker compose up -d              # start core services
docker compose down               # stop
docker compose logs -f worker     # tail worker logs
docker compose ps                 # status

docker compose restart worker     # apply WORKER_CONCURRENCY changes
docker compose build api          # rebuild after code changes in api/

# Wipe all jobs (UI also has a Bulk Delete button)
curl -X DELETE 'http://localhost:8000/api/jobs?all=true'
```

## Timeout & soft-deadline decision

Default job timeout is **6000s** (≈100 min). Override per-job from each
Analyze form, or globally in Settings (`job_timeout_seconds`).

The timeout is **soft**: when it elapses while the agent is still working,
the job is **not** killed. Instead a yellow banner appears on the job
detail panel showing two buttons:

| Button | What happens |
|---|---|
| **▶ Continue running** | Acknowledges the timeout and lets the agent run to completion. The watchdog does not fire again — your acknowledgment carries through to the natural end of the job. |
| **■ Stop now** | Hard-kills the job: signals the worker, removes any sibling containers, marks `meta.status = failed` with `error: "Stopped by user at soft timeout"`. |

Internally:
- The worker spawns an `asyncio` watchdog at the start of the agent loop
  that sleeps the user-set soft timeout, then sets `meta.awaiting_decision`
  and logs a single line. The agent loop is never interrupted.
- RQ's hard timeout is set automatically to **4× the soft budget (min 24 h,
  max 7 d)** so the worker has plenty of runway after a `continue` decision
  before RQ's safety net fires.
- If the agent finishes naturally before the soft timeout, the watchdog is
  cancelled silently and no banner ever appears.

## Retry / Resume

Web / Pwn / Crypto / Rev jobs can be re-issued at any terminal status
(`failed`, `no_flag`, `finished`, `stopped`) — and Stop&resume can also
fire while the job is still `queued` / `running`. Four buttons:

| Button | What happens |
|---|---|
| **↻ Retry with reviewer hint** | A separate Claude (Opus 4.7 by default) reads the prior job's `run.log`, exploit/solver, stdout/stderr, and key source files, then writes a one-paragraph diagnosis. That hint is appended to the original description as `[retry-hint] …` and a fresh job is enqueued. Reviewer output streams into the UI live (SSE). |
| **✏ Retry with my hint** | Inline textarea. Whatever you type is appended as `[retry-hint]` — the reviewer is **not** called. |
| **↻ Stop & resume with reviewer hint** | Only visible while the job is `queued`/`running`. Halts the in-flight job, asks the reviewer to write a diagnosis from the partial run, and submits the new job with that hint. SSE streams progress. |
| **✋ Stop & resume with my hint** | Same as the reviewer variant but you write the hint yourself. |

**What carries forward** (all four paths):

- the previous job's `./work/` directory (partial `exploit.py` / `solver.py`
  / `report.md` / notes / decomp output) is copied into the new job, so
  the new agent literally sees the files the prior agent wrote;
- the prior Claude SDK conversation: `meta.claude_session_id` is captured
  by `capture_session_id()` whenever the SDK emits an `init` SystemMessage,
  propagated to `meta.resume_session_id` of the new job, and the prior
  session's transcript jsonl (plus any `subagents/`) is copied into the
  new cwd's project-key directory. The new analyzer launches with
  `ClaudeAgentOptions(resume=<sid>, fork_session=True)`, so the new agent
  inherits the prior reasoning, thinking, and tool history — not just
  the work tree;
- the user-supplied (or reviewer-written) hint is hoisted to the **top**
  of the new agent's user prompt as `⚠ PRIORITY GUIDANCE` so it isn't
  buried under the original challenge description;
- module / target / model / timeout / source-or-binary upload / auto_run
  are inherited automatically. The retry chain is recorded as
  `meta.retry_of`; resume additionally records `meta.resumed_from`.

**Optional target override**: every retry/resume button accepts an optional
new target. Reviewer-mode buttons prompt via `window.prompt()` (prefilled
with the prior target); inline-form buttons add a one-line input under the
hint textarea. Empty input keeps the prior target; the sentinel `(none)`
clears it.

If the SDK can't locate the prior session for any reason, the new agent
boots fresh — `./work/` + the priority-guidance hint are still sufficient
context. The fallback is documented inside the preamble itself.

**Stale-absolute-path recovery**: a forked SDK session occasionally
re-uses absolute paths like `/data/jobs/<prev_id>/work/...` from its
prior tool history, so the new agent's `Write`/`Edit` calls land in the
**old** job dir while the new `work/` keeps the untouched carry-copy.
On finalize the analyzers walk the `retry_of` / `resumed_from` lineage
(up to 8 hops) via `prior_work_dirs()` and treat those dirs as fallback
candidates in `collect_outputs()`. When the same filename appears in
multiple candidates the most-recent mtime wins; the chosen file is then
mirrored back into the current `work/` so the next retry's carry step
picks up the freshest version. Each analyzer also exports `JOB_ID` into
the agent env so future preambles can anchor on it.

Errors from the reviewer (Claude API auth/rate-limit/credit failures,
policy refusals, empty responses) are surfaced in the panel with a red
"no new job created" header and the error body. The new job is **not**
enqueued in that case.

## UI niceties

- **Job detail modal**. Clicking a job opens a centered overlay (~96vw),
  not an inline panel. Esc / backdrop / ✕ closes; background scroll is
  locked while open.
- **Run log frame**. The run log lives in a macOS-style terminal window
  with traffic-light buttons and a green block caret that blinks while
  the job is `running` / `queued` (steady when terminal). Each line is
  classified by prefix and colored:
  `AGENT` (lavender) · `TOOL <name>` (blue + orange tool name) ·
  `TOOL_RESULT` (green) · `TOOL_ERROR` (red) · `THINK` (yellow italic) ·
  `DONE` (light blue) · `AGENT_ERROR` / `ERROR` (red bold) · system
  notes (dim italic).
- **Live elapsed / duration pill**. Right next to the status badge the
  job header carries a colored pill (`⏱ 12m 45s`):
    - yellow with a soft pulse + `running` tag while live (ticks every
      second from a dedicated 1 s timer that ignores the polling
      pause used by selection / open forms — so the counter stays
      smooth while you're copying log text or typing a hint),
    - green when finished, red when failed, etc.,
    - dim gray `⏱ queued` before the worker picks the job up.
  Auto-stamped by the backend the first time status flips to running
  / a terminal value.
- **Liveness chip + token/cost meter**. The run-log footer carries
  two ground-truth pills updated on the same 1 s timer:
    - **liveness** — `active` (green, ≤30 s since last SDK message),
      `silent` (amber, >30 s but RQ worker still heartbeating —
      thinking / first-token wait), `warming` (blue, worker alive but
      no agent event yet), `dead` (red, blinking, >60 s since RQ
      worker heartbeat → process gone, retry/stop now).
    - **tokens / cost** — sums `result.usage` across every turn in
      the run (input + cache_read + cache_creation + output) and the
      cumulative USD cost. Survives long runs without resetting on
      each turn boundary.
  Read together: yellow timing + active liveness = real progress;
  yellow + silent = thinking; yellow + dead = the process died.
- **File preview modal**. Clicking `result.json` / `report.md` /
  `exploit.py` / `solver.py` / `summary.json` / `findings.json` /
  `log_findings.json` etc. opens a syntax-highlighted overlay
  (highlight.js + marked from jsDelivr CDN). JSON is pretty-printed,
  Markdown is rendered with embedded code blocks highlighted, source
  files (`.py` / `.sage` / `.sh` / `.c` / …) are highlighted by
  extension, logs are plain text. `Open raw` / `Copy` / Esc / backdrop.
  Modifier-clicks (`Ctrl/Cmd/Shift/middle`) skip the modal.
- **Polling that respects user input**. The 2-second poll re-render
  is suppressed while you have an inline retry/resume form open OR
  while you have a non-collapsed selection inside the run log — so
  a copy-paste mid-run isn't clobbered by an incoming line.

## Out-of-band callbacks (XSS / SSRF / blind RCE)

CTFs that exfiltrate via a remote bot need a publicly-reachable
listener. HexTech_CTF_TOOL has a built-in collector that takes any HTTP
request, logs it, and auto-extracts flag-shaped strings.

Setup once:

```bash
# 1. Expose port 8000 publicly
ngrok http 8000     # or any tunnel: cloudflared, frp, ssh -R, …

# 2. Settings tab → Callback URL = https://<your-tunnel-host>
#    (the orchestrator appends /api/collector/<job_id> per job)
```

Then any agent-produced exploit can use `os.environ["COLLECTOR_URL"]`
as its callback. The collector:

- writes every hit to `<jobdir>/callbacks.jsonl`
- re-scans for FLAG/CTF/DH-style patterns in the URL/query/body
- flips meta.status to `finished` and surfaces flags the moment a
  match arrives — even if the exploit has already exited

`/api/collector/<job_id>` is intentionally exempt from the auth
token. Treat the job_id as a secret if you care.

## Security notes

- Sibling containers spawned by the worker run as root and share the Docker
  socket — treat the worker host as part of the trust boundary.
- `runner` (the sandbox for produced exploit/solver scripts) runs with a
  bridge network by default. For local-only crypto challenges the network
  could be disabled with `network_mode="none"` in `modules/_runner.py`.
- The worker bind-mounts the host's `~/.claude` (rw, so OAuth tokens can
  refresh). Don't run untrusted code as the worker.
- Only the `/api/health` route bypasses auth when an Auth Token is set.

## Troubleshooting

- **`ERR_EMPTY_RESPONSE` from browser**: WSL2 + Docker Desktop port forwarding
  glitch. Try `http://127.0.0.1:8000` or the WSL distro's IP.
- **`docker-credential-desktop.exe: exec format error`** during build: WSL
  interop disabled. Either enable interop, or write `~/.docker/config.json`
  to `{}` to drop the Windows credential helper.
- **`Unable to locate package` (forensic build)**: `bulk-extractor` is no
  longer in Ubuntu 22.04. The Dockerfile already excludes it; if you
  re-add tools, install from a third-party repo.
- **Claude returns 401**: Check Settings tab. `claude_oauth_detected` should
  be `true`, OR a real `ANTHROPIC_API_KEY` should be set. The placeholder
  `sk-ant-...` is automatically ignored.
- **Long-running job stuck**: `GET /api/jobs/queue` shows worker state. If a
  worker is in `busy` for too long, `docker compose restart worker` to recycle.

## License

MIT.
