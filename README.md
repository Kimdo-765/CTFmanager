# HextTech_CTF_TOOL

Docker-based web UI toolset for CTF problem solving. Six modules covering Web, Pwn,
Forensic, Misc, Crypto, and Reversing — each combines automated tooling with a
Claude Code agent that reads the challenge, identifies the vulnerability or
flag, and generates a runnable exploit/solver script.

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

```
                      ┌────────── docker-compose ──────────┐
                      │                                     │
   browser ──:8000──► │  api (FastAPI)  ─────► redis       │
                      │      │                  │           │
                      │      │              RQ queue       │
                      │      │                  │           │
                      │      ▼                  ▼           │
                      │   /data ◄──────► worker (N procs)  │
                      │      ▲              │ │ │           │
                      │      │              ▼ ▼ ▼           │
                      │      │     ┌────── docker.sock ────┴─────┐
                      │      │     ▼                              ▼
                      │      │   sibling sandboxes (per-job, transient):
                      │      │     decompiler  forensic  misc  runner  sage
                      │      │
                      │      └── settings.json (live edits via UI)
                      └─────────────────────────────────────┘
```

- **api**: FastAPI app on port 8000, serves the web UI and JSON endpoints.
- **worker**: spawns N (default 3) RQ worker processes that pull jobs from Redis.
  Each running job can launch sibling tool/sandbox containers via the mounted
  Docker socket.
- **redis**: job queue.
- **decompiler / forensic / misc / runner / sage**: built but not started.
  The worker `docker run`s them per job, then removes them.

## Prerequisites

- Docker Engine 24+ or Docker Desktop with WSL Integration enabled
- 6+ GB free disk for tool images (Ghidra alone is ~1.4 GB)
- Either:
  - **Claude Code OAuth** (recommended): Pro/Max claude.ai subscription, run
    `claude login` once on the host so `~/.claude/.credentials.json` exists, OR
  - **Anthropic API key**: set in `.env` or via the Settings tab

## Quick start

```bash
git clone <this-repo> HextTech_CTF_TOOL && cd HextTech_CTF_TOOL
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

2. **Settings tab** in the UI — writes to `/data/settings.json`, overrides `.env`
   without restart for: Anthropic API key, Claude model, Auth token, Job TTL,
   Job timeout, Worker concurrency. (Concurrency change requires
   `docker compose restart worker`.)

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
| GET | `/api/jobs/{id}/log` | run log (text) |
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
| POST | `/api/jobs/{id}/retry` | regenerate the job with a hint (body: `{"hint":"…"}` for manual hint, empty body = auto reviewer) |
| POST | `/api/jobs/{id}/retry/stream` | same as `/retry` but returns Server-Sent Events with reviewer progress |
| POST | `/api/jobs/{id}/resume` | hard-stop the job (if still queued/running), then enqueue a fresh one with `{"hint":"…"}` appended as `[retry-hint]` |
| POST | `/api/jobs/{id}/resume/stream` | SSE-streamed resume. With `{"hint":"…"}` body works exactly like `/resume`. With an empty body, calls the latest reviewer to write the hint (same flow as `/retry/stream`) before submitting. Both modes carry `./work/` and prepend the `[RESUMING]` preamble. |
| POST | `/api/jobs/{id}/timeout/continue` | acknowledge the soft timeout — let the agent keep running |
| POST | `/api/jobs/{id}/timeout/kill` | acknowledge the soft timeout — hard-stop the job |

## File layout

```
HextTech_CTF_TOOL/
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

## Retry with hint

When a Web/Pwn/Crypto/Rev job ends in `failed`, `no_flag`, or `finished
without a flag`, the job detail panel shows two retry buttons:

| Button | What happens |
|---|---|
| **↻ Retry with reviewer hint** | A separate Claude (Opus 4.7 by default) reads the prior job's `run.log`, exploit/solver, stdout/stderr, and key source files, then writes a one-paragraph diagnosis. That hint is appended to the original description as `[retry-hint] …` and a fresh job is enqueued. Reviewer output streams into the UI live (SSE). |
| **✏ Retry with my hint** | Opens an inline textarea. Whatever you type is appended verbatim as `[retry-hint]` — the reviewer is **not** called and no Claude credit is spent. Useful when you've already spotted the bug and just want the agent to focus on a specific lead. |
| **↻ Stop & resume with reviewer hint** | Only visible while the job is `queued`/`running`. Halts the in-flight job, then asks the latest Claude (Opus 4.7) to read the partial run.log + work/ + sources and write a one-paragraph diagnosis. That hint becomes the next job's `[retry-hint]`. SSE-streamed, so reviewer output appears live in the same purple panel used by `/retry/stream`. **Resume preserves context**: the previous agent's `./work/` (partial `exploit.py` / `solver.py` / `report.md` / notes) is copied into the new job and the agent is told to read those first. |
| **✋ Stop & resume with my hint** | Same as the reviewer variant, but you write the hint yourself in an inline textarea — no Claude credit spent. Use this when you've already spotted the wrong turn and want to redirect without paying for a reviewer pass. |

The new job inherits the previous module, target, model, timeout, source/binary
upload, and `auto_run` setting — you don't re-upload anything. The retry
chain is recorded as `meta.retry_of` on the new job so you can trace lineage.

Errors from the reviewer (Claude API auth/rate-limit/credit failures, policy
refusals, empty responses) are surfaced in the panel with a red "no new job
created" header and the error body. The new job is **not** enqueued in that
case — fix the underlying issue (or use the manual-hint button) and try
again.

## Out-of-band callbacks (XSS / SSRF / blind RCE)

CTFs that exfiltrate via a remote bot need a publicly-reachable
listener. HextTech_CTF_TOOL has a built-in collector that takes any HTTP
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
