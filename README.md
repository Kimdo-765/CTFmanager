# HexTech_CTF_TOOL

Docker-based web UI toolset for CTF problem solving. Six modules covering Web, Pwn,
Forensic, Misc, Crypto, and Reversing — each combines automated tooling with a
Claude Code agent that reads the challenge, identifies the vulnerability or
flag, and generates a runnable exploit/solver script.

Five Claude-driven roles split by responsibility:

- **reviewer** — Opus 4.7, no tools. Lives in the api container. Reads
  the prior job's `run.log` / exploit / stdout-stderr / source on
  `/retry` and `/resume` and writes ONE 1500-char paragraph hint that
  is hoisted to the next agent's prompt as `⚠ PRIORITY GUIDANCE`.
- **main worker** — RQ process in the worker container. Drives the
  module pipeline and runs the main Claude agent (writer) that
  produces `exploit.py` / `solver.py` / `report.md`. Hosted in a
  single `ClaudeSDKClient` session so postjudge feedback can flow
  back as a new user turn (see [auto-retry triangle](#auto-retry-triangle)).
- **recon** — read-only static-investigation peer subagent. Returns
  a ≤2 KB summary so heavy disasm / source greps / decomp triage
  never pollute main.
- **judge** — read-only quality-gate peer subagent. Two roles: (1) main
  invokes it before finalizing for hang/parse review; (2) the
  orchestrator wraps every `auto_run` execution in a 3-stage
  pre/supervise/post lifecycle that emits a retry hint on failure.
- **debugger** — dynamic-analysis peer subagent. Patchelfs the binary
  against the chal's bundled libc (auto-extracted from the Dockerfile's
  base image when needed), then runs gdb / strace / ltrace / qemu-user
  and reports observed runtime state to main. See
  [debugger](#debugger-modules_commonpy-debugger_agent_prompt).

**Subagent isolation (default ON).** All three peer subagents
(recon / judge / debugger) run in their **own** `claude` CLI subprocess
via a custom MCP tool `mcp__team__spawn_subagent`. Each invocation
forks a fresh `ClaudeSDKClient`, runs the subagent to completion, and
discards the subprocess on return — main only ever sees the
subagent's final-text reply as a tool result. The SDK's built-in
`Agent`/`Task` tools are explicitly disallowed so the model can't
fall back to the in-process path. See
[Subagent isolation](#subagent-isolation-default-on).

Sibling sandbox containers (decompiler / forensic / misc / runner /
sage) are spawned per job and removed when done — orthogonal to the
five Claude roles above.

See [Architecture](#architecture) and [Agent architecture](#agent-architecture).

Failed jobs (or finished-without-flag) can be **retried** with an automatic
reviewer-written hint, a hand-written hint, or stop-and-resume mid-run.
There's also an **inline auto-retry loop** that runs without leaving the
job: when the sandboxed run fails, postjudge's retry_hint is injected back
into main's same SDK session and main patches + re-finalizes (configurable
via `AUTO_RETRY_MAX`, default unlimited). See [Retry / Resume](#retry--resume).

## Modules

| Module | Pipeline | Output |
|---|---|---|
| **Web** | Claude reads source zip → identifies vuln → writes `exploit.py` (requests/pwntools) | exploit.py + report.md |
| **Pwn** | ghiant decomp + ghiant xrefs (cached Ghidra project) + chal-libc-fix base-image lib extraction + GEF gdb + debugger agent → Claude analysis → `exploit.py` | exploit.py + report.md |
| **Forensic** | sleuthkit + qemu-img + Volatility 3 artifact sweep → optional Claude summary | summary.json + artifacts/ + report.md |
| **Misc** | binwalk + foremost + exiftool + steghide + zsteg + pngcheck + qpdf → Claude triage | findings.json + extracted/ + report.md |
| **Crypto** | Claude analyzes source → writes `solver.py` using gmpy2/sympy/z3/pycryptodome (or `solver.sage` with optional SageMath sandbox) | solver.py + report.md |
| **Reversing** | ghiant decomp + xrefs + debugger agent → Claude reverses logic → `solver.py` | solver.py + report.md |

For Web/Pwn/Crypto/Rev, an optional `auto_run` checkbox executes the produced
script in a sandboxed `runner` container (network-isolated unless a remote
target is given).

## Architecture

Five Claude-driven roles, each with its own context window:

| Role | Where it runs | Tools | Purpose |
|---|---|---|---|
| **reviewer** | `api` container, inline in `/retry` & `/resume` handlers | none (diagnostic only) | Reads the failed prior job and writes a 1-paragraph hint, streamed to the browser |
| **main worker** | `worker` container, one RQ process per concurrency slot | `Read` `Write` `Edit` `Bash` `Glob` `Grep` `mcp__team__spawn_subagent` | Runs the module pipeline; writes `exploit.py` / `solver.py` / `report.md` in a single `ClaudeSDKClient` session that auto-retries on postjudge feedback. Built-in `Agent` / `Task` tools are disallowed; delegation goes through the MCP tool only |
| **recon** (peer subagent) | **own `claude` CLI subprocess** spawned via MCP, dies on return | `Read` `Bash` `Glob` `Grep` (read-only) | Static investigation: disasm walks, decomp triage, libc symbol lookup, ROPgadget / one_gadget filter, source-tree grep. Returns ≤2 KB summary |
| **judge** (peer subagent + lifecycle gate) | own subprocess when invoked by main · separate orchestrator-owned session around every `auto_run` execution | `Read` `Bash` `Glob` `Grep` (no Write) | Pre-finalize hang/parse review when invoked by main · pre/supervise/post lifecycle around the runner sandbox · pinned to latest model |
| **debugger** (peer subagent) | own `claude` CLI subprocess spawned via MCP | `Read` `Write` `Edit` `Bash` `Glob` `Grep` | Dynamic analysis under gdb (GEF) / strace / ltrace / qemu-user. Auto-extracts the chal's libc + ld + NEEDED libs from the Dockerfile's base image via `chal-libc-fix`. Returns ≤2 KB OBSERVED/TRACE/CONCLUSION/CAVEATS shape |

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
   ┌──── main worker  (N RQ procs) ──────────────────────┐
   │  ClaudeSDKClient session → deliverables             │
   │  + auto-retry on postjudge feedback                 │
   │  + heartbeat + token/cost meter                     │
   │  + spawn-cap + compaction guards + fallback         │
   └─┬─────────────────────┬───────────┬─────────────────┘
     │ mcp__team__         │ docker.sock          
     │ spawn_subagent      │                       
     ▼                     ▼                       
   ┌─isolated subagents (each: own claude CLI subprocess)─┐
   │ recon    static, read-only       (Node #2, dies)     │
   │ judge    quality gate            (Node #3, dies)     │
   │ debugger gdb/strace + chal-libc  (Node #4, dies)     │
   │ → only the final-text reply (~KB) returns to main    │
   └──────────────────────────────────────────────────────┘
            ┌─sibling sandboxes─────────┐
            │ decompiler · forensic ·   │
            │ misc · runner · sage      │
            │ (per-job, removed)        │
            └───────────────────────────┘
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

### peer subagents — isolated `claude` CLI subprocesses, transient per spawn

When main calls `mcp__team__spawn_subagent(subagent_type, prompt)`,
the orchestrator creates a brand-new `ClaudeSDKClient` for the
subagent with role-specific options (`make_standalone_options` in
`modules/_common.py`). That client owns its own `claude` CLI Node.js
subprocess, runs the subagent to completion, and is closed on
return — the subprocess dies. Main only sees the subagent's final
text response as the MCP tool result; the subagent's intermediate
tool calls, decomp reads, gdb sessions, etc. never touch main's
conversation history.

- **recon** — Read-only (`Read` / `Bash` / `Glob` / `Grep`); cannot
  `Write` or `Edit`. Returns a ≤2 KB compact summary so heavy disasm /
  source greps / ghiant decompilation never pollute main's history.
  Decomp triage protocol returns FUNCTIONS inventory + ranked
  CANDIDATES (HIGH/MED/LOW with bug class + file:line) so main only
  reads the flagged files. See [Agent architecture](#agent-architecture).
- **judge** — Quality gate. Used by main pre-finalize for hang/parse
  review, by the orchestrator around every `auto_run` execution.
  Pinned to `LATEST_JUDGE_MODEL`. Read-only; cannot cascade-spawn
  further subagents in isolated mode (preserves the "ONE level deep"
  invariant).
- **debugger** — Dynamic analysis. `gdb -batch` (GEF auto-loaded) /
  strace / ltrace / qemu-user gdbserver. Always patchelfs the binary
  against the chal's bundled libc first via `chal-libc-fix` so leaked
  addresses / heap layouts / one_gadget constraints match the remote.
  Falls back to extracting libc + ld + every `DT_NEEDED` .so directly
  from the Dockerfile's `FROM` image when no physical libs are bundled
  (the common Dreamhack / HackTheBox case). See [debugger](#debugger-modules_commonpy-debugger_agent_prompt).

### Subagent isolation (default ON)

Verified empirically (memory file `worker_fork_oom.md` and SDK
source reading): the `claude-agent-sdk` runs ALL `AgentDefinition`
contexts inside a **single** `claude` CLI Node.js subprocess.
When main spawned via the legacy `Agent(subagent_type=...)` tool,
the subagent's full conversation accumulated into main's Node.js
heap — a few heap-pwn delegations easily pushed cache_read past
5 M tokens and the V8 heap past the worker's cgroup `mem_limit`,
SIGKILLing the CLI with `exit code -9`. Jobs 011a / 7c4a / ff82 /
5c53 / c4f4 all died this way.

**How isolation works** (`make_spawn_subagent_mcp` +
`make_standalone_options` in `modules/_common.py`):

1. Main's options expose ONLY the MCP tool
   `mcp__team__spawn_subagent` for delegation. Built-in
   `Agent` / `Task` are added to `disallowed_tools=[...]` so the
   model cannot fall back to the in-process path even under
   `permission_mode=bypassPermissions`.
2. Each `spawn_subagent(subagent_type, prompt)` call:
   - increments `summary["subagent_spawns"]` (gated by
     `SUBAGENT_SPAWN_CAP`),
   - builds a standalone `ClaudeAgentOptions` with the requested
     agent's system prompt + tool list + model,
   - opens a fresh `ClaudeSDKClient` (= new `claude` CLI
     subprocess) for that one invocation,
   - drains the subagent's `receive_response()` to collect its
     final text,
   - returns the text to main as the MCP tool result.
3. The subagent's subprocess exits at the `async with` boundary;
   its in-process heap is fully released by the kernel.

Main therefore only accumulates the subagent's final reply
(typically a few KB) per delegation, not the subagent's whole
investigation transcript (often hundreds of KB). On a job that
runs 4 spawns the cumulative growth difference is ~1–2 MB of
context (isolated) vs. ~1–2 MB **per spawn** (legacy in-process).

**Spawn cap**. `SUBAGENT_SPAWN_CAP` (default `4`) bounds the
delegation count per run; the typical heap-pwn workflow is
`recon × 2 + debugger × 1 + judge × 1`. At `count == cap` the
orchestrator injects `SUBAGENT_CAP_USER_TURN` ("do the rest
inline") into the next user turn; at `count > cap` it breaks
the receive loop immediately, writes fallback artifacts, and
dispatches the sandbox — main never gets to make a (cap+1)th
spawn that would push it past safety.

**Compaction guard**. `CONTEXT_COMPACTION_THRESHOLD` (SOFT, default
6 M cache_read tokens) injects a "finalize now, no further
subagent spawns" user turn. `CONTEXT_COMPACTION_HARD_CEILING`
(default 10 M, well below the worker's 14g cgroup limit) cleanly
aborts the main session, writes fallback artifacts, and runs the
sandbox + judge cycle so the job ends as `no_flag` / `partial`
rather than `failed` (= what the legacy single-Node.js-process
sessions reached just before SIGKILL).

**Rollback**. Set `USE_ISOLATED_SUBAGENTS=0` in `.env` to revert
to the legacy `agents={}` in-process path. The cap + compaction
guards still apply.

### sibling sandboxes — transient docker containers

`decompiler` (Ghidra), `forensic` (TSK + qemu-img + Vol3), `misc`
(binwalk + steghide + …), `runner` (exec exploit.py / solver.py),
`sage` (optional Coppersmith / LLL). Built once via `--profile tools`,
never started by `compose up`. The worker `docker run`s them per job
and removes them when done.

### judge (`modules/_judge.py`)

Quality-gate agent around every `auto_run` exploit/solver execution.
Pinned to `LATEST_JUDGE_MODEL` (currently `claude-opus-4-7` — shared
with the retry reviewer). Judge is a peer to recon: same read-only
tool set (`Read` / `Bash` / `Glob` / `Grep`) plus `Agent` so it can
delegate heavy investigation to recon. **No `Write` / `Edit`** —
judge cannot patch the script.

**main ↔ peers** quartet (isolated subagent path, default ON):

```
   ┌──────────────────── main (writer, Node #1) ─────────────────┐
   │  Read · Write · Edit · Bash · Glob · Grep                   │
   │  + mcp__team__spawn_subagent(subagent_type=…, prompt=…)     │
   │  (Agent/Task: explicitly disallowed)                        │
   └────┬───────────────┬─────────────────┬──────────────────────┘
        │ spawn         │ spawn           │ spawn
        ▼               ▼                 ▼
   ┌── recon ─────┐  ┌── judge ──────┐  ┌── debugger ────────┐
   │ Node #2,     │  │ Node #3,      │  │ Node #4,           │
   │ dies on      │  │ dies on       │  │ dies on return     │
   │ return       │  │ return        │  │                    │
   │ read-only    │  │ read-only,    │  │ Read/Write/Bash    │
   │ ≤2 KB reply  │  │ no cascade    │  │ chal-libc-fix +    │
   └──────────────┘  │ pinned latest │  │ gdb (GEF) +        │
                    └───────────────┘  │ strace/ltrace      │
                                       └────────────────────┘
       ↑ all three return ONLY the final-text reply to main ↑
```

**Decision flow — main owns the gate, judge is the advisor**

The mission stanza in `mission_block()` makes a judge consult
**mandatory before main finalizes**. After main writes its draft
exploit/solver, it MUST call:

```python
mcp__team__spawn_subagent(
    subagent_type="judge",
    prompt="review ./exploit.py for hang/parse risks (recvuntil
            without timeout, wrong prompt, wrong tube, missing
            argv, infinite loop). Return: per-line FINDINGS,
            SEVERITY, RECOMMEND patch|proceed|abort, REASON.",
)
```

Judge replies with structured findings (see `JUDGE_AGENT_PROMPT`).
**Main reads them and decides**:

| Main's choice | Action |
|---|---|
| **patch** | `Edit` exploit.py to fix HIGH findings → call judge again until clean. Up to ~3 rounds. |
| **proceed** | Findings are LOW/MED, or main judges a HIGH to be a false positive. End the turn; orchestrator runs the script. |
| **abort** | `Bash(rm -f ./exploit.py)` to delete the deliverable, write report.md explaining the block. Orchestrator detects the missing file and skips the runner. |

The orchestrator does **not** override main's decision. Two
backstops still run around the runner:

- **prejudge (advisory)** — runs *before* the container. Findings
  are recorded into `result.json` so the retry reviewer can
  reference them. **Never blocks** the run — main already
  owned the gate.
- **supervise** — single one-shot when output stalls 60 s while
  still alive. Same Claude session as prejudge (resumed via
  `session_id`), so judge sees its earlier findings while making
  the kill/continue call.
- **postjudge** — categorize the finished run as one of `success` /
  `partial` / `hung` / `parse_error` / `network_error` / `crash` /
  `timeout` / `unknown` and emit a retry-ready hint.

Three orchestrator stages share **one Claude session** (prejudge
captures `session_id`; supervise + postjudge resume via
`fork_session=False`).

Each judge stage is best-effort: a judge auth/rate/empty failure
degrades to permissive defaults (prejudge ok, supervise continue,
postjudge unknown) so the runner is never harder to use because of a
flaky judge call. All output prefixed `[judge]` in `run.log`.

Toggle in **Settings → Enable judge for auto-run** (default on); off
reverts to plain blocking wait + bare `exit_code`. The `judge`
subagent stays registered for main — the toggle only gates the
orchestrator's pre/super/post lifecycle wrapping.

### Auto-retry triangle

The analyzer runs main inside a single `ClaudeSDKClient` session, not
fire-and-forget `query()`. After main writes its draft and ends the
turn, the orchestrator runs the sandbox + judge stages — and on a
non-success postjudge verdict, **injects the retry_hint as a fresh
user turn back into the same SDK session** (`run_main_agent_session`
in `modules/_common.py`). Main reads it like any user follow-up,
patches the script, re-invokes the JUDGE GATE on the patched file,
and ends the turn again. Cache prefix preserved across the loop.

```
   main  ──draft──►  orchestrator  ──run──►  judge  ──verdict──┐
    ▲                                                          │
    │                                                          ▼
    └───── new user turn (retry_hint) ◄── postjudge!=success ──┘
```

Loop terminates on the FIRST hit among:
- flag captured / postjudge `verdict == "success"`
- postjudge produced no actionable retry_hint
- main's SDK session errored / hit `INVESTIGATION_BUDGET`
- `AUTO_RETRY_MAX` cap reached (when configured to a non-negative N)
- user pressed Stop / soft / hard timeout

### Fallback artifact safety net

When something stops main mid-run before it produced an artifact —
budget exhausted, OOM/SIGKILL, soft-eject ignored, subagent cap
exceeded, compaction ceiling crossed — the orchestrator does **not**
abort the job. Instead `write_fallback_artifacts(work_dir, log_fn)`
(in `modules/_common.py`) drops a probe-only `exploit.py` + a brief
`report.md` into the work dir, then **continues into the sandbox +
judge dispatch** as if main had finished normally. The job ends as
`no_flag` (or `partial` if the probe extracted something) instead of
`failed`, and postjudge's `retry_hint` is still emitted so a manual
`/retry` has actionable feedback.

The fallback exploit.py:
- loads `./.chal-libs/libc_profile.json` if present (so chal-libc-
  fix's structured glibc snapshot is preserved across the retry),
- connects to the remote target if one was passed via `argv[1]`,
- sends a single newline + reads back what the server prints,
- writes the response to stdout so the runner captures it.

It is intentionally **not** an exploit — it's a minimal scaffold
that keeps the sandbox+judge cycle traversed so the retry path has
data to work with. `write_fallback_artifacts` is idempotent: it
only writes files that don't already exist, so a partial drop (main
wrote exploit.py but not report.md) still gets a companion report.

`AUTO_RETRY_MAX` env var (default `-1` = unlimited). Set to `0` to
disable the loop, or to a positive int to cap. The natural exit
conditions above mean unlimited is usually safe — same retry_hint
back-to-back will quickly land on "no actionable hint" and stop.

### debugger (`modules/_common.py` `DEBUGGER_AGENT_PROMPT`)

Dynamic-analysis peer subagent. Main delegates to it whenever the
answer depends on observed runtime state rather than disasm —
canary values, leaked addresses, heap chunk layouts at a breakpoint,
which one_gadget actually fires given post-leak register state.

Workflow inside one debugger turn:

1. **`chal-libc-fix <bin>`** patches the binary's interpreter +
   RUNPATH so it loads the chal's bundled libc instead of the
   worker's system libc (Debian glibc 2.41 at the time of writing).
   Lookup priority:
   - explicit `--libs <dir>`,
   - any `Dockerfile COPY libc-* /…` referencing physical files,
   - any `lib/` / `libs/` / `glibc/` dir with `libc.so.6` + `ld-linux-*`,
   - **base-image fallback**: if none of the above hit and a
     Dockerfile `FROM` line is present, `docker pull` the base image
     and `docker run --rm -v <stage>:/out` to copy out
     `/lib*/libc.so.6` + `/lib64/ld-linux-*` + every `DT_NEEDED` SONAME
     (`readelf -d` the binary, then `ldconfig -p` inside the chal
     image to resolve each name → real path → `cp -L`). This is the
     common Dreamhack / HackTheBox pattern: bundle = `Dockerfile +
     prob`, libs only inside the base image.
2. **One of three gdb session shapes** (the prompt makes this
   explicit since the Bash tool is one-shot):
   - **Pattern A** — short `-ex` chain (≤5 commands).
   - **Pattern B (recommended)** — `gdb -batch -x /tmp/probe.py`
     where `probe.py` runs `gdb.execute(...)` in sequence, branches
     on `gdb.parse_and_eval("$reg")`, and uses GEF helpers
     (`heap chunks`, `vmmap`, `canary`, `pattern …`, `xinfo`). One
     gdb session, full programmatic control — the closest thing to
     interactive REPL the SDK supports.
   - **Pattern C** — `gdbserver` + multiple `gdb -batch` attaches when
     state must persist across Bash calls.
3. **Reply ≤2 KB** in the `OBSERVED / TRACE / CONCLUSION / CAVEATS`
   shape so main can paste the conclusion directly into its
   reasoning.

GEF (single-file modern gdb plugin) is auto-loaded via
`/etc/gdb/gdbinit`; `gdb -nx` disables it for plain gdb. Worker also
ships `gdb-multiarch`, `qemu-aarch64-static` / `qemu-arm-static` for
foreign-arch chals, `patchelf`, `strace`, `ltrace`.

## Agent architecture

For web / pwn / crypto / rev jobs, the **main worker** spins up a
multi-peer Claude agent team — main agent (writer) plus `recon` /
`judge` / `debugger` subagents. Each peer runs in its own `claude`
CLI subprocess (`Subagent isolation`, default ON):

```
   main agent (writer, Node #1)    recon (static, read-only, Node #2)
   ────────────────────────────    ──────────────────────────────────
   • drives reasoning              • libc symbol/offset lookup
   • writes exploit.py /           • decomp triage protocol
     solver.py / report.md           (FUNCTIONS + CANDIDATES)
   • Read/Write/Edit/Bash/         • ROPgadget / one_gadget filter
     Glob/Grep                     • returns ≤2 KB summary
   • + mcp__team__                 • subprocess dies on return
     spawn_subagent
   • single ClaudeSDKClient        judge (quality gate, Node #3)
     session (auto-retries on     ─────────────────────────────────
     postjudge feedback)          • pre-finalize hang/parse review
              │                   • orchestrator pre/supervise/post
              │ spawn               around the runner sandbox
              │                   • emits retry_hint that loops back
   mcp__team__spawn_subagent(       into main's session
     subagent_type="recon"        • pinned to LATEST_JUDGE_MODEL
     | "judge" | "debugger",      
     prompt="<q>",                debugger (dynamic state, Node #4)
   )                              ──────────────────────────────────
              │                   • chal-libc-fix base-image extract
              ▼                   • gdb (GEF) / strace / ltrace /
        compact summary             qemu-user gdbserver
                                  • OBSERVED/TRACE/CONCLUSION/CAVEATS
                                  • subprocess dies on return
```

Same model on the writer side and recon/debugger so cache prefixes
align across spawns (the new subprocess still gets prompt-cache hits
from prior identical system-prompt prefixes). Judge is pinned to
`LATEST_JUDGE_MODEL`. Each peer exists so its own working set lives
in its own subprocess — only the ≤2 KB summary lands back in main.
See [Subagent isolation](#subagent-isolation-default-on) for details.

All peers share the same Bash environment as `main`, so anything in
the worker image is reachable: cross-arch binutils
(`aarch64-linux-gnu-{objdump,readelf,nm}`, `arm-linux-gnueabi-*`),
`qemu-aarch64-static` / `qemu-arm-static` (for running foreign-arch
ELFs and `qemu-aarch64-static -g 1234` gdbserver), `gdb` / `gdb-multiarch`
(GEF auto-loaded), `strace`, `ltrace`, `patchelf`, `chal-libc-fix`,
`cpio`, `ROPgadget` with `capstone>=5`, `one_gadget`, `pwntools`,
`ghiant` (Ghidra-headless wrapper into `./decomp/`), `ghiant xrefs`
(cross-reference query against the cached Ghidra project), plus
`jq` / `xxd` / `7z`. The recon and debugger system prompts ship
copy-pasteable invocation guides grouped by intent.

**Ghiant project caching**: the first `ghiant <bin>` call decompiles
into `./decomp/*.c` AND saves the analyzed Ghidra project under
`<jobdir>/.ghidra_proj/` (~10s extra). All later `ghiant <bin>`
re-decomp calls and every `ghiant xrefs <bin> <sym|addr>` query
reuse that project — cold call ~14s, warm call ~7s on a small ELF.

**Decomp triage protocol**: when `./decomp/` is empty and raw disasm
is dense, main delegates a single recon call ("run ghiant if empty,
return FUNCTIONS inventory + ranked CANDIDATES with bug class +
file:line + NEXT recommendation, skip libc/Go-runtime helpers"), and
reads only the .c files recon flagged. Walking the whole 50-500 file
tree is reserved for recon; main does the narrow read.

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

Each module's SYSTEM_PROMPT opens with the **MISSION** stanza
(`mission_block()` in `modules/_common.py`) that tells the model up
front: write the deliverables to cwd, delegate STATIC investigation
to recon and DYNAMIC analysis to debugger, mandatory JUDGE GATE
before finalize, write a draft within ~10 tool calls, never
disassemble libc/framework internals, never re-slice saved disasm,
STOP if a Bash result starts with "Output too large (NNN MB)". Long
tool catalogues and module-specific workflows follow the mission
stanza, so the highest-signal guidance lands in the first few
hundred tokens. The pwn prompt also includes a glibc-version-keyed
heap/FSOP cheat-sheet with standard chain templates (FSOP
`_IO_wfile_jumps` overflow, tcache poison + safe-linking, house of
orange, etc.) so heap chals don't waste turns rediscovering common
facts; user descriptions matching heap/FSOP keywords additionally
get a step-by-step checklist injected into the user-turn that
points at `./.chal-libs/libc_profile.json` (structured glibc
feature flags emitted by `chal-libc-fix`), `/opt/scaffold/*.py`
(copy-paste exploit templates that auto-branch on those flags),
the `heap-probe` JSON-timeline gdb wrapper, and the
`failure_code` → `HEAP_FIX_HINTS` prescriptive-preamble path on
the auto-retry user turn. See the [Pwn](#pwn) module section for
the full pipeline.

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
   | `WORKER_MEM_LIMIT` | `14g` | cgroup memory cap on the worker. Sized so the main `claude` CLI Node.js heap has room to grow under a heap-pwn run + the isolated subagent subprocesses share the same container. Set to `0` to disable, or lower if your host has less RAM. |
   | `WORKER_MEMSWAP_LIMIT` | `18g` | total cgroup memory+swap. Default = `WORKER_MEM_LIMIT` + 4 GiB so the worker can spill to swap during transient context spikes without invoking the host OOM-killer. |
   | `JOB_TTL_DAYS` | `7` | auto-delete jobs older than N days (`0`=keep) |
   | `JOB_TIMEOUT` | `6000` | soft job timeout in seconds — see [Timeout & soft-deadline decision](#timeout--soft-deadline-decision) |
   | `WEB_PORT` | `8000` | host port |
   | `GHIDRA_VERSION` / `GHIDRA_BUILD_DATE` | `12.0.4` / `20260303` | Ghidra release used by decompiler image |
   | `ANTHROPIC_API_KEY` | empty | leave empty for OAuth |
   | `AUTH_TOKEN` | empty | shared token; empty = no auth (dev) |
   | `HOST_CLAUDE_HOME` | `${HOME}/.claude` | host path of Claude Code config |
   | `CLAUDE_CODE_MAX_OUTPUT_TOKENS` | `999999` | per-turn SDK output cap (the model's own ceiling, ~64k for Sonnet/Opus, becomes the effective limit) |
   | `INVESTIGATION_BUDGET` | `150` | tool-call budget for the main agent. At 80% (`SOFT_EJECT`) the orchestrator injects a "finalize now" user-turn; at 100% it triggers `FINAL_DRAFT` last-chance, then falls back to a probe-only skeleton via `write_fallback_artifacts` so sandbox + postjudge still runs. `0` disables. |
   | `ENABLE_JUDGE` | `1` | wrap every `auto_run` runner execution with the 3-stage judge (pre / stall-supervise / post). Set to `0` to skip judge calls entirely. See [judge](#judge-modules_judgepy). |
   | `AUTO_RETRY_MAX` | `-1` | postjudge-driven inline retries within a single job. `0` disables the loop (legacy fire-and-forget). Positive int caps at exactly N retries on top of the initial run. `-1` / `inf` / `unlimited` lets the loop run until natural exit (success, no actionable hint, error, user Stop, timeout). See [auto-retry triangle](#auto-retry-triangle). |
   | `USE_ISOLATED_SUBAGENTS` | `1` | when `1` (default), main delegates via the MCP tool `mcp__team__spawn_subagent` — each subagent runs in its own `claude` CLI subprocess and only the final-text reply lands in main's history. Set to `0` for the legacy in-process `agents={}` path (kept as a fast rollback). See [Subagent isolation](#subagent-isolation-default-on). |
   | `SUBAGENT_SPAWN_CAP` | `4` | hard cap on subagent delegations per run. Typical workflow uses `recon × 2 + debugger × 1 + judge × 1`. At `count == cap` a "no more spawns" user-turn is injected; at `count > cap` the receive loop breaks immediately and the fallback path runs. Set to `0` to disable. |
   | `CONTEXT_COMPACTION_THRESHOLD` | `6000000` | SOFT cache_read ceiling. When main's accumulated `cache_read_input_tokens` crosses this, the orchestrator injects a "finalize now, no further subagent spawns" user-turn. `0` disables both compaction guards. |
   | `CONTEXT_COMPACTION_HARD_CEILING` | `10000000` | HARD ceiling. Crossing this cleanly aborts main, writes fallback artifacts, runs sandbox + postjudge — designed to land below the worker `mem_limit` so OOM never fires inside the SDK. |

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
| PATCH | `/api/jobs/{id}/target` | update only `target_url` on the job's meta — no retry, no resume, no new job. Body `{"target": "<new>"}` (use `(none)` or `""` to clear). The next manual `/run` (and the default of any future `/retry`) picks up the new value. Audit-logged to `run.log`. |
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
- Per-job timeline: ~2–3 min initial decompile + Claude analysis time.
  Subsequent `ghiant` / `ghiant xrefs` calls reuse the cached Ghidra
  project under `<jobdir>/.ghidra_proj/` (~5–10s warm).
- Worker container ships cross-arch CLIs the agent expects from Bash:
  `aarch64-linux-gnu-{objdump,nm,readelf}`, `arm-linux-gnueabi-*`,
  `qemu-aarch64-static` / `qemu-arm-static`, `gdb` / `gdb-multiarch`
  with **GEF** auto-loaded (`/etc/gdb/gdbinit`; use `gdb -nx` to
  disable), `strace`, `ltrace`, `patchelf`, `cpio`, `ROPgadget`
  (`capstone>=5` so ARM64 gadget search returns hits), `one_gadget`,
  `pwn checksec`.
- **`ghiant xrefs <bin> <sym|addr>`** — cross-reference query against
  the cached Ghidra project. Returns JSON with every reference site
  (UNCONDITIONAL_CALL / DATA_READ / DATA_WRITE / etc.) — strictly
  better than grepping `./decomp/*.c` for an address since Ghidra
  knows the ref_type. Auto-bootstraps full analysis if the cache
  isn't present yet, so it's safe to call before `ghiant <bin>`.
- **`chal-libc-fix <bin>`** — patches the binary's interpreter +
  RUNPATH so it loads the chal's bundled libc instead of the
  worker's system libc. Auto-discovers libs from (1) `Dockerfile
  COPY libc-* /…` lines, (2) `lib/` / `libs/` / `glibc/` dirs in
  the bundle, (3) **the Dockerfile's `FROM` base image** (docker
  pulls + extracts `libc.so.6` + `ld-linux-*` + every `DT_NEEDED`
  SONAME via `ldconfig -p`). Critical for heap/FSOP analysis
  where offsets shift between glibc versions; the debugger
  subagent calls it automatically before any gdb session. Pass
  `--no-image` to skip the base-image fallback.
  **Also emits `./.chal-libs/libc_profile.json`** — a structured
  snapshot of `{version, version_tuple, arch, safe_linking,
  tcache_key, tcache_present, hooks_alive,
  io_str_jumps_finish_patched, preferred_fsop_chain,
  recommended_techniques, blacklisted_techniques, symbols,
  one_gadget}`. Main agent / judge / `exploit.py` all `json.load`
  this instead of re-deriving glibc-version facts from `strings`
  every retry. Recommended/blacklisted technique lists drive the
  matrix-based branching (e.g. `__free_hook` is blacklisted on
  glibc ≥ 2.34; `_IO_str_jumps __finish` on ≥ 2.37).
- **`/opt/scaffold/` exploit templates** for heap chals (copied
  into the worker image at build time):
  - `heap_menu.py` — menu-driven (alloc / free / edit / show)
    chal scaffold. `cp /opt/scaffold/heap_menu.py ./exploit.py`,
    then fill the prompt strings + exploit body. Auto-loads
    `libc_profile.json`, ships `safe_link()`, `assert_libc_base()`,
    `assert_heap_base()` helpers.
  - `fsop_wfile.py` — `_IO_FILE_plus` / `_IO_wide_data` /
    `_wide_vtable` builders for glibc ≥ 2.34 FSOP. Encodes the
    "vtable LAST" invariant by returning the body with the
    vtable slot zeroed — caller flips the vtable pointer
    separately AFTER the rest of the chain is in place.
  - `tcache_poison.py` — `safe_link()` / `alignment_ok()` /
    `needs_key_bypass()` / `assert_techniques_match()` — auto-
    branches on `safe_linking` / `tcache_key` from the profile.
  - `aslr_retry.py` — `aslr_retry(exploit_one, max_attempts=64)`
    + `expected_attempts_for(success_rate)` for nibble-race
    chains (typical 1/16 success → ~72 attempts).
- **`heap-probe <bin> --break <bp> --dump tcache,fastbin,unsorted,chunks`**
  — gdb-batch harness that emits a JSON timeline of heap state at
  each breakpoint hit. Standardizes the "alloc a few, free a few,
  inspect tcache" recipe so the debugger subagent doesn't re-roll
  the gdb session every call. JSON shape:
  `{events: [{pc, function, hit, dumps: {tcache, fastbin, …}}, …]}`.
  Use `--gdb gdb-multiarch` for aarch64/arm.
- **pwndbg opt-in**: image build defaults to `INSTALL_PWNDBG=1`,
  installing pwndbg alongside GEF at `/opt/pwndbg/`. Switch at
  runtime via `GDB_USE_PWNDBG=1 gdb …` (otherwise GEF auto-loads).
  Use `--build-arg INSTALL_PWNDBG=0` if you want a leaner image.
- **`scaffold.aslr_retry` + `heap-probe` + spawn hygiene** —
  `DEBUGGER_AGENT_PROMPT` mandates AT MOST ONE inferior process
  alive at a time (`pkill -9 -f ./prob; pkill -9 -f gdbserver`
  before any new spawn). Combined with **subagent isolation** (each
  delegation runs in its own `claude` CLI subprocess, see
  [Subagent isolation](#subagent-isolation-default-on)) and the
  worker's mem/memswap cgroup limits, this prevents the OOM-on-
  delegation failure mode that historically killed long heap runs
  with `exit code -9`.
- **Decompile-vs-assembly workflow** (WORKFLOW step 3.5 in
  `modules/pwn/prompts.py`): for heap / int-overflow / signedness
  / OOB-index chals, *primitive validation* is mandatory before
  writing exploit code. Recon's CANDIDATES output now carries a
  `verify: objdump -d …` line per HIGH/MED candidate of those bug
  classes; main MUST run that disasm to confirm `movzx`/`movsx`,
  `lea` scale+displacement, `cmp`+`jXX` predicate, and C++ vtable
  slot number before locking in the primitive. Skipping this step
  is the documented cause of the 1d00be30d4e9 / a914ca943ed2
  failures (decompile said `int idx`, real code was unsigned,
  sentinel byte pattern wrong, all one_gadget retries SIGSEGV'd).
- **Postjudge `failure_code` classification** for heap chals (13
  codes: `heap.libc_version_mismatch`, `unaligned_libc_base`,
  `safe_linking_missing`, `safe_linking_misapplied`,
  `hook_on_modern_libc`, `str_finish_patched`,
  `vtable_write_order_violated`, `tcache_key_not_bypassed`,
  `aslr_unstable`, `unaligned_tcache_target`,
  `whitespace_in_address`, `interactive_in_sandbox`,
  `unbounded_recv`). When postjudge emits one, the orchestrator
  prepends a deterministic prescriptive fix snippet
  (`HEAP_FIX_HINTS` in `modules/_common.py`) ahead of the model-
  authored `retry_hint` in the next auto-retry user turn, so the
  fix is harder for main to phrase away.
- **C++ binaries**: full Ghidra demangler (`/opt/ghidra/GPL/DemanglerGnu`)
  + `c++filt` + `nm -C` / `objdump -d -C`. Decompiled output uses
  unmangled names (`MyClass::method()` not `_ZN7MyClass…`).
- **Go binaries**: Ghidra 12 ships Go runtime type databases for Go
  1.15–1.23 — ghiant decompiles named or stripped Go binaries with
  function/type recovery automatically. Plus `redress` (amd64 only)
  for first-pass triage: `redress info <bin>` reads Go version +
  module + package counts via pclntab, `redress packages`
  / `types` / `source` for deeper recovery.
- **Dynamic analysis** for foreign-arch ELFs:
  `qemu-aarch64-static -g 1234 ./bin/x &` followed by
  `gdb-multiarch -batch -ex 'set arch aarch64' -ex 'target remote
  :1234' -ex 'b *0x...' -ex 'continue' …` — the debugger subagent
  uses this pattern to break/inspect inside QEMU-user without a
  full system VM.

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

Two flavors:

1. **Inline auto-retry** (no user click) — driven by postjudge inside
   the same job. See [Auto-retry triangle](#auto-retry-triangle). Cap
   via `AUTO_RETRY_MAX` env (default unlimited). The same SDK session
   is reused, so cache prefix is preserved across retries.
2. **User-triggered retry / resume** — described below. Spawns a NEW
   job (new id, new RQ enqueue) and forks the prior SDK session.

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
  `DONE` (light blue) · `AGENT_ERROR` / `ERROR` (red bold) ·
  `BUDGET_ABORT` / `RUNAWAY_OUTPUT` (amber, raised) · system notes
  (dim italic). Each line also gets an **agent tag chip** indicating
  who emitted it: `main` (purple), `recon` (orange), `judge` (green),
  `debugger` (blue) — subagent lines additionally indented with a `↳`
  so a delegation reads visually like a nested call. Isolated
  subagents include a per-spawn index in the chip
  (`recon#1`, `debugger#2`, …) so multiple delegations to the same
  role are visually distinct.
- **UTC ↔ Local timestamp toggle**. Run-log titlebar has a button
  flipping `[HH:MM:SS]` between UTC (default, what the orchestrator
  writes to disk) and the user's local timezone. Choice persists in
  `localStorage`; multi-day jobs handle midnight rollover by
  anchoring on `meta.started_at`.
- **Runaway-output guard**. When a Bash result starts with "Output
  too large (NNN MB)" — typical when the binary loops on its prompt
  past stdin EOF — an explicit `RUNAWAY_OUTPUT detected (NNN MB)`
  warning line is appended to run.log and rendered in amber. The
  agent's system prompt also tells it to STOP and re-examine the
  command (`| head -c 65536`, `| head -200`, `| grep -m1 PATTERN`)
  rather than acting on the truncated 2 KB preview.
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
