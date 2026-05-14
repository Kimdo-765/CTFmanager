#!/usr/bin/env bash
# Live job status line — refreshes in place every 2s.
#   Usage:  scripts/job-status.sh <job_id>
# Example: scripts/job-status.sh 4bc4ad56ecfd
set -e
JOB=${1:?usage: job-status.sh <job_id>}
API=${API:-http://localhost:8000}

prev_out=0
prev_in=0
prev_cache=0
prev_log_bytes=0
t_start=$(date +%s)

while :; do
    meta=$(curl -s "$API/api/jobs/$JOB") || { echo; echo "API unreachable"; exit 1; }
    log_bytes=$(curl -s "$API/api/jobs/$JOB/file/run.log" | wc -c)

    read status stage turns ein cac eout cost worker <<<"$(echo "$meta" | python3 -c '
import sys, json
d = json.load(sys.stdin)
t = d.get("agent_tokens") or {}
print(
    d.get("status","-"),
    d.get("stage","-"),
    d.get("agent_turns") or 0,
    t.get("input_tokens", 0),
    t.get("cache_read_input_tokens", 0),
    t.get("output_tokens", 0),
    d.get("cost_usd") or 0,
    d.get("rq_worker_name","-"),
)
')"

    now=$(date +%s)
    elapsed=$((now - t_start))
    d_out=$((eout - prev_out))
    d_in=$((cac - prev_cache))
    d_log=$((log_bytes - prev_log_bytes))
    prev_out=$eout; prev_in=$ein; prev_cache=$cac; prev_log_bytes=$log_bytes

    # Format: status · stage · turns · ↑cached ↓out (Δ delta) · log Δ · cost · worker
    printf "\r\033[K%s · %s · t=%d · ↑cache=%s (+%d) ↓out=%s (+%d) · log+%dB · \$%.4f · %s · %ds   " \
        "$status" "$stage" "$turns" "$cac" "$d_in" "$eout" "$d_out" "$d_log" "$cost" "$worker" "$elapsed"

    [ "$status" = "finished" ] || [ "$status" = "failed" ] || [ "$status" = "no_flag" ] && { echo; break; }
    sleep 2
done
