const API = "/api";

// Catalog of Claude models offered in every Analyze form. Add new
// snapshot/alias names here to expose them. Empty value = "use the
// global Settings model".
const CLAUDE_MODELS = [
  // Aliases (Anthropic recommends pinning to dated snapshots in production)
  "claude-opus-4-7",
  "claude-opus-4-1",
  "claude-opus-4",
  "claude-sonnet-4-6",
  "claude-sonnet-4-5",
  "claude-sonnet-4",
  "claude-haiku-4-5",
  "claude-haiku-4",
  // Dated snapshots (most stable for reproducible runs)
  "claude-opus-4-7-20251205",
  "claude-opus-4-1-20250805",
  "claude-sonnet-4-6-20251119",
  "claude-sonnet-4-5-20250929",
  "claude-sonnet-4-20250514",
  "claude-haiku-4-5-20251001",
  "claude-3-7-sonnet-latest",
  "claude-3-5-sonnet-20241022",
  "claude-3-5-haiku-20241022",
];

function fillModelSelects() {
  // Per-job selects: empty = "default from Settings"
  document.querySelectorAll('[data-role="model-select"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const m of CLAUDE_MODELS) sel.appendChild(new Option(m, m));
  });
  // Global Settings select: no empty entry, but a leading blank means
  // "no override saved". Actual current value populated by loadSettings().
  document.querySelectorAll('[data-role="model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of CLAUDE_MODELS) sel.appendChild(new Option(m, m));
  });
}

let selectedJob = null;
let pollTimer = null;

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    if (t.disabled) return;
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    document.getElementById(`panel-${t.dataset.tab}`).classList.add("active");
  });
});

async function submitJob(form, endpoint) {
  const fd = new FormData(form);
  for (const cb of form.querySelectorAll('input[type="checkbox"]')) {
    fd.set(cb.name, cb.checked ? "true" : "false");
  }
  // Drop empty optional fields so backend uses its default.
  const to = fd.get("job_timeout");
  if (to === "" || to == null) fd.delete("job_timeout");
  const model = fd.get("model");
  if (model === "" || model == null) fd.delete("model");

  const res = await fetch(`${API}${endpoint}`, { method: "POST", body: fd });
  if (!res.ok) {
    alert(`error: ${res.status} ${await res.text()}`);
    return;
  }
  const data = await res.json();
  await refreshJobs();
  selectJob(data.job_id);
}

document.getElementById("web-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/web/analyze");
});
document.getElementById("pwn-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/pwn/analyze");
});
document.getElementById("forensic-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/forensic/collect");
});
document.getElementById("misc-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/misc/analyze");
});
document.getElementById("crypto-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/crypto/analyze");
});
document.getElementById("rev-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/rev/analyze");
});

async function loadSettings() {
  const res = await fetch(`${API}/settings`);
  if (!res.ok) return;
  const s = await res.json();
  const f = document.getElementById("settings-form");
  const modelSel = f.querySelector("[name=claude_model]");
  const modelCustom = f.querySelector("[name=claude_model_custom]");
  const cur = s.claude_model || "";
  // If the saved value is one we know, select it; otherwise stash it
  // in the custom-text input so the user can see/edit it.
  if (CLAUDE_MODELS.includes(cur)) {
    modelSel.value = cur; modelCustom.value = "";
  } else {
    modelSel.value = ""; modelCustom.value = cur;
  }
  f.querySelector("[name=job_ttl_days]").value =
    s.job_ttl_days != null ? s.job_ttl_days : "";
  f.querySelector("[name=job_timeout_seconds]").value =
    s.job_timeout_seconds != null ? s.job_timeout_seconds : "";
  f.querySelector("[name=worker_concurrency]").value =
    s.worker_concurrency != null ? s.worker_concurrency : "";
  f.querySelector("[name=callback_url]").value = s.callback_url || "";
  document.getElementById("key-status").textContent = s.anthropic_api_key_set
    ? `set (${s.anthropic_api_key_masked}) — leave blank to keep, type new to replace`
    : (s.anthropic_api_key_env_set ? "using ANTHROPIC_API_KEY from env" : "not set");
  document.getElementById("oauth-status").textContent = s.claude_oauth_detected
    ? "✓ Claude Code OAuth detected — works without API key"
    : "✗ no OAuth credentials — run `claude login` on the host";
  document.getElementById("oauth-status").style.color = s.claude_oauth_detected ? "#3fb950" : "#8b949e";
  document.getElementById("auth-status").textContent = s.auth_token_set
    ? `set (${s.auth_token_masked})`
    : (s.auth_token_env_set ? "using AUTH_TOKEN from env" : "not set (auth disabled)");
}

document.getElementById("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  // Custom-text overrides the dropdown for claude_model.
  const custom = (fd.get("claude_model_custom") || "").toString().trim();
  if (custom) fd.set("claude_model", custom);
  fd.delete("claude_model_custom");

  const payload = {};
  for (const [k, v] of fd.entries()) {
    if (v === "" && (k === "anthropic_api_key" || k === "auth_token")) {
      // Empty secret field: skip — keep current value
      continue;
    }
    if (v === "") {
      payload[k] = null;  // null = clear the override
      continue;
    }
    if (k === "job_ttl_days" || k === "job_timeout_seconds" || k === "worker_concurrency") {
      payload[k] = Number(v);
    } else {
      payload[k] = v;
    }
  }
  const res = await fetch(`${API}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    alert(`save failed: ${res.status} ${await res.text()}`);
    return;
  }
  // Clear secret fields after save
  e.target.querySelector("[name=anthropic_api_key]").value = "";
  e.target.querySelector("[name=auth_token]").value = "";
  await loadSettings();
  alert("Saved. Changes apply to the next job.");
});

document.getElementById("settings-reload").addEventListener("click", loadSettings);

// Load settings whenever the user clicks the Settings tab
document.querySelector('.tab[data-tab="settings"]').addEventListener("click", loadSettings);

document.getElementById("refresh-jobs").addEventListener("click", () => {
  refreshJobs(); refreshStats();
});

document.getElementById("bulk-delete").addEventListener("click", async () => {
  const filter = document.getElementById("bulk-filter").value;
  let url = `${API}/jobs`;
  let label;
  if (filter === "__all__") {
    if (!confirm("Delete ALL jobs (including queued/running)?\nRunning jobs will be cancelled.")) return;
    url += "?all=true";
    label = "ALL jobs";
  } else if (filter === "") {
    if (!confirm("Delete all finished + failed jobs?")) return;
    label = "finished + failed jobs";
  } else {
    if (!confirm(`Delete all jobs with status="${filter}"?`)) return;
    url += `?status=${encodeURIComponent(filter)}`;
    label = `jobs with status=${filter}`;
  }
  const res = await fetch(url, { method: "DELETE" });
  if (!res.ok) {
    alert(`bulk delete failed: ${res.status} ${await res.text()}`);
    return;
  }
  const r = await res.json();
  alert(`Deleted ${r.deleted} ${label}${r.skipped ? ` (skipped ${r.skipped})` : ""}.`);
  if (selectedJob && r.ids && r.ids.includes(selectedJob)) {
    _closeJobModal();
  }
  await refreshJobs();
  await refreshStats();
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/logout", { method: "POST" });
  location.href = "/login";
});

async function refreshStats() {
  try {
    const [statsRes, queueRes] = await Promise.all([
      fetch(`${API}/jobs/stats`),
      fetch(`${API}/jobs/queue`),
    ]);
    if (statsRes.ok) {
      const s = await statsRes.json();
      const el = document.getElementById("cost-total");
      el.textContent = `$${(s.total_cost_usd || 0).toFixed(3)} · ${s.count} jobs`;
      el.title = "by module: " + Object.entries(s.by_module || {})
        .map(([m, v]) => `${m}=${v.count} ($${v.cost_usd.toFixed(3)})`).join(", ");
    }
    if (queueRes.ok) {
      const q = await queueRes.json();
      const qe = document.getElementById("queue-info");
      qe.textContent = `${q.workers_busy}/${q.workers_total} workers · ${q.queued} queued`;
      qe.title = (q.workers || []).map(w =>
        `${w.name}: ${w.state}${w.job_id ? " (" + w.job_id + ")" : ""}`
      ).join("\n") || "no workers";
    }
  } catch (_) {}
}

async function deleteJob(id, ev) {
  ev.stopPropagation();
  if (!confirm(`Delete job ${id}?`)) return;
  await fetch(`${API}/jobs/${id}`, { method: "DELETE" });
  if (selectedJob === id) {
    _closeJobModal();
  }
  refreshJobs();
  refreshStats();
}

async function decideTimeout(jobId, decision, btn) {
  // Disable both decision buttons in the same banner
  const banner = btn.closest(".timeout-banner");
  if (banner) banner.querySelectorAll("button").forEach((b) => (b.disabled = true));
  const orig = btn.textContent;
  btn.textContent = decision === "continue" ? "▶ continuing…" : "■ stopping…";
  try {
    const res = await fetch(`${API}/jobs/${jobId}/timeout/${decision}`, { method: "POST" });
    if (!res.ok) {
      const body = await res.text();
      alert(`timeout/${decision} failed: ${res.status} ${body}`);
      if (banner) banner.querySelectorAll("button").forEach((b) => (b.disabled = false));
      btn.textContent = orig;
      return;
    }
    // Refresh the job view; meta.awaiting_decision should now be false
    // (and on 'kill', status flips to 'failed').
    await refreshJobs();
    await selectJob(jobId);
  } catch (e) {
    alert(`timeout/${decision} error: ${e}`);
    if (banner) banner.querySelectorAll("button").forEach((b) => (b.disabled = false));
    btn.textContent = orig;
  }
}

async function streamRetry(jobId, btn, manualHint = null, opts = {}) {
  // Endpoint can be /retry/stream (default) or /resume/stream — same SSE
  // protocol either way, only the stage labels differ.
  const endpoint = opts.endpoint || `${API}/jobs/${jobId}/retry/stream`;
  const flow = opts.flow || "retry";   // "retry" | "resume"
  const flowVerb = flow === "resume" ? "resume" : "retry";
  const flowEmoji = flow === "resume" ? "✋" : "↻";

  // Disable every retry button on the detail panel — only one path runs.
  const allRetryBtns = document.querySelectorAll(
    `#job-detail .retry-btn, #job-detail .retry-manual-submit, #job-detail .stop-resume-submit`,
  );
  allRetryBtns.forEach((b) => (b.disabled = true));
  const origText = btn.textContent;
  btn.textContent = `⏳ ${flowVerb}…`;
  const isManual = typeof manualHint === "string" && manualHint.length > 0;

  // Stop the regular polling so it doesn't fight our progress panel
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  // Tear down any in-flight inline form so it doesn't linger.
  const manualForm = document.getElementById("retry-manual-form-" + jobId);
  if (manualForm) manualForm.remove();
  const resumeForm = document.getElementById("stop-resume-form-" + jobId);
  if (resumeForm) resumeForm.remove();

  // Insert a live progress panel right above the run-log heading
  const detail = document.getElementById("job-detail");
  const panel = document.createElement("div");
  panel.className = "retry-panel";
  panel.id = "retry-panel-" + jobId;
  const headerText = isManual
    ? `${flowEmoji} ${flow === "resume" ? "Resume" : "Retry"} — your hint`
    : `${flowEmoji} ${flow === "resume" ? "Resume" : "Retry"} — reviewer in progress`;
  panel.innerHTML = `
    <h4>${headerText}</h4>
    <div class="stage"><span class="dot"></span><span class="stage-text">${isManual ? "submitting…" : "starting…"}</span></div>
    <pre class="hint-stream"></pre>
  `;
  // Place panel before the runBlock area (just under the meta line)
  const flagBanner = detail.querySelector(".flag-banner");
  const refNode = flagBanner || detail.querySelector(".file-links") || detail.querySelector("h4");
  if (refNode) refNode.parentNode.insertBefore(panel, refNode);
  else detail.appendChild(panel);

  const stageEl = panel.querySelector(".stage-text");
  const streamEl = panel.querySelector(".hint-stream");
  // Manual hint: show it immediately. Reviewer hint: wait for the first token.
  let firstToken = !isManual;
  if (isManual) streamEl.textContent = manualHint;
  else streamEl.textContent = "(awaiting reviewer output…)";

  // EventSource only supports GET. Use fetch + ReadableStream to POST + stream.
  const fetchOpts = { method: "POST" };
  if (isManual) {
    fetchOpts.headers = { "Content-Type": "application/json" };
    fetchOpts.body = JSON.stringify({ hint: manualHint });
  }

  let resp;
  try {
    resp = await fetch(endpoint, fetchOpts);
  } catch (e) {
    streamEl.textContent = "[err] " + e;
    allRetryBtns.forEach((b) => (b.disabled = false));
    btn.textContent = origText;
    return;
  }
  if (!resp.ok) {
    const body = await resp.text();
    streamEl.textContent = `[err] ${resp.status}: ${body}`;
    allRetryBtns.forEach((b) => (b.disabled = false));
    btn.textContent = origText;
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buf = "";

  function handleEvent(name, dataStr) {
    let data = {};
    try { data = JSON.parse(dataStr); } catch (_) {}
    if (name === "stage") {
      const s = data.name;
      stageEl.textContent = ({
        halting: "halting current job…",
        gathering: "gathering prior job context…",
        asking: "asking reviewer (Opus 4.7)…",
        submitting: isManual
          ? (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/) with your hint…"
              : "enqueueing new job with your hint…")
          : (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/)…"
              : "enqueueing new job…"),
      })[s] || s;
    } else if (name === "token") {
      if (firstToken) { streamEl.textContent = ""; firstToken = false; }
      streamEl.textContent += data.delta || "";
      streamEl.scrollTop = streamEl.scrollHeight;
    } else if (name === "done") {
      panel.querySelector(".dot").style.animation = "none";
      panel.querySelector(".dot").style.background = "#56d364";
      stageEl.textContent = `submitted new job ${data.new_job_id}`;
      // Switch to the new job after a beat so user can read the hint
      allRetryBtns.forEach((b) => (b.disabled = false));
      btn.textContent = origText;
      setTimeout(async () => {
        await refreshJobs();
        await selectJob(data.new_job_id);
      }, 800);
    } else if (name === "error") {
      const dot = panel.querySelector(".dot");
      dot.style.background = "#f85149";
      dot.style.animation = "none";
      panel.classList.add("retry-panel-error");
      const headerEl = panel.querySelector("h4");
      if (headerEl) headerEl.textContent =
        `${flowEmoji} ${flow === "resume" ? "Resume" : "Retry"} — error (no new job created)`;
      const kind = data.kind || "error";
      const kindLabel = ({
        api_error: "API error",
        auth: "auth error",
        rate_limit: "rate limit",
        policy_refusal: "usage-policy refusal",
        timeout: "timeout",
        empty: "empty response",
        no_context: "no prior context",
        gather: "context gather failed",
        halt: "stop failed",
        submit: "submit rejected",
        unknown: "unknown error",
      })[kind] || kind;
      stageEl.textContent = `${kindLabel} — ${flowVerb} aborted`;
      const errMsg = (data.message || "unknown error").trim();
      // If the reviewer streamed partial text before erroring, keep it as
      // forensic context above the error block. Otherwise just show error.
      if (firstToken) {
        streamEl.textContent = errMsg;
      } else {
        streamEl.textContent += `\n\n--- ${kindLabel} ---\n${errMsg}`;
      }
      streamEl.scrollTop = streamEl.scrollHeight;
      allRetryBtns.forEach((b) => (b.disabled = false));
      btn.textContent = origText;
    }
  }

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    // SSE frames are separated by blank lines
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const frame = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let evName = "message";
      let dataLines = [];
      for (const line of frame.split("\n")) {
        if (line.startsWith("event: ")) evName = line.slice(7).trim();
        else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
      }
      if (dataLines.length) handleEvent(evName, dataLines.join("\n"));
    }
  }
}

function openStopResumeForm(jobId, anchorBtn) {
  // If a form is already open for this job, just refocus it.
  const existing = document.getElementById("stop-resume-form-" + jobId);
  if (existing) {
    existing.querySelector("textarea")?.focus();
    return;
  }
  const form = document.createElement("div");
  form.className = "retry-manual-form stop-resume-form";
  form.id = "stop-resume-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Extra hint to add before resuming</label>
    <textarea rows="5" placeholder="What should the next attempt do differently? e.g. 'the leaked endpoint is /api/v2/profile, not /profile' — appended to the new job's description as [retry-hint]"></textarea>
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit stop-resume-submit">✋ Stop &amp; resume</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Halts this job, then enqueues a fresh one with the same files + hint appended</small>
    </div>
  `;
  const buttonRow = anchorBtn.parentElement;
  buttonRow.insertAdjacentElement("afterend", form);

  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".stop-resume-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();

  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", async () => {
    const hint = ta.value.trim();
    if (!hint) {
      ta.focus();
      ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    submit.disabled = true;
    cancel.disabled = true;
    const orig = submit.textContent;
    submit.textContent = "⏳ stopping & resuming…";
    // Stop polling so it doesn't fight the upcoming selectJob call.
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    try {
      const res = await fetch(`${API}/jobs/${jobId}/resume`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hint }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body);
        alert(`stop-and-resume failed: ${res.status} ${detail}`);
        submit.disabled = false; cancel.disabled = false;
        submit.textContent = orig;
        return;
      }
      form.remove();
      await refreshJobs();
      await selectJob(body.new_job_id);
    } catch (e) {
      alert(`stop-and-resume error: ${e}`);
      submit.disabled = false; cancel.disabled = false;
      submit.textContent = orig;
    }
  });
  ta.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      submit.click();
    } else if (e.key === "Escape") {
      e.preventDefault();
      form.remove();
    }
  });
}

function openManualHintForm(jobId, anchorBtn) {
  // If a form is already open for this job, just refocus it.
  const existing = document.getElementById("retry-manual-form-" + jobId);
  if (existing) {
    existing.querySelector("textarea")?.focus();
    return;
  }
  const form = document.createElement("div");
  form.className = "retry-manual-form";
  form.id = "retry-manual-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Your hint for the next agent</label>
    <textarea rows="5" placeholder="e.g. The bot visits /report?id= and the cookie is on .site.com — exfiltrate via document.cookie to \$COLLECTOR_URL. Or: the heap leak comes from the formatted error on /api/echo, not /api/profile."></textarea>
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit">Submit hint &amp; retry</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Skips reviewer · appended to new job's description as <code>[retry-hint]</code></small>
    </div>
  `;
  // Place the form right after the button row.
  const buttonRow = anchorBtn.parentElement;
  buttonRow.insertAdjacentElement("afterend", form);

  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".retry-manual-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();

  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", () => {
    const hint = ta.value.trim();
    if (!hint) {
      ta.focus();
      ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    streamRetry(jobId, submit, hint);
  });
  // Ctrl/Cmd+Enter shortcut
  ta.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      submit.click();
    } else if (e.key === "Escape") {
      e.preventDefault();
      form.remove();
    }
  });
}

async function refreshJobs() {
  const res = await fetch(`${API}/jobs`);
  const data = await res.json();
  const ul = document.getElementById("jobs-list");
  ul.innerHTML = "";
  for (const job of data.jobs) {
    const li = document.createElement("li");
    li.dataset.id = job.id;
    const cost = job.cost_usd ? `· $${Number(job.cost_usd).toFixed(3)}` : "";
    const flagPill = (job.flags && job.flags.length)
      ? `<span class="flag-pill" title="${escapeHtml(job.flags.join('\n'))}">🚩 ${job.flags.length}</span>` : "";
    li.innerHTML = `<strong>${job.module}</strong> · ${escapeHtml(job.filename || "")}
      <span class="status ${job.status}">${job.status}</span>${flagPill}
      <button class="delete-btn">×</button>
      <div style="font-size:0.75rem;color:#8b949e;">${job.id} ${cost}</div>`;
    li.addEventListener("click", () => selectJob(job.id));
    li.querySelector(".delete-btn").addEventListener("click", (e) => deleteJob(job.id, e));
    if (job.id === selectedJob) li.classList.add("selected");
    ul.appendChild(li);
  }
}

async function selectJob(id) {
  selectedJob = id;
  document.querySelectorAll("#jobs-list li").forEach((li) => {
    li.classList.toggle("selected", li.dataset.id === id);
  });
  _openJobModal(id);
  await renderJob(id, { force: true });
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const job = await renderJob(id);
    if (job && ["finished", "failed", "no_flag"].includes(job.status)) {
      clearInterval(pollTimer);
      pollTimer = null;
      await refreshJobs();
      await refreshStats();
    }
  }, 2000);
}

function _openJobModal(id) {
  const m = document.getElementById("job-modal");
  if (!m) return;
  const title = m.querySelector(".job-modal-title");
  if (title) title.textContent = `Job ${id}`;
  m.hidden = false;
  // Lock background scroll while the modal is open.
  document.body.classList.add("modal-open");
}

function _closeJobModal() {
  const m = document.getElementById("job-modal");
  if (m) m.hidden = true;
  document.body.classList.remove("modal-open");
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  selectedJob = null;
  document.querySelectorAll("#jobs-list li").forEach((li) =>
    li.classList.remove("selected"),
  );
  // Wipe the detail body so a stale render doesn't flash on the next open.
  const detail = document.getElementById("job-detail");
  if (detail) detail.innerHTML = "";
}

async function renderJob(id, opts = {}) {
  const detail = document.getElementById("job-detail");
  // If the user is actively typing in an inline form (manual retry hint
  // or stop-and-resume hint), the 2-second polling re-render would blow
  // it away mid-keystroke. Skip this poll cycle. selectJob() passes
  // {force:true} so explicit job switches still re-render.
  if (
    !opts.force
    && detail.querySelector(".retry-manual-form, .stop-resume-form")
  ) {
    return null;
  }
  const res = await fetch(`${API}/jobs/${id}`);
  if (!res.ok) {
    detail.textContent = "job not found";
    return null;
  }
  const job = await res.json();

  // Cap the polling fetch at 256 KB so verbose Claude output (after a
  // big Read or Bash dump) doesn't make every 2s poll re-ship megabytes.
  const logRes = await fetch(`${API}/jobs/${id}/log?tail=262144`);
  const log = await logRes.text();

  // Preserve log scroll position across re-renders. If the user was already
  // at (or near) the bottom, snap to bottom after re-render so new entries
  // are visible (tail behavior). Otherwise keep their scroll position.
  const prevPre = detail.querySelector("pre.run-log");
  const prevAtBottom = prevPre
    ? (prevPre.scrollTop + prevPre.clientHeight >= prevPre.scrollHeight - 12)
    : true;
  const prevScrollTop = prevPre ? prevPre.scrollTop : 0;
  const isSameJob = prevPre && prevPre.dataset.jobId === id;

  // File-link helper. Left-click opens the syntax-highlighting preview
  // modal; middle-click / Ctrl+click / right-click "Open in new tab" still
  // gets the raw response since the underlying href is the API URL.
  const fileLink = (label, url, name) =>
    `<a href="${url}" target="_blank" class="file-preview-link"
        data-url="${url}" data-name="${escapeHtml(name)}">${escapeHtml(label)}</a>`;

  let resultBlock = "";
  if (["finished", "running", "no_flag"].includes(job.status)) {
    const links = [
      fileLink("result.json", `${API}/jobs/${id}/result`, "result.json"),
      fileLink("report.md", `${API}/jobs/${id}/file/report.md`, "report.md"),
    ];
    if (job.module === "web" || job.module === "pwn") {
      links.push(fileLink("exploit.py", `${API}/jobs/${id}/file/exploit.py`, "exploit.py"));
      links.push(fileLink("stdout", `${API}/jobs/${id}/file/exploit.py.stdout`, "exploit.py.stdout"));
      links.push(fileLink("stderr", `${API}/jobs/${id}/file/exploit.py.stderr`, "exploit.py.stderr"));
    }
    if (job.module === "crypto" || job.module === "rev") {
      links.push(fileLink("solver.py", `${API}/jobs/${id}/file/solver.py`, "solver.py"));
      links.push(fileLink("stdout", `${API}/jobs/${id}/file/solver.py.stdout`, "solver.py.stdout"));
      links.push(fileLink("stderr", `${API}/jobs/${id}/file/solver.py.stderr`, "solver.py.stderr"));
    }
    if (job.module === "forensic") {
      links.push(fileLink("summary.json", `${API}/jobs/${id}/file/summary.json`, "summary.json"));
      links.push(fileLink("log_findings.json", `${API}/jobs/${id}/file/log_findings.json`, "log_findings.json"));
      links.push(fileLink("collector.log", `${API}/jobs/${id}/file/collector.log`, "collector.log"));
    }
    if (job.module === "misc") {
      links.push(fileLink("findings.json", `${API}/jobs/${id}/file/findings.json`, "findings.json"));
      links.push(fileLink("analyze.log", `${API}/jobs/${id}/file/analyze.log`, "analyze.log"));
    }
    links.push(`<a href="/terminal?job_id=${encodeURIComponent(id)}" target="_blank">⌨ open terminal</a>`);
    resultBlock = `<div class="file-links">${links.join(" ")}</div>`;
  }

  const cost = job.cost_usd ? ` · cost: $${Number(job.cost_usd).toFixed(4)}` : "";
  const stage = job.stage ? ` · stage: ${job.stage}` : "";
  const timeout = job.job_timeout ? ` · timeout: ${job.job_timeout}s` : "";
  const modelInfo = job.model ? ` · model: ${escapeHtml(job.model)}` : "";

  // Soft-timeout decision banner. Fires when the worker's wall-clock
  // watchdog sets meta.awaiting_decision=true. The agent is still running
  // — the user picks Continue (let it run) or Stop (hard-kill).
  let timeoutBlock = "";
  if (job.awaiting_decision) {
    const at = job.decision_at ? new Date(job.decision_at).toLocaleTimeString() : "";
    const budget = job.soft_timeout_s || job.job_timeout || "?";
    timeoutBlock = `<div class="timeout-banner" data-job-id="${id}">
      <h4>⏰ Soft timeout reached${at ? ` at ${escapeHtml(at)}` : ""}</h4>
      <div class="timeout-msg">
        The agent has been running for ~${escapeHtml(String(budget))}s and is still working.
        It will keep running until you decide. Pick one:
      </div>
      <div class="timeout-actions">
        <button class="timeout-continue-btn" data-action="continue">▶ Continue running</button>
        <button class="timeout-kill-btn" data-action="kill">■ Stop now</button>
      </div>
    </div>`;
  }

  // Description block: render the original description and any appended
  // `[retry-hint]` segment in a separate, color-coded chip so the user can
  // see at a glance which run is a retry and what hint was used.
  let descBlock = "";
  const rawDesc = (job.description || "").trim();
  if (rawDesc) {
    const marker = "[retry-hint]";
    const idx = rawDesc.indexOf(marker);
    let baseHtml = "";
    let hintHtml = "";
    if (idx === -1) {
      baseHtml = `<pre class="description-text">${escapeHtml(rawDesc)}</pre>`;
    } else {
      const base = rawDesc.slice(0, idx).trim();
      const hint = rawDesc.slice(idx + marker.length).trim();
      if (base) baseHtml = `<pre class="description-text">${escapeHtml(base)}</pre>`;
      if (hint) hintHtml = `
        <div class="description-hint">
          <span class="description-hint-label">retry hint</span>
          <pre class="description-text">${escapeHtml(hint)}</pre>
        </div>`;
    }
    descBlock = `<details class="description-block" open>
      <summary>Description${idx !== -1 ? " <span class=\"description-retry-chip\">retry</span>" : ""}</summary>
      ${baseHtml}${hintHtml}
    </details>`;
  }

  // Run-now button: show whenever the job dir actually contains a runnable
  // script (exploit.py / solver.py / solver.sage). Don't gate on status —
  // even 'failed' jobs sometimes have a usable partial script.
  let runBlock = "";
  const isExploitableModule = ["web", "pwn", "crypto", "rev"].includes(job.module);
  // Retry is offered for every TERMINAL status on an exploitable module
  // — including 'finished' with a flag, so the user can rerun against a
  // suspect / placeholder flag or grab additional flags. The reviewer
  // path is still useful in that case ("the captured value looks like a
  // dummy — find the real flag").
  const showRetry = isExploitableModule && [
    "failed", "no_flag", "finished", "stopped",
  ].includes(job.status);
  // Stop & resume: only meaningful while the job is still in flight.
  const showStopResume = isExploitableModule && (
    job.status === "queued" || job.status === "running"
  );
  if (
    job.runnable_script || job.exploit_present || job.solver_present
    || showRetry || showStopResume
  ) {
    const scriptName = job.runnable_script || (job.exploit_present ? "exploit.py" : "solver.py");
    const runHtml = (job.runnable_script || job.exploit_present || job.solver_present)
      ? `<button class="run-now-btn" data-action="run">▶ Run ${escapeHtml(scriptName)} in sandbox</button>`
      : "";
    const retryHtml = showRetry
      ? `<button class="retry-btn" data-action="retry">↻ Retry with reviewer hint</button>
         <button class="retry-btn retry-manual-open-btn" data-action="retry-manual">✏ Retry with my hint</button>` : "";
    const stopResumeHtml = showStopResume
      ? `<button class="retry-btn retry-stop-resume-btn" data-action="stop-resume-reviewer">↻ Stop &amp; resume with reviewer hint</button>
         <button class="retry-btn retry-stop-resume-btn" data-action="stop-resume">✋ Stop &amp; resume with my hint</button>` : "";
    const helperBits = [];
    if (runHtml) helperBits.push("re-runs the produced script");
    if (retryHtml) helperBits.push("reviewer hint = Claude diagnoses the failure · my hint = you write the hint yourself");
    if (stopResumeHtml) helperBits.push("stop & resume = halt this job, carry over ./work/, and start fresh with a reviewer-written or hand-written hint");
    runBlock = `<div class="retry-row" style="margin:0.5rem 0">
      ${runHtml} ${retryHtml} ${stopResumeHtml}
      <small style="color:#8b949e">${helperBits.join(" · ")}</small>
    </div>`;
  }

  let errorBlock = "";
  if (job.error_kind === "policy_refusal") {
    errorBlock = `<div class="refusal-banner">
      <h4>⚠ Claude Usage Policy refusal</h4>
      <div>The agent stopped mid-job because Claude refused to continue.
        Try switching the model in <strong>Settings → Claude model</strong> to
        <code>claude-sonnet-4-6</code> and re-run the job. Sonnet often
        completes CTF tasks where Opus declines.</div>
    </div>`;
  } else if (job.error) {
    errorBlock = `<div class="refusal-banner">
      <h4>⚠ Job error (${escapeHtml(job.error_kind || "unknown")})</h4>
      <div><code>${escapeHtml(String(job.error).slice(0, 400))}</code></div>
    </div>`;
  }

  // Forensic-only: log-miner findings panel. Shows category counts so the
  // user can see at a glance whether the run captured anything actionable.
  let logFindingsBlock = "";
  if (job.module === "forensic" && job.log_findings_counts) {
    const c = job.log_findings_counts;
    const cells = [
      ["passwords", c.passwords],
      ["sqli", c.sqli_attempts],
      ["xss", c.xss_attempts],
      ["lfi", c.lfi_attempts],
      ["rce", c.rce_attempts],
      ["auth events", c.auth_events],
      ["flag candidates", c.flag_candidates],
    ];
    const chips = cells
      .filter(([, v]) => typeof v === "number")
      .map(([label, v]) =>
        `<span class="lf-chip ${v > 0 ? "hit" : "zero"}">${escapeHtml(label)}: ${v}</span>`
      ).join(" ");
    const scanned = typeof c.scanned_files === "number"
      ? `<small style="color:#8b949e">scanned ${c.scanned_files} log/history files</small>` : "";
    logFindingsBlock = `<div class="log-findings-panel">
      <h4>🔎 Log mining</h4>
      <div class="lf-chips">${chips}</div>
      ${scanned}
      <small style="color:#8b949e;margin-left:0.5rem">
        full report: <a href="${API}/jobs/${id}/file/log_findings.json" target="_blank">log_findings.json</a>
      </small>
    </div>`;
  }

  let flagBlock = "";
  if (job.flags && job.flags.length) {
    const rows = job.flags.map((f, i) =>
      `<div class="flag-row">
         <code id="flag-${id}-${i}">${escapeHtml(f)}</code>
         <button class="copy-btn" data-flag="${escapeHtml(f)}">Copy</button>
       </div>`).join("");
    flagBlock = `<div class="flag-banner">
        <h4>🚩 Flag${job.flags.length > 1 ? "s" : ""} found</h4>
        ${rows}
      </div>`;
  }

  detail.innerHTML = `
    <h3>Job ${job.id}
      <span class="status ${job.status}">${job.status}</span>
    </h3>
    <div><small>module: ${job.module} · file: ${escapeHtml(job.filename || "")} · target: ${escapeHtml(job.target_url || "(none)")}${stage}${cost}${timeout}${modelInfo}</small></div>
    ${timeoutBlock}
    ${descBlock}
    ${runBlock}
    ${errorBlock}
    ${flagBlock}
    ${logFindingsBlock}
    ${resultBlock}
    <h4>Run log <small style="color:#8b949e;font-weight:normal">(auto-follows when scrolled to bottom)</small></h4>
    <pre class="run-log" data-job-id="${id}">${log ? colorizeRunLog(log) : "(empty)"}</pre>
  `;

  const newPre = detail.querySelector("pre.run-log");
  if (newPre) {
    if (!isSameJob || prevAtBottom) {
      newPre.scrollTop = newPre.scrollHeight;
    } else {
      newPre.scrollTop = prevScrollTop;
    }
  }

  const retryBtn = detail.querySelector('.retry-btn[data-action="retry"]');
  if (retryBtn) {
    retryBtn.addEventListener("click", () => streamRetry(id, retryBtn));
  }
  const retryManualBtn = detail.querySelector('.retry-btn[data-action="retry-manual"]');
  if (retryManualBtn) {
    retryManualBtn.addEventListener("click", () => openManualHintForm(id, retryManualBtn));
  }
  const stopResumeBtn = detail.querySelector('.retry-btn[data-action="stop-resume"]');
  if (stopResumeBtn) {
    stopResumeBtn.addEventListener("click", () => openStopResumeForm(id, stopResumeBtn));
  }
  const stopResumeReviewerBtn = detail.querySelector(
    '.retry-btn[data-action="stop-resume-reviewer"]',
  );
  if (stopResumeReviewerBtn) {
    stopResumeReviewerBtn.addEventListener("click", () => {
      // No manual hint: streamRetry will fetch the reviewer over SSE,
      // backend will halt the source job first, carry ./work/, and
      // submit the new job with a [RESUMING] preamble.
      streamRetry(id, stopResumeReviewerBtn, null, {
        endpoint: `${API}/jobs/${id}/resume/stream`,
        flow: "resume",
      });
    });
  }

  const continueBtn = detail.querySelector('.timeout-continue-btn[data-action="continue"]');
  if (continueBtn) {
    continueBtn.addEventListener("click", () => decideTimeout(id, "continue", continueBtn));
  }
  const killBtn = detail.querySelector('.timeout-kill-btn[data-action="kill"]');
  if (killBtn) {
    killBtn.addEventListener("click", () => decideTimeout(id, "kill", killBtn));
  }

  const runBtn = detail.querySelector('.run-now-btn[data-action="run"]');
  if (runBtn) {
    runBtn.addEventListener("click", async () => {
      runBtn.disabled = true;
      const origText = runBtn.textContent;
      runBtn.textContent = "⏳ running…";
      try {
        const res = await fetch(`${API}/jobs/${id}/run`, { method: "POST" });
        const body = await res.json();
        if (!res.ok) {
          alert(`run failed: ${res.status} ${JSON.stringify(body)}`);
        } else {
          const sb = body.sandbox || {};
          const msg = `exit=${sb.exit_code} · stdout ${sb.stdout?.length || 0}B · `
            + `flags: ${(body.flags || []).length ? body.flags.join(", ") : "(none)"}`;
          alert(msg);
        }
      } catch (e) {
        alert(`run error: ${e}`);
      } finally {
        runBtn.disabled = false;
        runBtn.textContent = origText;
        await renderJob(id, { force: true });
        await refreshJobs();
      }
    });
  }

  for (const btn of detail.querySelectorAll(".copy-btn")) {
    btn.addEventListener("click", async () => {
      const flag = btn.dataset.flag;
      try {
        await navigator.clipboard.writeText(flag);
      } catch (_) {
        // Fallback: select + execCommand
        const tmp = document.createElement("textarea");
        tmp.value = flag; document.body.appendChild(tmp);
        tmp.select(); document.execCommand("copy"); tmp.remove();
      }
      const orig = btn.textContent;
      btn.textContent = "✓ Copied"; btn.classList.add("copied");
      setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1500);
    });
  }
  return job;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// --- Run-log colorizer ------------------------------------------------------
// Lines look like: "[HH:MM:SS] LABEL[: body...]". Classify by LABEL and wrap
// the timestamp + label + body in spans so the run.log <pre> can show
// agent text, tool calls, tool results, thinking, and errors at a glance.

const _RUNLOG_PATTERNS = [
  // AGENT_ERROR (kind): body  — must come before plain ERROR
  { re: /^(AGENT_ERROR)(\s*\([^)]*\))?\s*:\s*([\s\S]*)$/,
    cls: "rl-agent-error",
    render: (m) => `<span class="rl-label rl-agent-error">${escapeHtml(m[1])}${escapeHtml(m[2] || "")}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[3])}</span>` },
  // TOOL_RESULT: body
  { re: /^(TOOL_RESULT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool-result">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // TOOL_ERROR: body
  { re: /^(TOOL_ERROR)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool-error">${escapeHtml(m[1])}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[2])}</span>` },
  // TOOL <name>: body
  { re: /^(TOOL)\s+(\S+)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool">${escapeHtml(m[1])}</span> <span class="rl-toolname">${escapeHtml(m[2])}</span>: <span class="rl-body">${escapeHtml(m[3])}</span>` },
  // AGENT: body
  { re: /^(AGENT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-agent">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // THINK: body
  { re: /^(THINK)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-think">${escapeHtml(m[1])}</span>: <span class="rl-body rl-think-body">${escapeHtml(m[2])}</span>` },
  // DONE: body
  { re: /^(DONE)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-done">${escapeHtml(m[1])}</span>: <span class="rl-body rl-done-body">${escapeHtml(m[2])}</span>` },
  // ERROR: body  (catastrophic — exception in run_job etc.)
  { re: /^(ERROR)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-error">${escapeHtml(m[1])}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[2])}</span>` },
];

function _colorizeRunLogLine(line) {
  // Header injected by /api/jobs/{id}/log?tail=… (e.g. "…(showing last X
  // of Y bytes — download full log via …)…"). Render dim+italic.
  if (line.startsWith("…(showing last")) {
    return `<span class="rl-system">${escapeHtml(line)}</span>`;
  }
  const m = line.match(/^\[(\d{2}:\d{2}:\d{2})\]\s+([\s\S]*)$/);
  if (!m) {
    if (!line) return "";
    return `<span class="rl-system">${escapeHtml(line)}</span>`;
  }
  const ts = m[1];
  const rest = m[2];
  for (const p of _RUNLOG_PATTERNS) {
    const mm = rest.match(p.re);
    if (mm) {
      return `<span class="rl-ts">[${ts}]</span> ${p.render(mm)}`;
    }
  }
  // System / unrecognised lines (e.g. "Launching Claude agent…",
  // "User chose CONTINUE…", "⏰ Soft timeout reached…").
  return `<span class="rl-ts">[${ts}]</span> <span class="rl-system">${escapeHtml(rest)}</span>`;
}

function colorizeRunLog(text) {
  if (!text) return "";
  return text.split("\n").map(_colorizeRunLogLine).join("\n");
}

// --- File preview modal -----------------------------------------------------
// Pretty-prints JSON, renders Markdown, and syntax-highlights source code
// using highlight.js + marked (loaded from CDN in index.html). Falls back
// to plain text if the libraries didn't load (e.g. offline).

const _LANG_FROM_EXT = {
  py: "python", sage: "python",
  js: "javascript", ts: "typescript",
  json: "json", jsonl: "json",
  md: "markdown", markdown: "markdown",
  html: "xml", xml: "xml",
  css: "css",
  sh: "bash", bash: "bash",
  c: "c", h: "c", cpp: "cpp", hpp: "cpp", cc: "cpp",
  rb: "ruby", go: "go", rs: "rust",
  yml: "yaml", yaml: "yaml",
  sql: "sql",
  log: "plaintext", stdout: "plaintext", stderr: "plaintext", txt: "plaintext",
};

function _languageFor(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return _LANG_FROM_EXT[ext] || "plaintext";
}

function _isMarkdown(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ext === "md" || ext === "markdown";
}

function _isJson(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ext === "json" || name === "result.json";
}

async function openFileModal(name, sourceUrl) {
  const modal = document.getElementById("file-modal");
  if (!modal) return;
  const body = modal.querySelector(".file-modal-body");
  const nameEl = modal.querySelector(".file-modal-name");
  const metaEl = modal.querySelector(".file-modal-meta");
  const rawLink = modal.querySelector(".file-modal-raw");
  const copyBtn = modal.querySelector(".file-modal-copy");

  nameEl.textContent = name;
  metaEl.textContent = "loading…";
  rawLink.href = sourceUrl;
  body.innerHTML = "";
  modal.hidden = false;
  modal.dataset.url = sourceUrl;
  modal.dataset.name = name;

  let text;
  try {
    const res = await fetch(sourceUrl);
    if (!res.ok) {
      metaEl.textContent = `error ${res.status}`;
      body.innerHTML = `<pre class="file-modal-error">${escapeHtml(await res.text())}</pre>`;
      return;
    }
    text = await res.text();
  } catch (e) {
    metaEl.textContent = "fetch failed";
    body.innerHTML = `<pre class="file-modal-error">${escapeHtml(String(e))}</pre>`;
    return;
  }
  modal.dataset.raw = text;
  metaEl.textContent = `${text.length.toLocaleString()} bytes`;

  // Render based on extension.
  if (_isJson(name)) {
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
    const code = `<pre><code class="language-json">${escapeHtml(pretty)}</code></pre>`;
    body.innerHTML = code;
  } else if (_isMarkdown(name)) {
    if (window.marked) {
      const html = window.marked.parse(text, { mangle: false, headerIds: false });
      body.innerHTML = `<div class="markdown-rendered">${html}</div>`;
    } else {
      body.innerHTML = `<pre><code class="language-markdown">${escapeHtml(text)}</code></pre>`;
    }
  } else {
    const lang = _languageFor(name);
    body.innerHTML = `<pre><code class="language-${lang}">${escapeHtml(text)}</code></pre>`;
  }

  // Highlight every code block (including those produced by marked).
  if (window.hljs) {
    body.querySelectorAll("pre code").forEach((el) => {
      try { window.hljs.highlightElement(el); } catch (_) {}
    });
  }

  // Wire one-shot Copy that pulls from the cached raw.
  copyBtn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(modal.dataset.raw || "");
      const orig = copyBtn.textContent;
      copyBtn.textContent = "✓ Copied";
      setTimeout(() => (copyBtn.textContent = orig), 1200);
    } catch (e) {
      alert("clipboard error: " + e);
    }
  };
}

function _closeFileModal() {
  const modal = document.getElementById("file-modal");
  if (!modal) return;
  modal.hidden = true;
  modal.dataset.url = "";
  modal.dataset.name = "";
  modal.dataset.raw = "";
}

// Single delegated click handler for all file-preview links + the modal's
// own close/backdrop/Escape. Set up once at load.
document.addEventListener("click", (e) => {
  const link = e.target.closest("a.file-preview-link");
  if (link) {
    // Allow modifier-clicks (new tab / window / download) to fall through
    // to the browser's normal link behavior.
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
      return;
    }
    e.preventDefault();
    openFileModal(link.dataset.name, link.dataset.url);
    return;
  }
  if (e.target.closest(".file-modal-close, .file-modal-backdrop")) {
    _closeFileModal();
    return;
  }
  if (e.target.closest(".job-modal-close, .job-modal-backdrop")) {
    _closeJobModal();
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  // File preview is on top of the job modal — close that one first.
  const fileModal = document.getElementById("file-modal");
  if (fileModal && !fileModal.hidden) {
    _closeFileModal();
    return;
  }
  const jobModal = document.getElementById("job-modal");
  if (jobModal && !jobModal.hidden) {
    _closeJobModal();
  }
});

fillModelSelects();
refreshJobs();
refreshStats();
