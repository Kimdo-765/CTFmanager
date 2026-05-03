const API = "/api";

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
  // Drop empty optional numeric fields so backend uses its default.
  const to = fd.get("job_timeout");
  if (to === "" || to == null) fd.delete("job_timeout");

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
  // Don't populate password fields with stored values — leave blank, show status only
  f.querySelector("[name=claude_model]").value = s.claude_model || "";
  f.querySelector("[name=job_ttl_days]").value =
    s.job_ttl_days != null ? s.job_ttl_days : "";
  f.querySelector("[name=job_timeout_seconds]").value =
    s.job_timeout_seconds != null ? s.job_timeout_seconds : "";
  f.querySelector("[name=worker_concurrency]").value =
    s.worker_concurrency != null ? s.worker_concurrency : "";
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
    selectedJob = null;
    document.getElementById("job-detail").innerHTML = "";
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
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
    selectedJob = null;
    document.getElementById("job-detail").innerHTML = "";
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }
  refreshJobs();
  refreshStats();
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
  await renderJob(id);
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const job = await renderJob(id);
    if (job && (job.status === "finished" || job.status === "failed")) {
      clearInterval(pollTimer);
      pollTimer = null;
      await refreshJobs();
      await refreshStats();
    }
  }, 2000);
}

async function renderJob(id) {
  const detail = document.getElementById("job-detail");
  const res = await fetch(`${API}/jobs/${id}`);
  if (!res.ok) {
    detail.textContent = "job not found";
    return null;
  }
  const job = await res.json();

  const logRes = await fetch(`${API}/jobs/${id}/log`);
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

  let resultBlock = "";
  if (job.status === "finished" || job.status === "running") {
    const links = [
      `<a href="${API}/jobs/${id}/result" target="_blank">result.json</a>`,
      `<a href="${API}/jobs/${id}/file/report.md" target="_blank">report.md</a>`,
    ];
    if (job.module === "web" || job.module === "pwn") {
      links.push(`<a href="${API}/jobs/${id}/file/exploit.py" target="_blank">exploit.py</a>`);
      links.push(`<a href="${API}/jobs/${id}/file/exploit.py.stdout" target="_blank">stdout</a>`);
      links.push(`<a href="${API}/jobs/${id}/file/exploit.py.stderr" target="_blank">stderr</a>`);
    }
    if (job.module === "crypto" || job.module === "rev") {
      links.push(`<a href="${API}/jobs/${id}/file/solver.py" target="_blank">solver.py</a>`);
      links.push(`<a href="${API}/jobs/${id}/file/solver.py.stdout" target="_blank">stdout</a>`);
      links.push(`<a href="${API}/jobs/${id}/file/solver.py.stderr" target="_blank">stderr</a>`);
    }
    if (job.module === "forensic") {
      links.push(`<a href="${API}/jobs/${id}/file/summary.json" target="_blank">summary.json</a>`);
      links.push(`<a href="${API}/jobs/${id}/file/collector.log" target="_blank">collector.log</a>`);
    }
    if (job.module === "misc") {
      links.push(`<a href="${API}/jobs/${id}/file/findings.json" target="_blank">findings.json</a>`);
      links.push(`<a href="${API}/jobs/${id}/file/analyze.log" target="_blank">analyze.log</a>`);
    }
    resultBlock = `<div class="file-links">${links.join(" ")}</div>`;
  }

  const cost = job.cost_usd ? ` · cost: $${Number(job.cost_usd).toFixed(4)}` : "";
  const stage = job.stage ? ` · stage: ${job.stage}` : "";
  const timeout = job.job_timeout ? ` · timeout: ${job.job_timeout}s` : "";

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
    <div><small>module: ${job.module} · file: ${escapeHtml(job.filename || "")} · target: ${escapeHtml(job.target_url || "(none)")}${stage}${cost}${timeout}</small></div>
    ${flagBlock}
    ${resultBlock}
    <h4>Run log <small style="color:#8b949e;font-weight:normal">(auto-follows when scrolled to bottom)</small></h4>
    <pre class="run-log" data-job-id="${id}">${escapeHtml(log) || "(empty)"}</pre>
  `;

  const newPre = detail.querySelector("pre.run-log");
  if (newPre) {
    if (!isSameJob || prevAtBottom) {
      newPre.scrollTop = newPre.scrollHeight;
    } else {
      newPre.scrollTop = prevScrollTop;
    }
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

refreshJobs();
refreshStats();
