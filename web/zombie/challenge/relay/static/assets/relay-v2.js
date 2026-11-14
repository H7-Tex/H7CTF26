(() => {
  const BUILD = "2026.09.24.2";
  const $ = selector => document.querySelector(selector);
  const toast = message => { const node = $("#toast"); node.textContent = message; node.classList.add("show"); setTimeout(() => node.classList.remove("show"), 2600); };
  const escapeHTML = value => String(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const event = (name, detail = {}) => console.debug(JSON.stringify({ event: name, ...detail }));
  const state = { updateFound: false };
  async function api(path) { const response = await fetch(path, { cache: "no-store" }); if (!response.ok) throw new Error(`Relay responded ${response.status}`); return response.json(); }
  function askWorker(worker, message) {
    if (!worker) return Promise.reject(new Error("Offline support is not ready"));
    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timer = setTimeout(() => reject(new Error("Offline support did not respond")), 4000);
      channel.port1.onmessage = event => { clearTimeout(timer); resolve(event.data); };
      worker.postMessage(message, [channel.port2]);
    });
  }
  async function refreshOutboxAction() {
    const registration = await navigator.serviceWorker?.getRegistration("/");
    const status = await askWorker(navigator.serviceWorker?.controller || registration?.active, { type: "RELAY_OUTBOX_STATUS" });
    const receipt = $("#reconciliation-receipt");
    if (status.reconciliation_receipt) {
      receipt.textContent = `Sync reference · ${status.reconciliation_receipt}`;
      receipt.hidden = false;
    } else { receipt.hidden = true; }
    let button = document.querySelector("#flush-button");
    if (status.count > 0 && !button) {
      button = document.createElement("button"); button.id = "flush-button"; button.className = "quiet-button";
      button.type = "button"; button.textContent = "Send queued updates";
      $("#sync-button").insertAdjacentElement("afterend", button);
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          const result = await askWorker(navigator.serviceWorker.controller, { type: "RELAY_OUTBOX_FLUSH" });
          if (result.status !== "complete") throw new Error("Queued updates were deferred");
          button.remove(); await refresh();
          toast("Queued updates sent");
        } catch (error) {
          console.warn("Relay queued updates were deferred", error);
          button.disabled = false; toast("Couldn’t send just now, we’ll retry");
        }
      });
    } else if (status.count === 0) button?.remove();
  }
  function renderJobs(items) {
    $("#job-list").innerHTML = items.map(job => `<article class="job-card"><div class="site-badge tone-${escapeHTML(job.tone)}">${escapeHTML(job.initials)}</div><div><div class="job-id">${escapeHTML(job.id)}</div><div class="job-title">${escapeHTML(job.title)}</div><div class="job-site">${escapeHTML(job.site)}</div></div><div class="job-address">${escapeHTML(job.address)}</div><div><span class="status-tag ${job.status === "Awaiting report" ? "amber" : job.status === "Draft" ? "gray" : ""}">${escapeHTML(job.status)}</span><div class="job-due">${escapeHTML(job.due)}</div></div><button class="job-open" type="button" data-job-id="${escapeHTML(job.id)}">View details</button></article>`).join("");
  }
  function renderActivity(items) { $("#activity-list").innerHTML = items.map(item => `<div class="activity-row"><span class="activity-symbol">${item.kind === "check" ? "✓" : item.kind === "pin" ? "⌖" : "↻"}</span><div><b>${escapeHTML(item.title)}</b><small>${escapeHTML(item.detail)}</small></div><time>${escapeHTML(item.when)}</time></div>`).join(""); }
  async function refresh() {
    try {
      const [meta, jobs, activity, preference] = await Promise.all([api("/api/meta"), api("/api/jobs"), api("/api/activity"), api("/api/jobs/JOB-3887/report-preference")]);
      if (meta.build !== BUILD) {
        if (!state.updateFound) { state.updateFound = true; toast("Relay has been updated. Refreshing your workspace…"); }
        const registration = await navigator.serviceWorker?.getRegistration("/");
        if (registration) await registration.update();
        setTimeout(() => location.reload(), 350);
      }
      const next = new Date(preference.dispatch.next_snapshot_at);
      $("#sync-label").textContent = `Next sync at ${next.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
      renderJobs(jobs.items); renderActivity(activity.items);
    } catch { $("#sync-label").textContent = "Working from saved data"; }
  }
  async function syncNow() {
    try {
      const preference = await api("/api/jobs/JOB-3887/report-preference");
      const planResponse = await fetch("/api/sync/plan", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cycle_id: preference.dispatch.cycle_id }) });
      if (planResponse.status === 409) {
        const detail = await planResponse.json().catch(() => ({}));
        const waiting = String(detail.detail || "").includes("not ready");
        $("#sync-label").textContent = waiting ? "Checking for updates…" : "Something changed, refresh to continue";
        toast(waiting ? "Not ready yet, try again in a moment" : "Something changed, refresh to continue");
        return;
      }
      if (!planResponse.ok) throw new Error(`Relay responded ${planResponse.status}`);
      const plan = await planResponse.json();
      $("#sync-label").textContent = plan.state === "pending-sync" ? "Drafts queued for sync" : "Sync complete";
      await refreshOutboxAction();
      await refresh();
      toast("Sync complete");
    } catch (error) {
      console.warn("Relay sync did not complete", error);
      $("#sync-label").textContent = "Sync will retry when connected";
      toast("Sync could not be completed");
    }
  }
  $("#jobs").addEventListener("click", async event => {
    const exportButton = event.target.closest("[data-export-job]");
    if (exportButton) {
      exportButton.disabled = true;
      try {
        const created = await fetch(`/api/jobs/${encodeURIComponent(exportButton.dataset.exportJob)}/exports`, { method: "POST" }).then(r => r.json());
        if (!created.export_id) throw new Error("Package request was not accepted");
        const detail = $("#job-detail");
        detail.insertAdjacentHTML("beforeend", `<p data-export-status>Preparing report package…</p>`);
        let status;
        do { await new Promise(resolve => setTimeout(resolve, 350)); status = await api(created.status_url); }
        while (status.status === "processing");
        detail.querySelector("[data-export-status]").innerHTML = `<a href="${escapeHTML(status.package_url)}">Download report package</a>`;
      } catch { toast("Report package is not available"); exportButton.disabled = false; }
      return;
    }
    const button = event.target.closest("[data-job-id]");
    if (!button) return;
    try {
      const result = await api(`/api/jobs/${encodeURIComponent(button.dataset.jobId)}`);
      const job = result.job;
      const detail = $("#job-detail");
      detail.hidden = false;
      let draftControls = "";
      if (job.id === "JOB-3887" && !job.report) {
        const preference = await api(`/api/jobs/${encodeURIComponent(job.id)}/report-preference`);
        const selected = preference.report_package.scope;
        draftControls = `<label class="report-option">Report detail<select data-report-package aria-label="Report detail"><option value="summary" ${selected === "summary" ? "selected" : ""}>Summary</option><option value="record" ${selected === "record" ? "selected" : ""}>Field record</option></select><small>This report setting will be used the next time this job syncs.</small></label>`;
      }
      detail.innerHTML = `<b>${escapeHTML(job.id)} · ${escapeHTML(job.title)}</b><span>${escapeHTML(job.site)}</span><p>${job.report ? `Report published · ${escapeHTML(job.report.diagnostic_reading)}` : "No report has been published."}</p>${draftControls}${job.export_url ? `<button type="button" class="quiet-button" data-export-job="${escapeHTML(job.id)}">Prepare report package</button>` : ""}`;
    } catch { toast("Job details are unavailable while offline"); }
  });
  $("#jobs").addEventListener("change", async event => {
    const selector = event.target.closest("[data-report-package]");
    if (!selector) return;
    try {
      const current = await fetch("/api/jobs/JOB-3887/report-preference", { cache: "no-store" });
      const response = await fetch("/api/jobs/JOB-3887/report-preference", {
        method: "PUT", headers: { "Content-Type": "application/json", "If-Match": current.headers.get("ETag") },
        body: JSON.stringify({ contract: "relay.report-package/v2", scope: selector.value }),
      });
      if (response.status === 412) {
        const fresh = await api("/api/jobs/JOB-3887/report-preference");
        selector.value = fresh.report_package.scope;
        await refresh();
        toast("Someone changed this setting, so we’ve refreshed it.");
        return;
      }
      if (!response.ok) throw new Error(`Relay responded ${response.status}`);
      toast("Report detail saved for the next sync");
    } catch { toast("We couldn’t save that, try again"); }
  });
  if ("serviceWorker" in navigator) {
    const workerScript = BUILD.endsWith(".1") ? "/sw-2026.09.24.1.js" : "/sw-2026.09.24.2.js";
    navigator.serviceWorker.register(workerScript, { scope: "/", updateViaCache: "none" }).then(registration => {
      event("sw_registered", { build: BUILD, active: registration.active?.state || null });
      registration.addEventListener("updatefound", () => {
        event("sw_installing", { build: BUILD });
        registration.installing?.addEventListener("statechange", e => event("sw_statechange", { state: e.target.state }));
      });
      if (registration.waiting) event("sw_waiting", { active: registration.active?.state });
    }).catch(error => console.warn("Relay offline support unavailable", error));
    navigator.serviceWorker.addEventListener("controllerchange", () => event("controller_changed", { build: BUILD }));
  }
  refresh(); refreshOutboxAction().catch(() => {}); setInterval(refresh, 5000);
  $("#sync-button").addEventListener("click", syncNow);
  $("#new-job").addEventListener("click", () => toast("New job details are ready to fill in"));
  event("page_build_loaded", { build: BUILD });
})();
