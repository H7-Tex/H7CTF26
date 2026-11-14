(() => {
  const BUILD = "2026.09.24.1";
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
      const timer = setTimeout(() => reject(new Error("Offline support did not respond")), 3000);
      channel.port1.onmessage = event => { clearTimeout(timer); resolve(event.data); };
      worker.postMessage(message, [channel.port2]);
    });
  }
  function renderJobs(items) {
    $("#job-list").innerHTML = items.map(job => `<article class="job-card"><div class="site-badge tone-${escapeHTML(job.tone)}">${escapeHTML(job.initials)}</div><div><div class="job-id">${escapeHTML(job.id)}</div><div class="job-title">${escapeHTML(job.title)}</div><div class="job-site">${escapeHTML(job.site)}</div></div><div class="job-address">${escapeHTML(job.address)}</div><div><span class="status-tag ${job.status === "Awaiting report" ? "amber" : job.status === "Draft" ? "gray" : ""}">${escapeHTML(job.status)}</span><div class="job-due">${escapeHTML(job.due)}</div></div><button class="job-open" type="button" data-job-id="${escapeHTML(job.id)}">View details</button></article>`).join("");
  }
  function renderActivity(items) { $("#activity-list").innerHTML = items.map(item => `<div class="activity-row"><span class="activity-symbol">${item.kind === "check" ? "✓" : item.kind === "pin" ? "⌖" : "↻"}</span><div><b>${escapeHTML(item.title)}</b><small>${escapeHTML(item.detail)}</small></div><time>${escapeHTML(item.when)}</time></div>`).join(""); }
  async function refresh() {
    try {
      const [meta, jobs, activity] = await Promise.all([api("/api/meta"), api("/api/jobs"), api("/api/activity")]);
      if (meta.build !== BUILD) {
        if (!state.updateFound) { state.updateFound = true; toast("Relay has been updated. Refreshing your workspace…"); }
        const registration = await navigator.serviceWorker?.getRegistration("/");
        if (registration) await registration.update();
        setTimeout(() => location.reload(), 350);
      }
      $("#sync-label").textContent = "Last synced just now";
      renderJobs(jobs.items); renderActivity(activity.items);
    } catch { $("#sync-label").textContent = "Working from saved data"; }
  }
  async function syncNow() {
    try {
      const currentMeta = await api("/api/meta");
      if (currentMeta.api_version === "1.0") {
        const rollout = await fetch("/api/runtime/ready", { method: "POST", cache: "no-store" });
        if (!rollout.ok) throw new Error(`Relay responded ${rollout.status}`);
        $("#sync-label").textContent = "Update received; refreshing workspace";
        toast("Update received");
        setTimeout(() => location.reload(), 200);
        return;
      }
      const plan = await api("/api/sync/plan");
      if (plan.state === "pending-sync") $("#sync-label").textContent = "Drafts queued for sync";
      else $("#sync-label").textContent = "Sync plan updated";
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
      let packageControl = "";
      if (job.id === "JOB-3887" && !job.report) {
        const preference = await api(`/api/jobs/${encodeURIComponent(job.id)}/report-preference`);
        const selected = preference.report_package.profile;
        packageControl = `<label class="report-option">Report package<select data-report-profile aria-label="Report package"><option value="summary" ${selected === "summary" ? "selected" : ""}>Summary</option><option value="record" ${selected === "record" ? "selected" : ""}>Field record</option></select><small>Choose the material to include when this draft is prepared for dispatch.</small></label>`;
      }
      detail.innerHTML = `<b>${escapeHTML(job.id)} · ${escapeHTML(job.title)}</b><span>${escapeHTML(job.site)}</span><p>${job.report ? `Report published · ${escapeHTML(job.report.diagnostic_reading)}` : "No report has been published."}</p>${packageControl}${job.export_url ? `<button type="button" class="quiet-button" data-export-job="${escapeHTML(job.id)}">Prepare report package</button>` : ""}`;
    } catch { toast("Job details are unavailable while offline"); }
  });
  $("#jobs").addEventListener("change", async event => {
    const selector = event.target.closest("[data-report-profile]");
    if (!selector) return;
    try {
      const current = await fetch("/api/jobs/JOB-3887/report-preference", { cache: "no-store" });
      const response = await fetch("/api/jobs/JOB-3887/report-preference", {
        method: "PUT", headers: { "Content-Type": "application/json", "If-Match": current.headers.get("ETag") },
        body: JSON.stringify({ contract: "relay.report-package/v1", profile: selector.value }),
      });
      if (!response.ok) throw new Error(`Relay responded ${response.status}`);
      const saved = await response.json();
      const registration = await navigator.serviceWorker.getRegistration("/");
      const stored = await askWorker(navigator.serviceWorker.controller || registration?.active,
        { type: "RELAY_REPORT_PACKAGE_SAVE", profile: saved.report_package.profile, revision: saved.revision });
      if (stored.status !== "saved") throw new Error("Offline package setting was not saved");
      toast("Report package saved for the next sync");
    } catch (error) {
      console.warn("Relay report setting did not save", error);
      toast("We couldn’t save that. Refresh and try again.");
    }
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
  refresh(); setInterval(refresh, 5000);
  $("#sync-button").addEventListener("click", syncNow);
  $("#new-job").addEventListener("click", () => toast("New job details are ready to fill in"));
  event("page_build_loaded", { build: BUILD });
})();
