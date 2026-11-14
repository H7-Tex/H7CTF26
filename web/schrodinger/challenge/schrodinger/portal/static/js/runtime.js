(() => {
  const { api, formatDate, link, make } = window.Exchange;
  const rows = document.getElementById("runtime-rows");
  const output = document.getElementById("runtime-output");

  async function loadJobs() {
    try {
      const result = await api("/api/runtime/jobs");
      document.getElementById("runtime-count").textContent = `${result.total} recorded sessions`;
      rows.replaceChildren();
      if (!result.items.length) return empty("No runtime sessions are available.");
      for (const job of result.items) {
        const row = make("tr");
        const packageCell = make("td");
        packageCell.append(link(`/packages/${encodeURIComponent(job.artifact_id)}`, job.package_name, "package-link"));
        row.append(packageCell);
        const idCell = make("td");
        const select = make("button", "session-select", job.job_id);
        select.type = "button";
        select.setAttribute("aria-label", `Show output for session ${job.job_id}`);
        select.addEventListener("click", () => loadJob(job.job_id));
        idCell.append(select); row.append(idCell);
        row.append(make("td", "", job.status), make("td", "numeric", `${job.duration_ms} ms`));
        row.append(make("td", "", formatDate(job.created_at)));
        const digest = make("td"); digest.append(make("span", "mono digest", job.sha256)); row.append(digest);
        rows.append(row);
      }
      const selected = new URLSearchParams(window.location.search).get("job");
      if (selected) await loadJob(selected);
    } catch (error) {
      document.getElementById("runtime-count").textContent = "Runtime activity unavailable";
      empty(error.message || "Runtime activity could not be loaded.");
    }
  }

  async function loadJob(jobId) {
    output.textContent = "Loading session output…";
    try {
      const job = await api(`/api/runtime/jobs/${encodeURIComponent(jobId)}`);
      output.textContent = job.output.join("\n");
    } catch (error) {
      output.textContent = error.message || "Session output could not be loaded.";
    }
  }

  function empty(message) {
    const row = make("tr");
    const cell = make("td", "table-state", message);
    cell.colSpan = 6;
    row.append(cell);
    rows.replaceChildren(row);
  }

  loadJobs();
})();
