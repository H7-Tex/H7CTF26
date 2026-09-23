(() => {
  const { api, badge, formatBytes, make, showNotice } = window.Exchange;
  const id = window.packageArtifactId;
  const files = document.getElementById("inspector-files");
  const findings = document.getElementById("inspector-findings");
  const run = document.getElementById("inspect-package");

  function tableState(message) {
    const row = make("tr");
    const cell = make("td", "table-state", message);
    cell.colSpan = 3;
    row.append(cell);
    files.replaceChildren(row);
  }

  async function load() {
    try {
      const report = await api(`/api/packages/${encodeURIComponent(id)}/inspector`);
      document.getElementById("inspector-title").textContent = `${report.package.package_name} inspector report`;
      document.getElementById("inspector-summary").textContent = report.inspector_summary || "No inspection has been recorded.";
      document.getElementById("inspector-package-id").textContent = report.package.package_id;
      document.getElementById("inspector-sha").textContent = report.package.sha256;
      const status = document.getElementById("inspector-status");
      status.replaceChildren(badge(report.inspector_status));
      const inspection = report.inspection;
      if (!inspection) {
        document.getElementById("inspector-hooks").textContent = "Not inspected";
        tableState("No file inventory has been recorded.");
        findings.replaceChildren(make("p", "table-state", "No inspection findings have been recorded."));
        return;
      }
      document.getElementById("inspector-hooks").textContent = inspection.parsed_metadata["Visible-Runtime-Hooks"] || "Not reported";
      files.replaceChildren();
      for (const item of inspection.files) {
        const row = make("tr");
        const digest = make("td");
        digest.append(make("span", "mono digest", item.sha256));
        row.append(make("td", "", item.path), make("td", "numeric", formatBytes(item.size)), digest);
        files.append(row);
      }
      if (!inspection.files.length) tableState("The Inspector did not record any files.");
      findings.replaceChildren();
      if (!inspection.findings.length) {
        findings.append(make("p", "table-state", "No findings were recorded."));
      } else {
        for (const finding of inspection.findings) {
          const item = make("article", "inspection-item");
          item.append(make("strong", "", `${finding.severity}: ${finding.code}`));
          item.append(make("p", "inspection-summary", finding.message));
          findings.append(item);
        }
      }
    } catch (error) {
      tableState(error.message || "The Inspector report could not be loaded.");
      findings.replaceChildren();
    }
  }

  run.addEventListener("click", async () => {
    run.disabled = true;
    try {
      await api(`/api/packages/${encodeURIComponent(id)}/inspection`, { method: "POST" });
      showNotice("Inspection record added.");
      await load();
    } catch (error) {
      showNotice(error.message || "The package could not be inspected.", true);
    } finally {
      run.disabled = false;
    }
  });

  load();
})();
