(() => {
  const { api, badge, formatBytes, formatDate, make, showNotice } = window.Exchange;
  const id = window.packageArtifactId;
  const inspectButton = document.getElementById("inspect-package");
  const runtimeButton = document.getElementById("run-package");
  const manifestRows = document.getElementById("manifest-rows");
  const historyPanel = document.getElementById("package-inspections");

  function stateRow(target, columns, message) {
    const row = make("tr");
    const cell = make("td", "table-state", message);
    cell.colSpan = columns;
    row.append(cell);
    target.replaceChildren(row);
  }

  function appendMetadata(data) {
    document.getElementById("package-name").textContent = data.package.package_name;
    document.getElementById("breadcrumb-package").textContent = data.package.package_name;
    document.getElementById("package-version").textContent = data.package.version;
    document.getElementById("package-filename").textContent = data.package.original_filename;
    document.getElementById("package-id").textContent = data.package.artifact_id;
    document.getElementById("package-uploaded").textContent = formatDate(data.package.created_at);
    document.getElementById("package-size").textContent = formatBytes(data.package.size);
    document.getElementById("package-sha").textContent = data.package.sha256;
    const inspection = data.latest_inspection;
    const meta = inspection ? inspection.parsed_metadata : {};
    document.getElementById("package-summary").textContent = meta.Summary || "No package summary was recorded.";
    document.getElementById("package-license").textContent = meta["License-Expression"] || meta.License || "Not declared";
    document.getElementById("package-python").textContent = meta["Requires-Python"] || "Not specified";
    const assurance = document.getElementById("package-assurance");
    assurance.replaceChildren(badge(inspection ? inspection.status : "not_recorded"));
  }

  function renderHistory(items) {
    if (!items.length) {
      historyPanel.replaceChildren(make("p", "table-state", "No inspection has been recorded for this package."));
      return;
    }
    historyPanel.replaceChildren();
    for (const item of items) {
      const article = make("article", "inspection-item");
      const date = make("time", "inspection-date", formatDate(item.created_at));
      date.dateTime = item.created_at;
      const detail = make("div");
      detail.append(badge(item.status), make("p", "inspection-summary", item.summary));
      if (item.findings.length) {
        const list = make("ul", "finding-list");
        for (const finding of item.findings) list.append(make("li", "", finding.message));
        detail.append(list);
      }
      article.append(date, detail);
      historyPanel.append(article);
    }
  }

  async function loadManifest() {
    try {
      const result = await api(`/api/packages/${encodeURIComponent(id)}/manifest`);
      manifestRows.replaceChildren();
      document.getElementById("file-count").textContent = `${result.files.length} files`;
      for (const item of result.files) {
        const row = make("tr");
        row.append(make("td", "", item.path), make("td", "numeric", formatBytes(item.size)));
        const digest = make("td");
        digest.append(make("span", "mono digest", item.sha256));
        row.append(digest);
        manifestRows.append(row);
      }
    } catch (error) {
      document.getElementById("file-count").textContent = "";
      stateRow(manifestRows, 3, error.status === 409 ? "No package inventory has been recorded." : error.message);
    }
  }

  async function loadPackage() {
    try {
      const data = await api(`/api/packages/${encodeURIComponent(id)}`);
      const history = await api(`/api/packages/${encodeURIComponent(id)}/inspection`);
      appendMetadata(data);
      renderHistory(history.items);
      await loadManifest();
      if (new URLSearchParams(window.location.search).get("uploaded") === "1") showNotice("Package uploaded.");
    } catch (error) {
      showNotice(error.message || "Package details could not be loaded.", true);
      document.getElementById("package-name").textContent = "Package unavailable";
      stateRow(manifestRows, 3, "The package details could not be loaded.");
      historyPanel.replaceChildren();
    }
  }

  inspectButton.addEventListener("click", async () => {
    inspectButton.disabled = true;
    inspectButton.setAttribute("aria-busy", "true");
    inspectButton.lastChild.textContent = " Inspecting…";
    try {
      await api(`/api/packages/${encodeURIComponent(id)}/inspection`, { method: "POST" });
      showNotice("Inspection record added.");
      await loadPackage();
    } catch (error) {
      showNotice(error.message || "The inspection could not be completed.", true);
    } finally {
      inspectButton.disabled = false;
      inspectButton.removeAttribute("aria-busy");
      inspectButton.lastChild.textContent = " Run inspection";
    }
  });

  runtimeButton.addEventListener("click", async () => {
    runtimeButton.disabled = true;
    runtimeButton.setAttribute("aria-busy", "true");
    runtimeButton.textContent = "Starting session…";
    try {
      const job = await api(`/api/packages/${encodeURIComponent(id)}/runtime`, { method: "POST" });
      if (job.flag) {
        const released = document.getElementById("runtime-flag");
        released.textContent = job.flag;
        released.hidden = false;
        showNotice("Runtime session completed.");
      } else {
        window.location.assign(`/runtime?job=${encodeURIComponent(job.job_id)}`);
      }
    } catch (error) {
      showNotice(error.message || "The runtime session could not be created.", true);
    } finally {
      runtimeButton.disabled = false;
      runtimeButton.removeAttribute("aria-busy");
      runtimeButton.textContent = "Create runtime session";
    }
  });

  loadPackage();
})();
