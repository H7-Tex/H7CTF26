(() => {
  const { api, badge, formatDate, link, make } = window.Exchange;
  const table = document.getElementById("inspection-rows");
  if (table) loadInspections();
  if (document.getElementById("policy-rows")) loadPolicy();

  async function loadInspections() {
    try {
      const result = await api("/api/inspections");
      const count = document.getElementById("inspection-count");
      count.textContent = `${result.total} inspection ${result.total === 1 ? "record" : "records"}`;
      table.replaceChildren();
      if (!result.items.length) return empty(table, 6, "No inspection records are available.");
      for (const item of result.items) {
        const row = make("tr");
        const packageCell = make("td");
        packageCell.append(link(`/packages/${encodeURIComponent(item.artifact_id)}`, item.package_name, "package-link"));
        row.append(packageCell, make("td", "mono", item.version));
        const status = make("td"); status.append(badge(item.status)); row.append(status);
        row.append(make("td", "numeric", String(item.file_count)));
        row.append(make("td", "", formatDate(item.created_at)));
        const digest = make("td"); digest.append(make("span", "mono digest", item.sha256)); row.append(digest);
        table.append(row);
      }
    } catch (error) {
      document.getElementById("inspection-count").textContent = "Inspections unavailable";
      empty(table, 6, error.message || "Inspection records could not be loaded.");
    }
  }

  async function loadPolicy() {
    const rows = document.getElementById("policy-rows");
    try {
      const policy = await api("/api/policy");
      document.getElementById("policy-name").textContent = policy.name;
      document.getElementById("policy-revision").textContent = policy.revision;
      rows.replaceChildren();
      for (const check of policy.checks) {
        const row = make("tr");
        row.append(make("td", "mono", check.code), make("td", "", check.description));
        row.append(make("td", "", check.code === "license_metadata" ? "Informational" : "Required"));
        rows.append(row);
      }
    } catch (error) {
      document.getElementById("policy-name").textContent = error.message || "Policy could not be loaded.";
      empty(rows, 3, "Policy details are unavailable.");
    }
  }

  function empty(target, span, message) {
    const row = make("tr");
    const cell = make("td", "table-state", message);
    cell.colSpan = span;
    row.append(cell);
    target.replaceChildren(row);
  }
})();
