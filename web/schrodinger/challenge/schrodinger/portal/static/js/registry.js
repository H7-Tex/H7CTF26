(() => {
  const { api, badge, formatBytes, formatDate, link, make, showNotice } = window.Exchange;
  const body = document.getElementById("package-rows");
  const search = document.getElementById("registry-search");
  const count = document.getElementById("registry-count");
  const upload = document.getElementById("package-upload");

  function cell(row, text, className = "") {
    const node = make("td", className, text);
    row.append(node);
    return node;
  }

  async function loadPackages(query = "") {
    body.replaceChildren(make("tr", "", ""));
    const loading = body.firstElementChild;
    const state = make("td", "table-state", "Loading registry…");
    state.colSpan = 6;
    loading.append(state);
    try {
      const params = new URLSearchParams({ limit: "100", q: query });
      const result = await api(`/api/packages?${params}`);
      body.replaceChildren();
      count.textContent = `${result.total} ${result.total === 1 ? "package" : "packages"}`;
      if (!result.items.length) {
        const row = make("tr");
        const empty = make("td", "table-state", query ? "No packages match this search." : "No packages are registered yet.");
        empty.colSpan = 6;
        row.append(empty);
        body.append(row);
        return;
      }
      for (const item of result.items) {
        const row = make("tr");
        const packageCell = cell(row, "");
        packageCell.append(link(`/packages/${encodeURIComponent(item.package_id)}`, item.package_name, "package-link"));
        packageCell.append(make("span", "package-cell-note", item.filename));
        cell(row, item.version, "mono");
        const assurance = cell(row, "");
        assurance.append(badge(item.assurance));
        cell(row, formatDate(item.created_at));
        cell(row, formatBytes(item.size), "numeric");
        const digest = cell(row, "");
        digest.append(make("span", "mono digest", item.sha256));
        body.append(row);
      }
    } catch (error) {
      body.replaceChildren();
      const row = make("tr");
      const state = make("td", "table-state", error.message || "The registry could not be loaded.");
      state.colSpan = 6;
      row.append(state);
      body.append(row);
      count.textContent = "Registry unavailable";
    }
  }

  search.addEventListener("input", () => {
    clearTimeout(search.timer);
    search.timer = setTimeout(() => loadPackages(search.value.trim()), 120);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      event.preventDefault();
      search.focus();
    }
  });
  upload.addEventListener("change", async () => {
    const file = upload.files && upload.files[0];
    if (!file) return;
    const label = document.querySelector("label[for='package-upload']");
    label.setAttribute("aria-busy", "true");
    label.classList.add("is-busy");
    try {
      const form = new FormData();
      form.append("file", file);
      const result = await api("/api/packages", { method: "POST", body: form });
      window.location.assign(`/packages/${encodeURIComponent(result.package_id)}?uploaded=1`);
    } catch (error) {
      showNotice(error.message || "The package could not be uploaded.", true);
    } finally {
      label.removeAttribute("aria-busy");
      label.classList.remove("is-busy");
      upload.value = "";
    }
  });

  loadPackages();
})();
