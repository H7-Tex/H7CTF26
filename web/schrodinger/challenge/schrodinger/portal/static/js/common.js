(() => {
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  async function api(path, options = {}) {
    const response = await fetch(path, { headers: { Accept: "application/json" }, ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = typeof payload.detail === "string" ? payload.detail : `Request failed (${response.status})`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function badge(status) {
    const labels = {
      passed: "Passed",
      passed_with_advisories: "Passed with advisories",
      rejected: "Rejected",
      not_recorded: "Not recorded",
      completed: "Completed",
      failed: "Failed",
      running: "Running",
      queued: "Queued",
    };
    const value = labels[status] || status.replaceAll("_", " ");
    return make("span", `status-badge status-${status}`, value);
  }

  function formatDate(value) {
    if (!value) return "-";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "-" : new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
    }).format(date) + " UTC";
  }

  function formatBytes(value) {
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
    return `${(value / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function showNotice(message, isError = false) {
    const notice = document.getElementById("notice");
    if (!notice) return;
    notice.textContent = message;
    notice.classList.toggle("is-error", isError);
    notice.hidden = false;
  }

  function link(href, text, className = "") {
    const node = make("a", className, text);
    node.href = href;
    return node;
  }

  window.Exchange = { api, badge, formatBytes, formatDate, link, make, showNotice };
})();
