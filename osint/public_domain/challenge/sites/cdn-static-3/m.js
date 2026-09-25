/* lightweight first-party metrics beacon. origin: cdn-static-3.abu.rocks */
(function () {
  var s = document.currentScript;
  var acct = s && s.getAttribute("data-account");
  if (!acct) return;
  try {
    var p = {
      a: acct,
      u: location.pathname,
      r: document.referrer || "",
      w: screen.width,
      t: Date.now()
    };
    var q = Object.keys(p).map(function (k) { return k + "=" + encodeURIComponent(p[k]); }).join("&");
    (new Image()).src = "https://cdn-static-3.abu.rocks/p.gif?" + q;
  } catch (e) {}
})();
