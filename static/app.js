// nzbd client script. The CSP forbids inline script; this file is the only one.
// htmx is progressive enhancement: every page works without it. Its hardening is also set
// here, so it holds even if the <meta name="htmx-config"> tag is ever dropped from a template.
if (window.htmx && window.htmx.config) {
  var cfg = window.htmx.config;
  cfg.allowEval = false;
  cfg.allowScriptTags = false;
  cfg.includeIndicatorStyles = false; // the CSP forbids the inline <style> htmx would inject
  cfg.historyCacheSize = 0; // no page snapshots in localStorage
  cfg.selfRequestsOnly = true;
}
// Adds the CSRF synchronizer token to every HTMX request (AUTH_SPEC, section CSRF).
document.addEventListener("htmx:configRequest", function (event) {
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) {
    event.detail.headers["X-CSRF-Token"] = meta.content;
  }
});
// Select-all for the bulk-actions column (T119). The checkbox is rendered hidden: without this
// script the per-row checkboxes and the form work unchanged, so nothing depends on it.
(function () {
  function reveal() {
    var boxes = document.querySelectorAll("input.select-all");
    for (var i = 0; i < boxes.length; i++) {
      boxes[i].hidden = false;
    }
  }
  document.addEventListener("change", function (event) {
    var t = event.target;
    if (!t || !t.classList || !t.classList.contains("select-all")) {
      return;
    }
    var form = t.form || document;
    var rows = form.querySelectorAll('input[type="checkbox"][name="id"]');
    for (var i = 0; i < rows.length; i++) {
      rows[i].checked = t.checked;
    }
  });
  document.addEventListener("DOMContentLoaded", reveal);
  document.addEventListener("htmx:afterSettle", reveal);
})();
