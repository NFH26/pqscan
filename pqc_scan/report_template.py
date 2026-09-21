"""Self-contained HTML report template.

Design notes, so a later change does not quietly undo them:

* Status colours (good / warning / serious / critical) carry readiness and score bands.
  They are reserved for state and are never used as series colours. Every status colour is
  paired with a text label, so meaning never rests on hue alone.
* Colour tokens are declared once as custom properties and redeclared for dark mode under
  BOTH the OS media query and an explicit data-theme, so the in-page toggle wins either way.
* No external assets: the file is opened from disk, emailed, and printed.
"""

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC readiness - {{ profile_name }}</title>
<style>
:root {
  color-scheme: light;
  --surface: #fcfcfb; --plane: #f9f9f7;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --rule: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
  --accent: #2a78d6;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --surface: #1a1a19; --plane: #0d0d0d;
    --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --rule: #383835; --ring: rgba(255,255,255,0.10);
    --accent: #3987e5;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --surface: #1a1a19; --plane: #0d0d0d;
  --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --rule: #383835; --ring: rgba(255,255,255,0.10);
  --accent: #3987e5;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--plane); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 32px 16px 72px; }
header.top { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-start; justify-content: space-between; margin-bottom: 8px; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 17px; margin: 40px 0 12px; letter-spacing: -0.01em; }
h3 { font-size: 14px; margin: 0 0 8px; }
.sub { color: var(--ink-2); font-size: 13px; margin: 0; }
.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 20px; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px 24px; font-size: 13px; }
.meta div span { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
.meta div b { font-weight: 600; word-break: break-word; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-top: 14px; }
.tile { background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 16px 18px; }
.tile .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
.tile .value { font-size: 30px; font-weight: 600; letter-spacing: -0.02em; margin-top: 4px; }
.tile .note { color: var(--ink-2); font-size: 12px; margin-top: 2px; }
/* stacked composition bar: 2px surface gap between segments, 4px rounded outer ends */
.stack { display: flex; gap: 2px; height: 26px; margin: 6px 0 12px; }
.stack .seg { border-radius: 2px; min-width: 3px; }
.stack .seg:first-child { border-top-left-radius: 4px; border-bottom-left-radius: 4px; }
.stack .seg:last-child { border-top-right-radius: 4px; border-bottom-right-radius: 4px; }
.legend { display: flex; flex-wrap: wrap; gap: 8px 20px; font-size: 13px; color: var(--ink-2); }
.legend span.sw { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 7px; vertical-align: -1px; }
.bars { display: grid; grid-template-columns: max-content 1fr max-content; gap: 7px 12px; align-items: center; font-size: 13px; }
.bars .track { background: var(--grid); border-radius: 4px; height: 12px; }
.bars .fill { height: 12px; border-radius: 4px; }
.cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 0 0 12px; }
.controls input, .controls select {
  font: inherit; font-size: 13px; padding: 7px 10px; border-radius: 8px;
  border: 1px solid var(--rule); background: var(--surface); color: var(--ink);
}
.controls input { flex: 1 1 240px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--grid); vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; cursor: pointer; white-space: nowrap; user-select: none; }
th[data-sort]:hover { color: var(--ink); }
th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
tbody tr:hover { background: color-mix(in srgb, var(--accent) 7%, transparent); }
.pill { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.pill .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.score { font-variant-numeric: tabular-nums; font-weight: 600; }
.host { font-weight: 600; word-break: break-all; }
.tag { display: inline-block; font-size: 11px; color: var(--ink-2); background: var(--plane); border: 1px solid var(--grid); border-radius: 999px; padding: 1px 8px; margin: 1px 3px 1px 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
details { border-top: 1px solid var(--grid); padding: 10px 0; }
details summary { cursor: pointer; font-weight: 600; font-size: 13px; }
details pre { white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--ink-2); margin: 10px 0 0; }
.toggle { font: inherit; font-size: 12px; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--rule); background: var(--surface); color: var(--ink-2); cursor: pointer; }
.prose { color: var(--ink-2); font-size: 13px; max-width: 78ch; }
.prose li { margin-bottom: 5px; }
.empty { color: var(--muted); font-size: 13px; }
@media print {
  body { background: #fff; }
  .controls, .toggle { display: none; }
  details { break-inside: avoid; }
  details[open] summary ~ * { display: block; }
  .card, .tile { border-color: #ccc; }
}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div>
    <h1>Post-quantum readiness</h1>
    <p class="sub">LATICE Locate phase &middot; profile <b>{{ profile_name }}</b>{% if rules_version %} &middot; rules {{ rules_version }}{% endif %}</p>
  </div>
  <button class="toggle" id="theme">Toggle theme</button>
</header>

<div class="card">
  <div class="meta">
    <div><span>Operator</span><b>{{ meta.operator or "not recorded" }}</b></div>
    <div><span>Engagement</span><b>{{ meta.engagement or "not recorded" }}</b></div>
    <div><span>Scan time (UTC)</span><b>{{ meta.scan_time or "not recorded" }}</b></div>
    <div><span>Authorised</span><b>{{ meta.authorised }}</b></div>
    <div><span>Scope file</span><b>{{ meta.scope_file or "none" }}</b></div>
    <div><span>Tool version</span><b>{{ meta.tool_version or "unknown" }}</b></div>
  </div>
</div>

<h2>Scanner capability</h2>
<div class="card prose">
  <p style="margin-top:0">A "no post-quantum support" result is only meaningful if the scanner was able to ask
  the question. This scan used the <b>{{ meta.probe_method }}</b> probe, which sends its own ClientHello and
  therefore does not depend on the local OpenSSL for group detection.
  Local OpenSSL was <span class="mono">{{ meta.openssl_version or "not recorded" }}</span>.</p>
  <p style="margin-bottom:0">Groups offered to every reachable endpoint:
  {% for group in meta.groups_offered %}<span class="tag mono">{{ group }}</span>{% else %}<span class="empty">not recorded</span>{% endfor %}</p>
</div>

<h2>Summary</h2>
<div class="tiles">
  <div class="tile"><div class="label">Endpoints</div><div class="value">{{ summary.total }}</div><div class="note">{{ summary.conf_measured }} scored for confidentiality, {{ summary.auth_measured }} for authentication</div></div>
  <div class="tile"><div class="label">Post-quantum today</div><div class="value" style="color:var(--good)">{{ summary.readiness.pure_pq_approved }}</div><div class="note">negotiating a pure approved group</div></div>
  <div class="tile"><div class="label">Hybrid, transitional</div><div class="value" style="color:var(--warning)">{{ summary.readiness.hybrid_transitional }}</div><div class="note">approved now, not beyond 2030</div></div>
  <div class="tile"><div class="label">Classical only</div><div class="value" style="color:var(--critical)">{{ summary.readiness.classical_only }}</div><div class="note">no post-quantum key exchange</div></div>
</div>

{% if actions %}
<h2>What to do next</h2>
<p class="prose" style="margin-top:-4px">Most urgent first. Every recommendation names the endpoints
it applies to, with the service each one runs; select an endpoint to jump to its measurements.</p>
<div class="card" style="padding:4px 8px">
<table>
  <thead><tr><th style="width:3em">#</th><th style="width:8em">Effort</th><th>Action</th><th style="width:22em">Applies to</th></tr></thead>
  <tbody>
  {% for action in actions %}
    <tr>
      <td class="num">{{ loop.index }}</td>
      <td><span class="tag">{{ action.effort }}</span></td>
      <td>
        <b style="color:{{ action.priority_color }}">{{ action.action }}</b>
        <div class="sub" style="margin-top:3px">{{ action.why }}</div>
      </td>
      <td>{% for host in action.hosts %}{% if host.anchor %}<a class="tag mono" href="#{{ host.anchor }}">{{ host.label }}</a>{% else %}<span class="tag mono">{{ host.label }}</span>{% endif %}{% endfor %}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% endif %}

<h2>Readiness mix</h2>
<div class="card">
  <div class="stack">
    {% for row in summary.readiness_rows %}{% if row.count %}<div class="seg" style="width:{{ row.pct }}%;background:{{ row.color }}" title="{{ row.label }}: {{ row.count }} of {{ summary.total }}"></div>{% endif %}{% endfor %}
  </div>
  <div class="legend">
    {% for row in summary.readiness_rows %}<div><span class="sw" style="background:{{ row.color }}"></span>{{ row.label }} &mdash; {{ row.count }} ({{ row.pct }}%)</div>{% endfor %}
  </div>
</div>

<h2>Score distribution</h2>
<p class="prose" style="margin-top:-4px"><b>These are risk scores, so lower is better.</b> 0 means the endpoint already meets the profile for that dimension; 100 is the worst case. Confidentiality risk is about the key exchange protecting traffic in transit; authentication risk is about the certificate chain proving identity.</p>
<div class="cols">
  {% for chart in summary.distributions %}
  <div class="card">
    <h3>{{ chart.title }}</h3>
    <div class="bars">
      {% for bucket in chart.buckets %}
      <div>{{ bucket.label }}</div>
      <div class="track"><div class="fill" style="width:{{ bucket.pct }}%;background:{{ bucket.color }}"></div></div>
      <div class="num">{{ bucket.count }}</div>
      {% endfor %}
    </div>
    <p class="sub" style="margin-top:10px">Average {{ chart.average }} across {{ chart.measured }} measured endpoints.</p>
  </div>
  {% endfor %}
</div>

<h2>Endpoints</h2>
<div class="controls">
  <input id="q" type="search" placeholder="Filter by host, group or finding" aria-label="Filter endpoints">
  <select id="readiness" aria-label="Filter by readiness">
    <option value="">All readiness states</option>
    {% for row in summary.readiness_rows %}<option value="{{ row.key }}">{{ row.label }}</option>{% endfor %}
  </select>
  <span class="sub" id="count"></span>
</div>
<div class="card" style="padding:4px 8px">
<table id="hosts">
  <thead><tr>
    <th data-sort="text">Host</th>
    <th data-sort="text">TLS</th>
    <th data-sort="text">Key exchange</th>
    <th data-sort="text">Readiness</th>
    <th data-sort="num" class="num">Conf risk</th>
    <th data-sort="num" class="num">Auth risk</th>
    <th data-sort="text">Findings</th>
  </tr></thead>
  <tbody>
  {% for row in rows %}
    <tr data-readiness="{{ row.readiness_key }}" id="{{ row.anchor }}">
      <td class="host">{{ row.host }}<br><span class="sub">{{ row.service }}</span></td>
      <td class="mono">{{ row.tls }}</td>
      <td class="mono">{{ row.group }}{% if row.capability %}<br><span class="sub">can negotiate {{ row.capability }}</span>{% endif %}</td>
      <td><span class="pill" style="color:{{ row.readiness_color }}"><span class="dot" style="background:{{ row.readiness_color }}"></span>{{ row.readiness_label }}</span></td>
      <td class="num"><span class="score" style="color:{{ row.conf_color }}">{{ row.conf }}</span></td>
      <td class="num"><span class="score" style="color:{{ row.auth_color }}">{{ row.auth }}</span></td>
      <td>{% for item in row.findings %}<span class="tag">{{ item }}</span>{% else %}<span class="empty">none</span>{% endfor %}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
</div>

{% if issues %}
<h2>Issues</h2>
<div class="card">
  <table>
    <thead><tr><th>Host</th><th>Detail</th></tr></thead>
    <tbody>
    {% for issue in issues %}<tr><td class="host">{{ issue.host }}</td><td class="mono">{{ issue.detail }}</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<h2>How each score was reached</h2>
<div class="card" style="padding:4px 20px">
{% for row in rows %}
  <details>
    <summary>{{ row.host }} &mdash; confidentiality risk {{ row.conf }}, authentication risk {{ row.auth }}</summary>
    <pre>Confidentiality:
{{ row.conf_explanation or "not measured" }}

Authentication:
{{ row.auth_explanation or "not measured" }}</pre>
    {% if row.actions %}
    <div style="margin:10px 0 4px"><b style="font-size:13px">Recommended</b></div>
    <ul class="prose" style="margin:0">
      {% for item in row.actions %}<li><b>{{ item.action }}</b> <span class="tag">{{ item.effort }}</span><br>{{ item.why }}</li>{% endfor %}
    </ul>
    {% endif %}
  </details>
{% endfor %}
</div>

<h2>Certificate inventory</h2>
<div class="card" style="padding:4px 8px">
<table>
  <thead><tr><th>Subject</th><th>Issuer</th><th>Key</th><th>Signature</th><th>Expires</th><th>Used by</th></tr></thead>
  <tbody>
  {% for cert in certs %}
    <tr>
      <td class="host">{{ cert.subject_cn or "unknown" }}</td>
      <td>{{ cert.issuer or "unknown" }}</td>
      <td class="mono">{{ cert.pub_key_algo }}{% if cert.pub_key_size %} {{ cert.pub_key_size }}{% endif %}</td>
      <td class="mono">{{ cert.sig_algo }}</td>
      <td class="mono">{{ cert.not_after }}</td>
      <td>{% for usage in cert.usages %}<span class="tag mono">{{ usage }}</span>{% endfor %}</td>
    </tr>
  {% else %}
    <tr><td colspan="6" class="empty">No certificates were collected.</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>

<h2>Method and limitations</h2>
<div class="card prose">
  <p style="margin-top:0">Classifications come from the rule profile
  <b>{{ profile_name }}</b>{% if rules_version %} ({{ rules_version }}){% endif %}, which cites the ASD ISM control
  behind every entry. Scores are additive, multiplied by the asset's criticality, then capped at 100.
  Controls the ISM words "is used" are treated as mandatory; anything it words "preferably" is recorded as an
  informational note with a token weight, so a preference can never outweigh a control breach.</p>
  <ul>
    <li><b>Hybrids are transitional, not approved.</b> The ISM says hybrid post-quantum and traditional
      schemes are "not recommended; however, it is not prohibited", and both halves of the common
      X25519MLKEM768 hybrid stop being approved after 2030.</li>
    <li><b>Key exchange is measured twice.</b> Once as a default client would negotiate it, which is what
      protects traffic today, and once by offering each group explicitly, which is what the endpoint is
      capable of. The table shows the second only where it is stronger than the first.</li>
    <li><b>A capped score hides detail.</b> Where a score reads 100, read the findings, not the number.</li>
    <li><b>Not testable is not a pass or a fail.</b> Endpoints that did not resolve or did not answer are
      excluded from the readiness percentages and listed under Issues.</li>
    <li><b>Certificate trust depends on the local trust store</b>, so validation findings reflect this
      scanner's view of the chain rather than that of any particular client.</li>
  </ul>
</div>

<footer class="prose" style="margin-top:48px;padding-top:16px;border-top:1px solid var(--grid);font-size:12px">
  Generated by <b>pqc-scan</b>, an open-source post-quantum readiness scanner by
  Nayef Alharbi, licensed Apache-2.0.
  Classifications cite the ASD Information Security Manual, Guidelines for cryptography.
  This report describes what the scanner observed; it is not a compliance certification.
</footer>

</div>
<script>
(function () {
  var root = document.documentElement;
  var toggle = document.getElementById("theme");
  toggle.addEventListener("click", function () {
    var dark = root.getAttribute("data-theme") === "dark";
    root.setAttribute("data-theme", dark ? "light" : "dark");
  });

  var table = document.getElementById("hosts");
  var body = table.querySelector("tbody");
  var rows = Array.prototype.slice.call(body.querySelectorAll("tr"));
  var query = document.getElementById("q");
  var readiness = document.getElementById("readiness");
  var count = document.getElementById("count");

  function apply() {
    var text = query.value.toLowerCase();
    var state = readiness.value;
    var shown = 0;
    rows.forEach(function (row) {
      var matchText = !text || row.textContent.toLowerCase().indexOf(text) !== -1;
      var matchState = !state || row.getAttribute("data-readiness") === state;
      var visible = matchText && matchState;
      row.style.display = visible ? "" : "none";
      if (visible) { shown += 1; }
    });
    count.textContent = shown + " of " + rows.length + " endpoints";
  }
  query.addEventListener("input", apply);
  readiness.addEventListener("change", apply);
  apply();

  table.querySelectorAll("th[data-sort]").forEach(function (header, index) {
    var ascending = true;
    header.addEventListener("click", function () {
      var numeric = header.getAttribute("data-sort") === "num";
      rows.sort(function (a, b) {
        var left = a.children[index].textContent.trim();
        var right = b.children[index].textContent.trim();
        if (numeric) {
          var lv = parseFloat(left); var rv = parseFloat(right);
          if (isNaN(lv)) { lv = -1; }
          if (isNaN(rv)) { rv = -1; }
          return ascending ? lv - rv : rv - lv;
        }
        return ascending ? left.localeCompare(right) : right.localeCompare(left);
      });
      ascending = !ascending;
      rows.forEach(function (row) { body.appendChild(row); });
    });
  });
})();
</script>
</body>
</html>
"""
