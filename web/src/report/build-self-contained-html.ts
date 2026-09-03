import type { ReportData } from "./build-report-data";

/**
 * Build a self-contained HTML snapshot with tabs like the live ReportView.
 * Tabs: Overview | Findings | Reviews | Remediation | Frameworks
 * No external CSS/JS — styles + tab JS inlined, window.REPORT_DATA embedded.
 */
export function buildSelfContainedHtml(
  data: ReportData,
  meta: { tenantDomain: string; runId: string; startedAt: string; finishedAt?: string; title?: string },
): string {
  const title = meta.title ?? `M365 Assessment — ${meta.tenantDomain || meta.runId}`;
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const escCell = (s: string) => esc(s || "—");

  const statusBadge = (s: string) => {
    const cls =
      s === "Pass" ? "badge-pass" :
      s === "Fail" ? "badge-fail" :
      s === "Warning" ? "badge-warning" :
      s === "Review" ? "badge-review" :
      s === "Skipped" ? "badge-skipped" : "badge-info";
    return `<span class="badge ${cls}">${esc(s)}</span>`;
  };

  const sevBadge = (sev?: string) => {
    const v = (sev ?? "unknown").toLowerCase();
    const cls = v === "critical" ? "sev-critical" : v === "high" || v === "medium" ? "sev-high" : v === "low" ? "sev-low" : "sev-info";
    return `<span class="badge ${cls}">${esc(sev ?? "unknown")} severity</span>`;
  };

  const evaluated = data.summary.pass + data.summary.fail + data.summary.warning + data.summary.review;

  const findingsRows = data.findings
    .map(
      (f) => `<tr>
        <td>${esc(f.domain)}</td>
        <td>${esc(f.category)}</td>
        <td><strong>${esc(f.setting)}</strong><div class="mono">${esc(f.checkId)}</div></td>
        <td>${escCell(f.currentValue)}</td>
        <td>${escCell(f.recommendedValue)}</td>
        <td>${statusBadge(f.status)}</td>
        <td>${sevBadge(f.severity)}</td>
      </tr>
      <tr class="detail"><td colspan="7"><strong>Remediation:</strong> ${esc(f.remediation || "No guidance")}${f.skipReason ? `<br><strong>Skip reason:</strong> ${esc(f.skipReason)}` : ""}${f.evidenceSource ? `<br><strong>Source:</strong> ${esc(f.evidenceSource)}` : ""}</td></tr>`,
    )
    .join("\n");

  const reviewRows = data.findings
    .filter((f) => f.status === "Review")
    .map(
      (f) => `<tr>
        <td>${esc(f.domain)}</td>
        <td>${esc(f.category)}</td>
        <td><strong>${esc(f.setting)}</strong><div class="mono">${esc(f.checkId)}</div></td>
        <td>${escCell(f.currentValue)}</td>
        <td>${escCell(f.recommendedValue)}</td>
        <td>${sevBadge(f.severity)}</td>
      </tr>
      <tr class="detail"><td colspan="6"><strong>Remediation:</strong> ${esc(f.remediation || "—")}<br><em>Needs human judgment — counts as 0 in pass rate.</em></td></tr>`,
    )
    .join("\n");

  const remediationCards = data.remediationItems
    .map(
      (r) => `<div class="card">
        <div class="card-head">${sevBadge(r.finding.severity)} <strong>${esc(r.finding.setting)}</strong> <span class="mono">${esc(r.finding.checkId)}</span></div>
        <div class="card-body">
          <div><strong>Category:</strong> ${esc(r.finding.category)} — <strong>Domain:</strong> ${esc(r.finding.domain)}</div>
          <div><strong>Found:</strong> ${escCell(r.finding.currentValue)}</div>
          <div><strong>Expected:</strong> ${escCell(r.finding.recommendedValue)}</div>
          <div><strong>Remediation:</strong> ${esc(r.finding.remediation || "—")}</div>
        </div>
      </div>`,
    )
    .join("\n");

  const frameworksRows = data.frameworks
    .map(
      (fw) => `<tr><td><strong>${esc(fw.name)}</strong><div class="mono">${esc(fw.id)}</div></td><td>${fw.scorePct}%</td><td>${fw.controlsCovered}/${fw.controlsTotal}</td><td>${fw.checks.length} checks</td></tr>`,
    )
    .join("\n");

  const reportDataJson = `window.REPORT_DATA = ${JSON.stringify(data).replace(/</g, "\\u003c")};`;

  return `<!DOCTYPE html>
<html data-theme="neon" data-mode="dark" data-density="compact">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${esc(title)}</title>
<script>try{var d=document.documentElement;var t=localStorage.getItem('m365-theme');var m=localStorage.getItem('m365-mode');if(t)d.dataset.theme=t;if(m)d.dataset.mode=m;}catch(e){}</script>
<style>
:root{--background:#09090b;--foreground:#fafafa;--card:#18181b;--card-foreground:#fafafa;--popover:#18181b;--popover-foreground:#fafafa;--primary:#3b82f6;--primary-foreground:#fafafa;--secondary:#18181b;--secondary-foreground:#fafafa;--muted:#27272a;--muted-foreground:#a1a1aa;--accent:#27272a;--accent-foreground:#fafafa;--destructive:#ef4444;--success:#22c55e;--warning:#f59e0b;--review:#a855f7;--border:#27272a;--radius:0.625rem}
*{box-sizing:border-box}html,body{margin:0;padding:0;background:var(--background);color:var(--foreground);font-family:InterVariable,Inter,ui-sans-serif,system-ui,sans-serif;font-size:14px;line-height:1.5}
a{color:var(--primary)}h1{font-size:24px;margin:0}h2{font-size:18px;margin:24px 0 8px}h3{font-size:16px;margin:16px 0 8px}
.container{max-width:1120px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:12px 16px;margin-bottom:12px}
.badge{display:inline-flex;align-items:center;border-radius:9999px;padding:2px 8px;font-size:12px;font-weight:500;border:1px solid transparent}
.badge-pass{background:rgba(34,197,94,0.12);color:var(--success);border-color:transparent}
.badge-fail{background:rgba(239,68,68,0.12);color:var(--destructive)}
.badge-warning{background:rgba(245,158,11,0.12);color:var(--warning)}
.badge-review{background:rgba(168,85,247,0.15);color:var(--review);border-color:rgba(168,85,247,0.3)}
.badge-skipped,.badge-info{background:var(--muted);color:var(--muted-foreground)}
.sev-critical{background:rgba(239,68,68,0.12);color:var(--destructive)}
.sev-high{background:rgba(245,158,11,0.12);color:var(--warning)}
.sev-low{background:rgba(34,197,94,0.12);color:var(--success)}
.sev-info{background:var(--muted);color:var(--muted-foreground)}
.mono{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted-foreground)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border:1px solid var(--border);padding:8px;text-align:left;vertical-align:top}
th{background:var(--muted);color:var(--foreground);font-weight:600}
tr.detail td{background:rgba(39,39,42,0.4);font-size:12px}
.grid5{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.stat{padding:12px;border:1px solid var(--border);border-radius:var(--radius);background:var(--card)}
.stat .label{font-size:12px;color:var(--muted-foreground)}
.stat .value{font-size:20px;font-weight:600}
.alert{border:1px solid var(--border);border-radius:var(--radius);padding:12px 16px;margin:12px 0;background:var(--card)}
.alert-review{border-color:rgba(168,85,247,0.3);background:rgba(168,85,247,0.08)}
.tabs{border-bottom:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.tab{padding:8px 14px;font-size:14px;font-weight:500;border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;background:transparent;color:var(--muted-foreground);cursor:pointer}
.tab.active{background:var(--card);color:var(--foreground);border-color:var(--border);border-bottom:1px solid var(--card);margin-bottom:-1px}
.tab-review.active{color:var(--review);border-color:rgba(168,85,247,0.3)}
.badge-tab{margin-left:6px;padding:1px 6px;font-size:11px}
.tab-panel{display:none;padding-top:16px}
.tab-panel.active{display:block}
@media print{.tabs{display:none}.tab-panel{display:block !important}body{background:white;color:black}.card{break-inside:avoid}}
</style>
<script>${reportDataJson}</script>
</head>
<body>
<div class="container">
<h1>${esc(title)}</h1>
<div style="color:var(--muted-foreground);font-size:13px;margin:8px 0 16px">${esc(meta.tenantDomain)} — ${esc(meta.startedAt)} ${meta.finishedAt ? `— ${esc(meta.finishedAt)}` : ""} — Run ${esc(meta.runId)}</div>

<div class="card">
<div style="font-size:28px;font-weight:600"><span style="color:var(--success)">${data.summary.passRatePct}%</span> <span style="font-size:16px;font-weight:400;color:var(--muted-foreground)">Pass rate</span></div>
<div style="font-size:13px;color:var(--muted-foreground)">${data.summary.pass} of ${evaluated} evaluated checks passed — ${data.summary.review} review${data.summary.review===1?"":"s"} need attention, ${data.summary.fail} fail, ${data.summary.warning} warning, ${data.summary.infoAndSkipped} skipped/info</div>
</div>

<div class="grid5">
<div class="stat"><div class="label">Pass</div><div class="value" style="color:var(--success)">${data.summary.pass}</div></div>
<div class="stat"><div class="label">Fail</div><div class="value" style="color:var(--destructive)">${data.summary.fail}</div></div>
<div class="stat"><div class="label">Warning</div><div class="value">${data.summary.warning}</div></div>
<div class="stat"><div class="label">Review</div><div class="value" style="color:var(--review)">${data.summary.review}</div></div>
<div class="stat"><div class="label">Skipped / Info</div><div class="value">${data.summary.infoAndSkipped}</div></div>
</div>

${data.summary.review > 0 ? `<div class="alert alert-review"><strong>${data.summary.review} review${data.summary.review===1?"":"s"} need your attention</strong> — counted as not passing. Open Reviews tab to triage. 100% requires 0 reviews.</div>` : ""}

<div class="alert"><strong>Coverage</strong><div>${esc(data.coverage.label)}</div><div class="mono">${esc(data.coverage.domainsPresent.join(", "))}</div></div>

<div class="tabs" role="tablist">
<button class="tab active" data-tab="overview" role="tab" aria-selected="true">Overview</button>
<button class="tab" data-tab="findings" role="tab">Findings <span class="badge badge-info badge-tab">${data.findings.length}</span></button>
<button class="tab ${data.summary.review>0?"tab-review":""}" data-tab="reviews" role="tab">Reviews <span class="badge ${data.summary.review>0?"badge-review":"badge-info"} badge-tab">${data.summary.review}</span></button>
<button class="tab" data-tab="remediation" role="tab">Remediation <span class="badge badge-info badge-tab">${data.remediationItems.length}</span></button>
<button class="tab" data-tab="frameworks" role="tab">Frameworks</button>
</div>

<div id="tab-overview" class="tab-panel active">
<p style="color:var(--muted-foreground);font-size:13px">Overview shows the headline scorecard. Use tabs to drill into Findings (all), Reviews (human judgment), Remediation (Fail+Warning) and Framework scores. Export buttons are available in the live app.</p>
</div>

<div id="tab-findings" class="tab-panel">
<h2>Findings — all checks</h2>
<table><thead><tr><th>Domain</th><th>Category</th><th>Setting / CheckId</th><th>Current</th><th>Recommended</th><th>Status</th><th>Severity</th></tr></thead><tbody>
${findingsRows || `<tr><td colspan="7">No findings</td></tr>`}
</tbody></table>
</div>

<div id="tab-reviews" class="tab-panel">
<h2>Reviews — human judgment required (${data.findings.filter((f) => f.status==="Review").length})</h2>
${reviewRows ? `<table><thead><tr><th>Domain</th><th>Category</th><th>Setting / CheckId</th><th>Current</th><th>Recommended</th><th>Severity</th></tr></thead><tbody>${reviewRows}</tbody></table>` : `<div class="alert">No reviews pending — pass rate can reach 100%.</div>`}
</div>

<div id="tab-remediation" class="tab-panel">
<h2>Remediation — Fail + Warning prioritized</h2>
${remediationCards || `<div style="color:var(--muted-foreground)">No open issues — no remediation needed.</div>`}
</div>

<div id="tab-frameworks" class="tab-panel">
<h2>Frameworks — ${data.frameworks.length} scores</h2>
<table><thead><tr><th>Framework</th><th>Score</th><th>Controls covered</th><th>Checks</th></tr></thead><tbody>
${frameworksRows}
</tbody></table>
</div>

<div style="margin-top:24px;font-size:12px;color:var(--muted-foreground)">Generated by M365-Assess Web — self-contained HTML, no network required. window.REPORT_DATA embedded for tooling. — ${new Date().toISOString()}</div>
</div>
<script>
(function(){
  var tabs=document.querySelectorAll('.tab');
  var panels=document.querySelectorAll('.tab-panel');
  function activate(id){
    tabs.forEach(function(t){ var a=t.getAttribute('data-tab')===id; t.classList.toggle('active',a); t.setAttribute('aria-selected',a?'true':'false'); });
    panels.forEach(function(p){ p.classList.toggle('active', p.id==='tab-'+id); });
    try{localStorage.setItem('m365-report-tab',id);}catch(e){}
  }
  tabs.forEach(function(t){ t.addEventListener('click', function(){ activate(t.getAttribute('data-tab')); }); });
  try{var s=localStorage.getItem('m365-report-tab'); if(s) activate(s);}catch(e){}
})();
</script>
</body>
</html>`;
}
