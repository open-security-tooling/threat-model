// A self-contained, printable HTML report built from `show` data: inline CSS,
// no scripts, and every piece of model text escaped. It's a file to attach
// to a review, never rendered inside the app.
import type { Threat, View } from '../core/types';
import { diagramSvg, palettes, xmlEscape as esc } from './exportSvg';
import * as L from './labels';
import { byRisk, componentName, dataName, isExpired, isOverdue, riskClass, targetName, transitLabel } from './query';

const css = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px; font: 14px/1.5 system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1b1f24; background: #fff; }
main { max-width: 980px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 32px 0 10px; padding-bottom: 4px; border-bottom: 2px solid #c9ced6; }
h3 { font-size: 15px; margin: 0 0 6px; }
.muted { color: #4d5764; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #c9ced6; }
th { background: #eceff3; font-size: 12.5px; }
.risk { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; border: 1px solid transparent; white-space: nowrap; }
.risk-critical { background: #a50e0e; color: #fff; } .risk-high { background: #c2410c; color: #fff; }
.risk-medium { background: #f9b81b; color: #1b1f24; border-color: #8a6100; } .risk-low { background: #2e7d32; color: #fff; }
.risk-none { background: #646c78; color: #fff; } .risk-na { color: #4d5764; border: 1px dashed #7d8794; }
.threat { border: 1px solid #c9ced6; border-left: 5px solid #7d8794; border-radius: 8px; padding: 12px 14px; margin: 0 0 12px; }
.threat.risk-border-critical { border-left-color: #a50e0e; } .threat.risk-border-high { border-left-color: #c2410c; }
.threat.risk-border-medium { border-left-color: #8a6100; } .threat.risk-border-low { border-left-color: #2e7d32; }
.threat dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 8px 0 0; }
.threat dt { color: #4d5764; } .threat dd { margin: 0; }
ol, ul { margin: 4px 0; padding-left: 20px; }
.diagram { border: 1px solid #c9ced6; border-radius: 8px; overflow: hidden; }
.diagram svg { display: block; width: 100%; height: auto; }
.overdue { color: #8c1d18; }
.signoff { padding: 8px 10px; border-left: 3px solid #2e7d32; background: #eceff3; }
.summary { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 10px 0; }
footer { margin-top: 40px; color: #4d5764; font-size: 12px; }
@media print {
  body { padding: 0; font-size: 11.5pt; }
  @page { margin: 16mm; }
  h2 { break-after: avoid; }
  .threat, tr, .diagram { break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
`;

function riskPill(t: Threat, view: View): string {
  const cls = riskClass(t, view.risks[t.id]);
  return `<span class="risk risk-${cls}">${esc(cls === 'na' ? 'Doesn’t apply' : L.riskLabel(view.risks[t.id]?.level))}</span>`;
}

function threatCard(t: Threat, view: View): string {
  const m = view.model;
  const a = view.risks[t.id];
  const cls = riskClass(t, a);
  const rows: string[] = [];
  const row = (k: string, v: string) => v && rows.push(`<dt>${esc(k)}</dt><dd>${v}</dd>`);
  row('Where', esc((t.affects ?? []).map((x) => targetName(m, x)).join(', ')));
  row('Status', esc(L.label(L.threatStatuses, t.status)));
  if (t.accepted) row('Accepted', esc(`by ${t.accepted.by} until ${t.accepted.until}${isExpired(t.accepted.until) ? ' (expired)' : ''}: ${t.accepted.reason}`));
  if (t.status === 'not-applicable' && t.reason) row('Why it doesn’t apply', esc(t.reason));
  row('Who could do it', esc(t.who ? `${L.label(L.who, t.who)} (${L.hint(L.who, t.who)})` : ''));
  row('How hard', esc(t.effort ? `${L.label(L.efforts, t.effort)}: ${L.hint(L.efforts, t.effort)}` : ''));
  row('How bad', esc([t.impact ? L.label(L.impacts, t.impact) : '', t.impact_note ?? ''].filter(Boolean).join(': ')));
  row('Why this risk', esc(a?.why ?? ''));
  const fixes = (t.mitigations ?? []).map((id) => {
    const mt = m.mitigations?.find((x) => x.id === id);
    const ch = a?.changes?.find((c) => c.mitigation === id);
    if (!mt) return `<li>${esc(id)} (not defined)</li>`;
    const after = ch?.to && mt.status !== 'done' ? ` → ${esc(ch.to)} once done` : '';
    return `<li>${esc(mt.title)} <span class="muted">(${esc(L.label(L.mitigationStatuses, mt.status))}${after})</span></li>`;
  });
  if (fixes.length) row('Fixes', `<ul>${fixes.join('')}</ul>`);
  const refs = Object.entries(t.refs ?? {}).map(([k, v]) => `${esc(k.toUpperCase())}: ${esc(v.join(', '))}`);
  if (refs.length) row('Security mappings', refs.join('<br>'));
  const steps = t.attack?.length ? `<p class="muted" style="margin:8px 0 0">How it works</p><ol>${t.attack.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : '';
  return `<section class="threat risk-border-${cls}"><h3>${riskPill(t, view)} ${esc(t.title)}</h3>${steps}<dl>${rows.join('')}</dl></section>`;
}

export function htmlReport(view: View): string {
  const m = view.model;
  const s = view.summary;
  const levels = ['critical', 'high', 'medium', 'low'];
  const threats = byRisk(view, m.threats ?? []);
  const open = threats.filter((t) => t.status !== 'not-applicable');
  const dismissed = threats.filter((t) => t.status === 'not-applicable');
  const { svg } = diagramSvg(view, palettes.light);
  const kinds = L.threatKinds;
  const gaps = (m.components ?? [])
    .map((c) => ({
      c,
      missing: kinds
        .filter((k) => (k.value !== 'manipulate-ai' || c.kind === 'ai') && !view.coverage[c.id]?.[k.value]?.length && !c.considered?.[k.value])
        .map((k) => k.label),
    }))
    .filter((g) => g.missing.length);
  const yesNo = (v: boolean | undefined) => esc(L.yesNo(v));

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>${esc(`Threat model: ${m.system.name}`)}</title>
<style>${css}</style>
</head>
<body>
<main>
<h1>Threat model: ${esc(m.system.name)}</h1>
${m.system.description ? `<p>${esc(m.system.description)}</p>` : ''}
${m.system.owners?.length ? `<p class="muted">Owned by ${esc(m.system.owners.join(', '))}</p>` : ''}
<p class="muted">${esc(`${s.components} components, ${s.flows} flows, ${s.threats} threats (${s.open} open).`)}</p>
${
  m.signoff
    ? `<p class="signoff">Signed off by <strong>${esc(m.signoff.by)}</strong> on ${esc(m.signoff.on)}${m.signoff.note ? `: ${esc(m.signoff.note)}` : ''}</p>`
    : '<p class="signoff muted">Not signed off.</p>'
}
<div class="summary">${levels.map((l) => `<span><span class="risk risk-${l}">${l}</span> ${s.by_risk[l] ?? 0}</span>`).join('')}${s.not_assessed ? `<span><span class="risk risk-none">not assessed</span> ${s.not_assessed}</span>` : ''}</div>

<h2>Diagram</h2>
<div class="diagram">${svg}</div>
<p class="muted">Thick arrows cross from one zone to another. Dots are threats, colored by the risk that remains after the fixes that are done.</p>

<h2>Threats, highest risk first</h2>
${open.map((t) => threatCard(t, view)).join('\n') || '<p class="muted">No threats yet.</p>'}

${
  dismissed.length
    ? `<h2>Considered and dismissed</h2><table><tr><th>Threat</th><th>Why it doesn’t apply</th></tr>${dismissed
        .map((t) => `<tr><td>${esc(t.title)}</td><td>${esc(t.reason ?? '')}</td></tr>`)
        .join('')}</table>`
    : ''
}

<h2>Fixes</h2>
${
  (m.mitigations ?? []).length
    ? `<table><tr><th>Fix</th><th>Status</th><th>Owner</th><th>Due</th><th>For</th></tr>${(m.mitigations ?? [])
        .map((mt) => {
          const used = (m.threats ?? []).filter((t) => t.mitigations?.includes(mt.id)).map((t) => t.title);
          return `<tr><td>${esc(mt.title)}</td><td>${esc(L.label(L.mitigationStatuses, mt.status))}</td><td>${esc(mt.owner ?? '')}</td><td>${esc(mt.due ?? '')}${isOverdue(mt) ? ' <strong class="overdue">overdue</strong>' : ''}</td><td>${used.map((u) => esc(u)).join('<br>')}</td></tr>`;
        })
        .join('')}</table>`
    : '<p class="muted">No fixes yet.</p>'
}

<h2>Components</h2>
<table><tr><th>Component</th><th>Kind</th><th>Zone</th><th>Keeps</th><th>Runs as</th><th>Encrypted on disk</th><th>Monitored</th><th>Updates</th></tr>
${(m.components ?? [])
  .map(
    (c) =>
      `<tr><td>${esc(c.name)}</td><td>${esc(L.label(L.componentKinds, c.kind))}${c.exposure === 'internet' ? ' · internet' : ''}</td><td>${esc(
        m.zones?.find((z) => z.id === c.zone)?.name ?? c.zone ?? '',
      )}</td><td>${esc((c.stores ?? []).map((d) => dataName(m, d)).join(', '))}</td><td>${esc(m.identities?.find((i) => i.id === c.identity)?.name ?? c.identity ?? '')}</td><td>${yesNo(
        c.encrypted_at_rest,
      )}</td><td>${yesNo(c.monitored)}</td><td>${esc(c.patching ? L.label(L.patching, c.patching) : 'Not said')}</td></tr>`,
  )
  .join('')}
</table>

<h2>Flows</h2>
<table><tr><th>From → to</th><th>Carries</th><th>Over</th><th>Encrypted</th><th>Crosses zones</th></tr>
${(m.flows ?? [])
  .map(
    (f) =>
      `<tr><td>${esc(`${componentName(m, f.from)} → ${componentName(m, f.to)}`)}</td><td>${esc((f.carries ?? []).map((d) => dataName(m, d)).join(', '))}</td><td>${esc(
        f.over ?? '',
      )}</td><td>${esc(transitLabel(view, f))}</td><td>${view.crossings.includes(f.id) ? 'Yes' : ''}</td></tr>`,
  )
  .join('')}
</table>

${
  (m.identities ?? []).length
    ? `<h2>Identities and permissions</h2><table><tr><th>Identity</th><th>Kind</th><th>Can</th><th>Used by</th></tr>${(m.identities ?? [])
        .map(
          (i) =>
            `<tr><td>${esc(i.name)}</td><td>${esc(L.label(L.identityKinds, i.kind))}</td><td>${(i.can ?? [])
              .map((p) => esc(`${p.do} ${m.components?.find((c) => c.id === p.on)?.name ?? dataName(m, p.on)}`))
              .join('<br>')}</td><td>${esc((m.components ?? []).filter((c) => c.identity === i.id).map((c) => c.name).join(', '))}</td></tr>`,
        )
        .join('')}</table>`
    : ''
}

<h2>Not looked at yet</h2>
${
  gaps.length
    ? `<p class="muted">Kinds of threat nobody has considered for each component. These are the honest to-do list.</p><table><tr><th>Component</th><th>Not considered</th></tr>${gaps
        .map((g) => `<tr><td>${esc(g.c.name)}</td><td>${esc(g.missing.join(', '))}</td></tr>`)
        .join('')}</table>`
    : '<p>Every component has been looked at for every kind of threat.</p>'
}

${
  view.diagnostics.length
    ? `<h2>Problems in the file</h2><ul>${view.diagnostics
        .map((d) => `<li>${esc(`${d.severity === 'error' ? 'Error' : 'Warning'}${d.line ? `, line ${d.line}` : ''}: ${d.message}${d.hint ? ` ${d.hint}` : ''}`)}</li>`)
        .join('')}</ul>`
    : ''
}

<footer>Generated ${esc(new Date().toISOString().slice(0, 10))} by threat-model from the model file. The file is the source of truth.</footer>
</main>
</body>
</html>
`;
  return html;
}
