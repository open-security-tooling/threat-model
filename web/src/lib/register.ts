// The risk register: one row per threat with what a security reviewer
// needs (inherent vs residual risk, owners, due dates, acceptance, evidence,
// mappings). Shared by the reviewer columns, the Register view and CSV.
import type { Threat, View } from '../core/types';
import * as L from './labels';
import { byRisk, isExpired, isOverdue, riskClass, targetName } from './query';

export interface RegisterRow {
  threat: Threat;
  cls: string;
  residual: string;
  inherent: string;
  planned: string;
  where: string;
  status: string;
  fixes: { title: string; status: string; owner: string; due: string; overdue: boolean }[];
  owners: string[];
  /** Earliest due date among fixes that aren't done. */
  due: string;
  overdue: boolean;
  accepted: string;
  acceptanceExpired: boolean;
  evidence: boolean;
  refs: string;
}

export function registerRows(view: View): RegisterRow[] {
  const m = view.model;
  return byRisk(view, m.threats ?? []).map((t) => {
    const a = view.risks[t.id];
    const fixes = (t.mitigations ?? [])
      .map((id) => m.mitigations?.find((x) => x.id === id))
      .filter((x) => !!x)
      .map((mt) => ({ title: mt.title, status: mt.status, owner: mt.owner ?? '', due: mt.due ?? '', overdue: isOverdue(mt), evidence: !!mt.evidence?.length }));
    const pending = fixes.filter((f) => f.status !== 'done' && f.due).map((f) => f.due).sort();
    const cls = riskClass(t, a);
    return {
      threat: t,
      cls,
      residual: cls === 'na' ? 'n/a' : L.riskLabel(a?.level),
      inherent: cls === 'na' ? 'n/a' : L.riskLabel(a?.inherent_level),
      planned: a?.planned ? L.riskLabel(a.planned) : '',
      where: (t.affects ?? []).map((x) => targetName(m, x)).join(', '),
      status: L.label(L.threatStatuses, t.status),
      fixes,
      owners: [...new Set(fixes.map((f) => f.owner).filter(Boolean))],
      due: pending[0] ?? '',
      overdue: fixes.some((f) => f.overdue),
      accepted: t.accepted ? `${t.accepted.by} until ${t.accepted.until}` : '',
      acceptanceExpired: isExpired(t.accepted?.until),
      evidence: fixes.some((f) => f.evidence),
      refs: Object.entries(t.refs ?? {})
        .map(([k, v]) => `${k.toUpperCase()} ${v.join(', ')}`)
        .join('; '),
    };
  });
}

/**
 * One CSV cell. Cells that a spreadsheet would run as a formula (starting
 * with = + - @, a tab or a carriage return) get a leading apostrophe, so a
 * crafted threat title can't execute when someone opens the export.
 */
export function csvCell(value: string): string {
  let v = value;
  if (/^[=+\-@\t\r]/.test(v)) v = `'${v}`;
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function registerCsv(view: View): string {
  const header = ['ID', 'Threat', 'Kind', 'Where', 'Risk before fixes', 'Risk now', 'Risk once planned fixes are done', 'Status', 'Fixes', 'Owners', 'Next due', 'Overdue', 'Accepted by / until', 'Evidence', 'Security mappings'];
  const rows = registerRows(view).map((r) => [
    r.threat.id,
    r.threat.title,
    L.label(L.threatKinds, r.threat.kind),
    r.where,
    r.inherent,
    r.residual,
    r.planned,
    r.status,
    r.fixes.map((f) => `${f.title} (${L.label(L.mitigationStatuses, f.status)}${f.due ? `, due ${f.due}` : ''})`).join('; '),
    r.owners.join(', '),
    r.due,
    r.overdue ? 'yes' : '',
    r.accepted,
    r.evidence ? 'yes' : 'no',
    r.refs,
  ]);
  // CRLF line endings, as spreadsheets expect.
  return [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
