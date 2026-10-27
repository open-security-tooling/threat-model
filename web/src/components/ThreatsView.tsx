// The triage view: what do we fix first?
import { useMemo, useState } from 'react';
import { app } from '../lib/app';
import { dialogs } from '../lib/dialogs';
import * as L from '../lib/labels';
import { riskClass, riskOrder, targetName } from '../lib/query';
import type { View } from '../core/types';
import { lens } from '../lib/lens';
import { useStore } from '../lib/store';
import { registerRows } from '../lib/register';

type Key = 'risk' | 'title' | 'kind' | 'where' | 'status';

const columns: [Key, string][] = [
  ['risk', 'Risk'],
  ['title', 'Threat'],
  ['kind', 'Kind'],
  ['where', 'Where'],
  ['status', 'Status'],
];

export function ThreatsView({ view }: { view: View }) {
  useStore(lens);
  const m = view.model;
  const reviewer = lens.reviewer;
  const reg = useMemo(() => new Map(registerRows(view).map((r) => [r.threat.id, r])), [view]);
  const [sortKey, setSortKey] = useState<Key>('risk');
  const [desc, setDesc] = useState(true);
  const [fRisk, setFRisk] = useState('');
  const [fStatus, setFStatus] = useState('');
  const [fComponent, setFComponent] = useState('');
  const [fKind, setFKind] = useState('');
  const [query, setQuery] = useState('');

  const rows = useMemo(
    () =>
      (m.threats ?? []).map((t) => {
        const a = view.risks[t.id];
        // A threat on a flow counts for both ends of it.
        const comps = new Set<string>();
        for (const target of t.affects ?? []) {
          const f = m.flows?.find((x) => x.id === target);
          if (f) {
            comps.add(f.from);
            comps.add(f.to);
          } else comps.add(target);
        }
        return { t, a, cls: riskClass(t, a), order: riskOrder(t, a), where: (t.affects ?? []).map((x) => targetName(m, x)).join(', '), comps };
      }),
    [m, view.risks],
  );
  type Row = (typeof rows)[number];

  const q = query.trim().toLowerCase();
  const cmp: Record<Key, (x: Row, y: Row) => number> = {
    risk: (x, y) => x.order - y.order || L.riskRank(x.a?.planned) - L.riskRank(y.a?.planned),
    title: (x, y) => x.t.title.localeCompare(y.t.title),
    kind: (x, y) => (x.t.kind ?? '').localeCompare(y.t.kind ?? ''),
    where: (x, y) => x.where.localeCompare(y.where),
    status: (x, y) => x.t.status.localeCompare(y.t.status),
  };
  const filtered = rows
    .filter(
      (r) =>
        (!fRisk || r.cls === fRisk) &&
        (!fStatus || r.t.status === fStatus) &&
        (!fComponent || r.comps.has(fComponent)) &&
        (!fKind || r.t.kind === fKind) &&
        (!q || r.t.title.toLowerCase().includes(q) || r.t.id.includes(q)),
    )
    .sort((x, y) => (desc ? -1 : 1) * cmp[sortKey](x, y));

  const sortBy = (k: Key) => {
    if (sortKey === k) setDesc(!desc);
    else {
      setSortKey(k);
      setDesc(k === 'risk');
    }
  };
  const clear = () => {
    setFRisk('');
    setFStatus('');
    setFComponent('');
    setFKind('');
    setQuery('');
  };

  return (
    <div className="scroll-view">
      <div className="filters" role="search">
        <div className="field grow">
          <label htmlFor="f-q">Search</label>
          <input id="f-q" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Words in the title" />
        </div>
        <div className="field">
          <label htmlFor="f-risk">Risk</label>
          <select id="f-risk" value={fRisk} onChange={(e) => setFRisk(e.target.value)}>
            <option value="">Any</option>
            {L.riskLevels.map((l) => (
              <option key={l} value={l}>
                {L.capitalize(l)}
              </option>
            ))}
            <option value="none">Not assessed</option>
            <option value="na">Doesn’t apply</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-status">Status</label>
          <select id="f-status" value={fStatus} onChange={(e) => setFStatus(e.target.value)}>
            <option value="">Any</option>
            {L.threatStatuses.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-comp">Component</label>
          <select id="f-comp" value={fComponent} onChange={(e) => setFComponent(e.target.value)}>
            <option value="">Any</option>
            {(m.components ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-kind">Kind</label>
          <select id="f-kind" value={fKind} onChange={(e) => setFKind(e.target.value)}>
            <option value="">Any</option>
            {L.threatKinds.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
        <button type="button" className="btn" onClick={clear}>
          Clear
        </button>
        <button type="button" className="btn primary" onClick={() => dialogs.openForm({ section: 'threats' })}>
          Add threat
        </button>
      </div>

      <p className="count" aria-live="polite">
        {filtered.length} of {rows.length} threats
      </p>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              {columns.map(([k, title]) => (
                <th key={k} scope="col" aria-sort={sortKey === k ? (desc ? 'descending' : 'ascending') : 'none'}>
                  <button type="button" className="sort" onClick={() => sortBy(k)}>
                    {title}
                    <span aria-hidden="true">{sortKey === k ? (desc ? ' ▼' : ' ▲') : ''}</span>
                  </button>
                </th>
              ))}
              {reviewer && (
                <>
                  <th scope="col">Before fixes → now</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Next due</th>
                  <th scope="col">Accepted</th>
                  <th scope="col">Evidence</th>
                  <th scope="col">Mappings</th>
                </>
              )}
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.t.id} className={app.selection?.type === 'threat' && app.selection.id === r.t.id ? 'selected' : undefined}>
                <td className="nowrap">
                  <span className={`risk risk-${r.cls}`}>{r.cls === 'na' ? 'n/a' : L.riskLabel(r.a?.level)}</span>
                  {r.a?.planned && r.a.planned !== r.a.level && r.t.status !== 'not-applicable' && (
                    <span className="planned" title="Once the planned fixes are done">
                      → {r.a.planned}
                    </span>
                  )}
                </td>
                <td>
                  <button type="button" className="link-btn row-title" onClick={() => app.select('threat', r.t.id)}>
                    {r.t.title}
                  </button>
                </td>
                <td>{L.label(L.threatKinds, r.t.kind)}</td>
                <td>{r.where}</td>
                <td>{L.label(L.threatStatuses, r.t.status)}</td>
                {reviewer && <ReviewerCells row={reg.get(r.t.id)} />}
              </tr>
            ))}
            {!filtered.length && (
              <tr>
                <td colSpan={reviewer ? 11 : 5} className="muted empty-cell">
                  No threats match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ReviewerCells({ row }: { row: ReturnType<typeof registerRows>[number] | undefined }) {
  if (!row) return null;
  return (
    <>
      <td className="nowrap">
        {row.inherent} → {row.residual}
      </td>
      <td>{row.owners.join(', ') || <span className="muted">—</span>}</td>
      <td className="nowrap">
        {row.due || <span className="muted">—</span>}
        {row.overdue && <span className="overdue-tag">overdue</span>}
      </td>
      <td>
        {row.accepted || <span className="muted">—</span>}
        {row.acceptanceExpired && <span className="overdue-tag">expired</span>}
      </td>
      <td>{row.evidence ? 'Yes' : <span className="muted">No</span>}</td>
      <td className="small">{row.refs || <span className="muted">—</span>}</td>
    </>
  );
}
