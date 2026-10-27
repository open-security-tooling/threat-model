// The risk register, for security reviewers: printable, with CSV export.
import { app } from '../lib/app';
import { download } from '../backend/local';
import * as L from '../lib/labels';
import { registerCsv, registerRows } from '../lib/register';
import type { View } from '../core/types';
import { SignoffPanel } from './SignoffPanel';

export function RegisterView({ view }: { view: View }) {
  const m = view.model;
  const rows = registerRows(view);
  const base = (app.backend?.name ?? 'threatmodel').replace(/\.(ya?ml)$/i, '') || 'threatmodel';
  return (
    <div className="scroll-view register">
      <div className="register-head">
        <div>
          <h2>Risk register: {m.system.name}</h2>
          <p className="muted small">
            {rows.length} threats · generated {new Date().toISOString().slice(0, 10)} from the model file
          </p>
        </div>
        <div className="row no-print">
          <button type="button" className="btn" onClick={() => download(`${base}-register.csv`, registerCsv(view), 'text/csv')}>
            Export CSV
          </button>
          <button type="button" className="btn" onClick={() => window.print()}>
            Print
          </button>
        </div>
      </div>
      <SignoffPanel model={m} />
      <div className="table-wrap">
        <table className="table register-table">
          <thead>
            <tr>
              <th scope="col">Threat</th>
              <th scope="col">Risk</th>
              <th scope="col">Status</th>
              <th scope="col">Fixes</th>
              <th scope="col">Next due</th>
              <th scope="col">Accepted</th>
              <th scope="col">Evidence</th>
              <th scope="col">Mappings</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.threat.id}>
                <td>
                  <button type="button" className="link-btn row-title" onClick={() => app.select('threat', r.threat.id)}>
                    {r.threat.title}
                  </button>
                  <div className="muted small">
                    {L.label(L.threatKinds, r.threat.kind)}
                    {r.where && ` · ${r.where}`} · <code>{r.threat.id}</code>
                  </div>
                </td>
                <td className="nowrap">
                  <span className={`risk risk-${r.cls}`}>{r.residual}</span>
                  {r.inherent !== r.residual && <div className="muted small">was {r.inherent.toLowerCase()}</div>}
                  {r.planned && r.planned !== r.residual && <div className="muted small">→ {r.planned.toLowerCase()} once planned fixes are done</div>}
                </td>
                <td>{r.status}</td>
                <td>
                  {r.fixes.length ? (
                    <ul className="plain">
                      {r.fixes.map((f, i) => (
                        <li key={i} className="small">
                          {f.title} <span className="muted">({L.label(L.mitigationStatuses, f.status)}{f.owner && `, ${f.owner}`})</span>
                          {f.overdue && <span className="overdue-tag">overdue</span>}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="muted">none</span>
                  )}
                </td>
                <td className="nowrap">
                  {r.due || <span className="muted">—</span>}
                  {r.overdue && <span className="overdue-tag">overdue</span>}
                </td>
                <td>
                  {r.accepted || <span className="muted">—</span>}
                  {r.acceptanceExpired && <span className="overdue-tag">expired</span>}
                </td>
                <td>{r.evidence ? 'Yes' : <span className="muted">No</span>}</td>
                <td className="small">{r.refs || <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
