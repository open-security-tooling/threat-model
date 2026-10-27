import { app } from '../../lib/app';
import * as L from '../../lib/labels';
import { byRisk, riskClass } from '../../lib/query';
import type { Threat, View } from '../../core/types';

export function ThreatList({ view, threats }: { view: View; threats: Threat[] }) {
  const sorted = byRisk(view, threats);
  if (!sorted.length) return <p className="muted">No threats yet.</p>;
  return (
    <ul className="threat-list">
      {sorted.map((t) => {
        const cls = riskClass(t, view.risks[t.id]);
        return (
          <li key={t.id}>
            <span className={`risk risk-${cls}`}>{cls === 'na' ? 'n/a' : L.riskLabel(view.risks[t.id]?.level)}</span>
            <button type="button" className="link-btn" onClick={() => app.select('threat', t.id)}>
              {t.title}
            </button>
            {t.status !== 'open' && <span className="muted small">({L.label(L.threatStatuses, t.status).toLowerCase()})</span>}
          </li>
        );
      })}
    </ul>
  );
}
