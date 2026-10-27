// The diagram as tables: the same zones, components and flows (and their
// threats), for screen readers, keyboard users and anyone who prefers text.
import { app } from '../../lib/app';
import * as L from '../../lib/labels';
import { byRisk, componentName, dataName, riskClass, threatsAffecting, transitLabel } from '../../lib/query';
import type { View } from '../../core/types';

function Threats({ view, id }: { view: View; id: string }) {
  const ts = byRisk(view, threatsAffecting(view.model, id));
  if (!ts.length) return <span className="muted">none</span>;
  return (
    <ul className="plain">
      {ts.map((t) => {
        const cls = riskClass(t, view.risks[t.id]);
        return (
          <li key={t.id}>
            <span className={`risk risk-${cls}`}>{cls === 'na' ? 'n/a' : L.riskLabel(view.risks[t.id]?.level)}</span>{' '}
            <button type="button" className="link-btn" onClick={() => app.select('threat', t.id)}>
              {t.title}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

export function ElementsList({ view }: { view: View }) {
  const m = view.model;
  const zoneName = (id: string | undefined) => (id ? (m.zones?.find((z) => z.id === id)?.name ?? id) : '');
  return (
    <div className="scroll-view elements-list">
      <h2 className="list-heading">Zones</h2>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Zone</th>
              <th scope="col">Trust</th>
              <th scope="col">Inside</th>
              <th scope="col">Outbound</th>
              <th scope="col">Components</th>
            </tr>
          </thead>
          <tbody>
            {(m.zones ?? []).map((z) => (
              <tr key={z.id}>
                <th scope="row">
                  <button type="button" className="link-btn row-title" onClick={() => app.select('zone', z.id)}>
                    {z.name}
                  </button>
                </th>
                <td>{L.label(L.trusts, z.trust)}</td>
                <td>{L.label(L.networks, z.network ?? 'open')}</td>
                <td>{L.label(L.egress, z.egress ?? 'open')}</td>
                <td>
                  {(m.components ?? [])
                    .filter((c) => c.zone === z.id)
                    .map((c) => c.name)
                    .join(', ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="list-heading">Components</h2>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">Kind</th>
              <th scope="col">Zone</th>
              <th scope="col">Reachable</th>
              <th scope="col">Threats</th>
            </tr>
          </thead>
          <tbody>
            {(m.components ?? []).map((c) => (
              <tr key={c.id}>
                <th scope="row">
                  <button type="button" className="link-btn row-title" onClick={() => app.select('component', c.id)}>
                    {c.name}
                  </button>
                </th>
                <td>{L.label(L.componentKinds, c.kind)}</td>
                <td>{zoneName(c.zone)}</td>
                <td>{L.label(L.exposures, c.exposure)}</td>
                <td>
                  <Threats view={view} id={c.id} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="list-heading">Flows</h2>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">From → to</th>
              <th scope="col">Carries</th>
              <th scope="col">Encrypted</th>
              <th scope="col">Crosses zones</th>
              <th scope="col">Threats</th>
            </tr>
          </thead>
          <tbody>
            {(m.flows ?? []).map((f) => (
              <tr key={f.id}>
                <th scope="row">
                  <button type="button" className="link-btn row-title" onClick={() => app.select('flow', f.id)}>
                    {componentName(m, f.from)} → {componentName(m, f.to)}
                  </button>
                </th>
                <td>{(f.carries ?? []).map((d) => dataName(m, d)).join(', ') || f.over || ''}</td>
                <td>{transitLabel(view, f)}</td>
                <td>{view.crossings.includes(f.id) ? 'Yes' : 'No'}</td>
                <td>
                  <Threats view={view} id={f.id} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
