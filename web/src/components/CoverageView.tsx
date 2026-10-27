// For each component: have we thought about each kind of threat? Empty
// cells are the honest to-do list. A cell is done when it has threats, or
// when someone recorded why that kind doesn't apply (`considered`).
import { useState } from 'react';
import { app } from '../lib/app';
import { dialogs } from '../lib/dialogs';
import { core } from '../core/client';
import * as L from '../lib/labels';
import { riskClass } from '../lib/query';
import type { Component, View } from '../core/types';
import { ReasonDialog } from './ReasonDialog';

/** Tricking an AI only applies to AI components. */
const applies = (c: Component, kind: string) => kind !== 'manipulate-ai' || c.kind === 'ai';

export function CoverageView({ view }: { view: View }) {
  const m = view.model;
  const comps = m.components ?? [];
  const kinds = comps.some((c) => c.kind === 'ai') ? L.threatKinds : L.threatKinds.filter((k) => k.value !== 'manipulate-ai');
  const threat = (id: string) => m.threats?.find((t) => t.id === id);
  const [asking, setAsking] = useState<{ component: Component; kind: (typeof L.threatKinds)[number] } | null>(null);

  let open = 0;
  let total = 0;
  for (const c of comps) {
    for (const k of kinds) {
      if (!applies(c, k.value)) continue;
      total++;
      if (!view.coverage[c.id]?.[k.value]?.length && !c.considered?.[k.value]) open++;
    }
  }

  const setConsidered = (c: Component, kind: string, reason: string | null) => {
    const next = { ...(c.considered ?? {}) };
    if (reason === null) delete next[kind];
    else next[kind] = reason;
    return app.edit((s) => core.upsert(s, 'components', c.id, { considered: Object.keys(next).length ? next : null }));
  };

  return (
    <div className="scroll-view">
      <p className="intro">
        One row per component, one column per kind of threat. A cell is done when it lists threats, or when you’ve recorded why that kind doesn’t apply. A dashed cell means
        nobody has thought about it yet. <strong>{open}</strong> of {total} cells are still open.
      </p>
      <div className="table-wrap">
        <table className="table coverage">
          <thead>
            <tr>
              <th scope="col">Component</th>
              {kinds.map((k) => (
                <th key={k.value} scope="col" title={k.hint}>
                  <span className="kind-label">{k.label}</span>
                  <code className="kind-id">{k.value}</code>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {comps.map((c) => (
              <tr key={c.id}>
                <th scope="row">
                  <button type="button" className="link-btn row-title" onClick={() => app.select('component', c.id)}>
                    {c.name}
                  </button>
                </th>
                {kinds.map((k) => {
                  if (!applies(c, k.value)) {
                    return (
                      <td key={k.value} className="cov-na">
                        <span className="muted small">Not an AI component</span>
                      </td>
                    );
                  }
                  const threats = (view.coverage[c.id]?.[k.value] ?? []).map(threat).filter((t) => !!t);
                  const reason = c.considered?.[k.value];
                  if (!threats.length && !reason) {
                    return (
                      <td key={k.value} className="cov-empty">
                        <div className="cov-actions">
                          <button
                            type="button"
                            className="cov-add"
                            aria-label={`Add a “${k.label.toLowerCase()}” threat for ${c.name}`}
                            title="Add a threat"
                            onClick={() => dialogs.openForm({ section: 'threats', preset: { affects: [c.id], kind: k.value } })}
                          >
                            +
                          </button>
                          <button
                            type="button"
                            className="link-btn small"
                            aria-label={`Mark “${k.label.toLowerCase()}” as considered and not applying to ${c.name}`}
                            onClick={() => setAsking({ component: c, kind: k })}
                          >
                            Doesn’t apply…
                          </button>
                        </div>
                      </td>
                    );
                  }
                  return (
                    <td key={k.value} className={reason && !threats.length ? 'cov-considered' : undefined}>
                      {reason && (
                        <div className="considered">
                          <span className="considered-title">Considered: doesn’t apply</span>
                          <span className="muted small">{reason}</span>
                          <button type="button" className="link-btn small" aria-label={`Undo “doesn’t apply” for ${k.label.toLowerCase()} on ${c.name}`} onClick={() => void setConsidered(c, k.value, null)}>
                            Undo
                          </button>
                        </div>
                      )}
                      {threats.length > 0 && (
                        <ul className="cov-list">
                          {threats.map((t) => {
                            const cls = riskClass(t, view.risks[t.id]);
                            return (
                              <li key={t.id}>
                                <button type="button" className={`cov-chip risk-border-${cls}`} title={t.title} onClick={() => app.select('threat', t.id)}>
                                  <span className={`risk risk-${cls}`}>{cls === 'na' ? 'n/a' : L.riskLabel(view.risks[t.id]?.level)}</span>
                                  <span className="cov-title">{t.title}</span>
                                </button>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
            {!comps.length && (
              <tr>
                <td colSpan={kinds.length + 1} className="muted empty-cell">
                  Add components to see coverage.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {asking && (
        <ReasonDialog
          title={`“${asking.kind.label}” on ${asking.component.name}`}
          label={`Why doesn’t this apply? (${asking.kind.hint ?? ''})`}
          confirm="Mark as considered"
          onSubmit={(r) => setConsidered(asking.component, asking.kind.value, r)}
          onClose={() => setAsking(null)}
        />
      )}
    </div>
  );
}
