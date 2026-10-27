// Shown when nothing is selected: the system at a glance, and the items
// that aren't drawn on the diagram (data, actors, fixes).
import { app } from '../../lib/app';
import { dialogs } from '../../lib/dialogs';
import * as L from '../../lib/labels';
import type { FormSection } from '../../lib/forms';
import type { View } from '../../core/types';
import { lens } from '../../lib/lens';
import { useStore } from '../../lib/store';
import { isOverdue } from '../../lib/query';
import { SignoffPanel } from '../SignoffPanel';

const levels = ['critical', 'high', 'medium', 'low'] as const;

export function Overview({ view }: { view: View }) {
  useStore(lens);
  const m = view.model;
  const s = view.summary;
  const lists: { section: FormSection; title: string; noun: string; items: { id: string; name: string; meta: string }[] }[] = [
    { section: 'data', title: 'Data worth protecting', noun: 'data', items: (m.data ?? []).map((d) => ({ id: d.id, name: d.name, meta: L.label(L.sensitivities, d.sensitivity) })) },
    { section: 'actors', title: 'People who use it', noun: 'actor', items: (m.actors ?? []).map((a) => ({ id: a.id, name: a.name, meta: L.label(L.who, a.access) })) },
    {
      section: 'identities',
      title: 'Identities and permissions',
      noun: 'identity',
      items: (m.identities ?? []).map((i) => ({ id: i.id, name: i.name, meta: `${L.label(L.identityKinds, i.kind)}${i.can?.length ? ` · ${i.can.length} permission${i.can.length === 1 ? '' : 's'}` : ''}` })),
    },
    {
      section: 'mitigations',
      title: 'Fixes',
      noun: 'fix',
      items: (m.mitigations ?? []).map((x) => ({ id: x.id, name: x.title, meta: `${L.label(L.mitigationStatuses, x.status)}${isOverdue(x) ? ' · overdue' : ''}` })),
    },
    { section: 'zones', title: 'Zones', noun: 'zone', items: (m.zones ?? []).map((z) => ({ id: z.id, name: z.name, meta: L.label(L.trusts, z.trust) })) },
  ];
  return (
    <article>
      <h2>{m.system.name}</h2>
      {m.system.description && <p className="desc">{m.system.description}</p>}
      {m.system.owners?.length ? <p className="muted">Owned by {m.system.owners.join(', ')}</p> : null}
      <button type="button" className="btn small space-top" onClick={() => dialogs.openForm({ section: 'system' })}>
        Edit system
      </button>

      <section className="panel-section">
        <h3>Risk at a glance</h3>
        <p>
          {s.components} components, {s.flows} flows, {s.threats} threats ({s.open} open)
        </p>
        <ul className="tally">
          {levels.map((level) => (
            <li key={level}>
              <span className={`risk risk-${level}`}>{level}</span> {s.by_risk[level] ?? 0}
            </li>
          ))}
          {s.not_assessed > 0 && (
            <li>
              <span className="risk risk-none">not assessed</span> {s.not_assessed}
            </li>
          )}
        </ul>
        <button type="button" className="link-btn" onClick={() => app.setTab('threats')}>
          See what to fix first
        </button>
      </section>

      {lens.reviewer && (
        <div className="panel-section">
          <SignoffPanel model={m} />
        </div>
      )}

      {app.suggestions.length > 0 && (
        <section className="panel-section">
          <h3>Suggestions</h3>
          <button type="button" className="btn small" onClick={() => app.select('suggestions', '')}>
            {app.suggestions.length} suggested threats to go through
          </button>
        </section>
      )}

      {lists.map((list) => (
        <section className="panel-section" key={list.section}>
          <h3>{list.title}</h3>
          {list.items.length > 0 && (
            <ul className="items">
              {list.items.map((item) => (
                <li key={item.id}>
                  <button type="button" className="link-btn" onClick={() => dialogs.openForm({ section: list.section, id: item.id })}>
                    {item.name}
                  </button>
                  <span className="muted">{item.meta}</span>
                </li>
              ))}
            </ul>
          )}
          <button type="button" className="btn small" onClick={() => dialogs.openForm({ section: list.section })}>
            Add {list.noun}
          </button>
        </section>
      ))}
    </article>
  );
}
