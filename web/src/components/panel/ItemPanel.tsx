// Details for a component, flow or zone.
import { app } from '../../lib/app';
import { dialogs } from '../../lib/dialogs';
import { core } from '../../core/client';
import * as L from '../../lib/labels';
import { componentName, dataName, threatsAffecting, transitLabel } from '../../lib/query';
import type { Section, View } from '../../core/types';
import { ThreatList } from './ThreatList';
import { SuggestionList } from './Suggestions';

export function ItemPanel({ view, type, id }: { view: View; type: 'component' | 'flow' | 'zone'; id: string }) {
  const m = view.model;
  const section: Section = type === 'component' ? 'components' : type === 'flow' ? 'flows' : 'zones';
  const component = type === 'component' ? m.components?.find((c) => c.id === id) : undefined;
  const flow = type === 'flow' ? m.flows?.find((f) => f.id === id) : undefined;
  const zone = type === 'zone' ? m.zones?.find((z) => z.id === id) : undefined;
  const crossing = view.crossings.includes(id);
  const identity = component?.identity ? m.identities?.find((i) => i.id === component.identity) : undefined;
  // Controls the model doesn't answer yet, for things you run (not clients).
  const unknown =
    component && component.kind !== 'client'
      ? [
          component.encrypted_at_rest === undefined && component.stores?.length ? 'whether its data is encrypted on disk' : '',
          component.monitored === undefined ? 'whether it’s monitored' : '',
          component.patching || component.managed ? '' : 'how it gets updates',
        ].filter(Boolean)
      : [];
  const targetLabel = (target: string) => m.components?.find((c) => c.id === target)?.name ?? dataName(m, target);
  const suggestions = app.suggestions.filter((s) => s.target === id);

  if (!component && !flow && !zone) return <p className="muted">That item is no longer in the model.</p>;

  const remove = async () => {
    const name = component?.name ?? zone?.name ?? id;
    if (!confirm(`Delete “${name}”?`)) return;
    if (await app.edit((s) => core.delete(s, section, id))) app.clearSelection();
  };

  return (
    <article>
      {component && (
        <>
          <p className="eyebrow">{L.label(L.componentKinds, component.kind)}</p>
          <h2>{component.name}</h2>
          <dl className="facts">
            {component.zone && (
              <>
                <dt>Zone</dt>
                <dd>
                  <button type="button" className="link-btn" onClick={() => app.select('zone', component.zone!)}>
                    {m.zones?.find((z) => z.id === component.zone)?.name ?? component.zone}
                  </button>
                </dd>
              </>
            )}
            {component.exposure && (
              <>
                <dt>Reachable</dt>
                <dd>{L.label(L.exposures, component.exposure)}</dd>
              </>
            )}
            {component.stores?.length ? (
              <>
                <dt>Keeps</dt>
                <dd>{component.stores.map((d) => dataName(m, d)).join(', ')}</dd>
              </>
            ) : null}
            {component.tech?.length ? (
              <>
                <dt>Tech</dt>
                <dd>{component.tech.join(', ')}</dd>
              </>
            ) : null}
            {component.identity && (
              <>
                <dt>Runs as</dt>
                <dd>
                  {identity ? (
                    <button type="button" className="link-btn" onClick={() => dialogs.openForm({ section: 'identities', id: identity.id })}>
                      {identity.name}
                    </button>
                  ) : (
                    <code>{component.identity}</code>
                  )}
                  {identity?.can?.length ? (
                    <ul className="plain perms">
                      {identity.can.map((p, i) => (
                        <li key={i} className="muted small">
                          can {p.do} {targetLabel(p.on)}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </dd>
              </>
            )}
            {component.encrypted_at_rest !== undefined && (
              <>
                <dt>Encrypted on disk</dt>
                <dd>{L.yesNo(component.encrypted_at_rest)}</dd>
              </>
            )}
            {component.monitored !== undefined && (
              <>
                <dt>Monitored</dt>
                <dd>{L.yesNo(component.monitored)}</dd>
              </>
            )}
            {component.patching && (
              <>
                <dt>Updates</dt>
                <dd>
                  {L.label(L.patching, component.patching)}: {L.hint(L.patching, component.patching).toLowerCase()}
                </dd>
              </>
            )}
            {component.managed !== undefined && (
              <>
                <dt>Managed</dt>
                <dd>{component.managed ? 'Yes, the provider runs and patches it' : 'No, you run it'}</dd>
              </>
            )}
            {component.reviewed && (
              <>
                <dt>Reviewed</dt>
                <dd>
                  {component.reviewed}
                  {component.reviewed_by && ` by ${component.reviewed_by}`}
                </dd>
              </>
            )}
          </dl>
          {unknown.length > 0 && <p className="muted small">Not said yet: {unknown.join(', ')}.</p>}
          {component.notes && <p className="notes">{component.notes}</p>}
        </>
      )}
      {flow && (
        <>
          <p className="eyebrow">Flow{crossing ? ' · crosses zones' : ''}</p>
          <h2>
            {componentName(m, flow.from)} → {componentName(m, flow.to)}
          </h2>
          {crossing && <p className="callout">This flow crosses from one zone to another. That’s where most attacks happen, so look here first.</p>}
          <dl className="facts">
            {flow.carries?.length ? (
              <>
                <dt>Carries</dt>
                <dd>{flow.carries.map((d) => dataName(m, d)).join(', ')}</dd>
              </>
            ) : null}
            {flow.over && (
              <>
                <dt>Over</dt>
                <dd>{flow.over}</dd>
              </>
            )}
            {flow.auth && (
              <>
                <dt>Auth</dt>
                <dd>{L.label(L.flowAuths, flow.auth)}</dd>
              </>
            )}
            <dt>Encrypted</dt>
            <dd>{view.transit?.[flow.id] === 'unencrypted' ? 'No — anyone on the path can read or change it' : transitLabel(view, flow)}</dd>
          </dl>
          {flow.notes && <p className="notes">{flow.notes}</p>}
        </>
      )}
      {zone && (
        <>
          <p className="eyebrow">Zone · {L.label(L.trusts, zone.trust)}</p>
          <h2>{zone.name}</h2>
          <p className="muted">{L.hint(L.trusts, zone.trust)}</p>
          <dl className="facts">
            <dt>Inside</dt>
            <dd>{L.label(L.networks, zone.network ?? 'open')}: {L.hint(L.networks, zone.network ?? 'open').toLowerCase()}</dd>
            <dt>Outbound</dt>
            <dd>{L.label(L.egress, zone.egress ?? 'open')}: {L.hint(L.egress, zone.egress ?? 'open').toLowerCase()}</dd>
          </dl>
          <section className="panel-section">
            <h3>In this zone</h3>
            <ul className="plain">
              {(m.components ?? [])
                .filter((c) => c.zone === zone.id)
                .map((c) => (
                  <li key={c.id}>
                    <button type="button" className="link-btn" onClick={() => app.select('component', c.id)}>
                      {c.name}
                    </button>
                  </li>
                ))}
              {!(m.components ?? []).some((c) => c.zone === zone.id) && <li className="muted">Nothing yet. Drag a component into the zone, or set its zone.</li>}
            </ul>
          </section>
        </>
      )}

      {(component || flow) && (
        <section className="panel-section">
          <h3>Threats</h3>
          <ThreatList view={view} threats={threatsAffecting(m, id)} />
        </section>
      )}
      {suggestions.length > 0 && (
        <section className="panel-section">
          <h3>Suggested threats</h3>
          <SuggestionList suggestions={suggestions} />
        </section>
      )}

      <footer className="card-actions">
        <button type="button" className="btn small" onClick={() => dialogs.openForm({ section, id })}>
          Edit
        </button>
        {(component || flow) && (
          <button type="button" className="btn small" onClick={() => dialogs.openForm({ section: 'threats', preset: { affects: [id] } })}>
            Add a threat
          </button>
        )}
        {view.lines[id] ? (
          <button type="button" className="btn small" onClick={() => app.revealLine(view.lines[id]!)}>
            Show in YAML
          </button>
        ) : null}
        <button type="button" className="btn small danger" onClick={() => void remove()}>
          Delete
        </button>
      </footer>
    </article>
  );
}
