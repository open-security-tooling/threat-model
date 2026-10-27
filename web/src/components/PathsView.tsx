// Attack paths: pick where someone starts and what they're after, and see
// the chains of threats that get them there, highlighted on the diagram. The
// blast-radius mode asks the reverse: if this component is taken over, what
// else does that give away?
import { useEffect, useState } from 'react';
import { app } from '../lib/app';
import { core } from '../core/client';
import type { AttackPath, BlastResult, PathsResult, View } from '../core/types';
import * as L from '../lib/labels';
import { Diagram } from './diagram/Diagram';

type Mode = 'paths' | 'blast';

function highlightFor(view: View, paths: AttackPath[], extra: string[] = []) {
  const threats = new Set<string>();
  for (const p of paths) for (const s of p.steps) if (s.threat) threats.add(s.threat);
  const components = new Set<string>(extra);
  for (const id of threats) {
    for (const target of view.model.threats?.find((t) => t.id === id)?.affects ?? []) {
      const f = view.model.flows?.find((x) => x.id === target);
      if (f) {
        components.add(f.from);
        components.add(f.to);
      } else components.add(target);
    }
  }
  return { threats, components };
}

/** Paths that get the data out first; contained ones after. */
const ordered = (paths: AttackPath[]) => [...paths.filter((p) => !p.contained), ...paths.filter((p) => p.contained)];

function PathList({ paths, focus, onFocus }: { paths: AttackPath[]; focus: number | null; onFocus: (i: number | null) => void }) {
  return (
    <ol className="paths">
      {paths.map((p, i) => (
        <li key={i} className={[focus === i && 'focused', p.contained && 'contained'].filter(Boolean).join(' ') || undefined}>
          <button type="button" className="path-head" aria-pressed={focus === i} onClick={() => onFocus(focus === i ? null : i)}>
            <strong>{p.target_name}</strong>
            <span className="muted"> · hardest step: {L.label(L.efforts, p.weakest) || p.weakest}</span>
            {p.contained && <span className="contained-tag">can’t get it out</span>}
          </button>
          <ol className="path-steps">
            {p.steps.map((s, j) => (
              <li key={j} className={s.rule ? 'rule-step' : undefined}>
                {s.threat ? (
                  <button type="button" className="link-btn" onClick={() => app.select('threat', s.threat!)}>
                    {s.title}
                  </button>
                ) : (
                  <span className="muted">{s.title}</span>
                )}
                {s.gains.length > 0 && <span className="gains"> → {s.gains.join(', ')}</span>}
              </li>
            ))}
            {p.exit && (
              <li className={p.contained ? 'exit-step contained' : 'exit-step'}>
                <span className="exit-label">{p.contained ? 'Stays in' : 'Gets out'}</span> {p.exit}
              </li>
            )}
          </ol>
        </li>
      ))}
    </ol>
  );
}

/** Everything a takeover reaches; what it adds comes first in each list. */
function BlastSummary({ blast, name }: { blast: BlastResult; name: (id: string) => string }) {
  const already = new Set(blast.already_reachable);
  const label = (id: string) => blast.names[id] ?? name(id);
  const groups: [string, string[]][] = [
    ['Reads', blast.reads],
    ['Changes', blast.changes],
    ['Controls', blast.controls],
  ];
  const adds = groups.reduce((n, [, ids]) => n + ids.filter((id) => !already.has(id)).length, 0);
  return (
    <section className="panel-section">
      <h3>Taking over {label(blast.component)}</h3>
      <p className="small">
        {adds
          ? `Adds ${adds} ${adds === 1 ? 'thing' : 'things'} an attacker on the internet couldn’t reach before.`
          : 'Adds nothing new: anyone on the internet can already reach all of this. Fix the ways in first (see “Ways in”).'}
      </p>
      <dl className="facts blast">
        {groups.map(([title, ids]) => (
          <div key={title} className="dl-row">
            <dt>{title}</dt>
            <dd>
              {ids.length ? (
                <ul className="plain">
                  {[...ids.filter((id) => !already.has(id)), ...ids.filter((id) => already.has(id))].map((id) => (
                    <li key={id} className={already.has(id) ? 'already' : 'adds'}>
                      {label(id)}
                      {already.has(id) ? <span className="muted small"> · reachable from the internet anyway</span> : <span className="adds-tag">new</span>}
                    </li>
                  ))}
                </ul>
              ) : (
                <span className="muted">nothing</span>
              )}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export function PathsView({ view }: { view: View }) {
  const m = view.model;
  const [mode, setMode] = useState<Mode>('paths');
  const [start, setStart] = useState('anyone');
  const [target, setTarget] = useState('');
  const [component, setComponent] = useState(m.components?.[0]?.id ?? '');
  const [result, setResult] = useState<PathsResult | null>(null);
  const [blast, setBlast] = useState<BlastResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [focus, setFocus] = useState<number | null>(null);
  const source = app.source;

  useEffect(() => {
    let cancelled = false;
    const run =
      mode === 'paths'
        ? core.paths(source, start, target ? [target] : undefined).then((r) => !cancelled && setResult(r))
        : component
          ? core.blastRadius(source, component).then((r) => !cancelled && setBlast(r))
          : Promise.resolve();
    run
      .then(() => {
        if (cancelled) return;
        setError(null);
        setFocus(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setResult(null);
        setBlast(null);
        setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [source, mode, start, target, component]);

  const paths = ordered((mode === 'paths' ? result?.paths : blast?.paths) ?? []);

  useEffect(() => {
    const all = ordered((mode === 'paths' ? result?.paths : blast?.paths) ?? []);
    const shown = focus === null ? all : all.slice(focus, focus + 1);
    app.setHighlight(highlightFor(view, shown, mode === 'blast' && component ? [component] : []));
  }, [view, result, blast, focus, mode, component]);
  useEffect(() => () => app.setHighlight(null), []);

  const name = (id: string) => m.components?.find((c) => c.id === id)?.name ?? m.data?.find((d) => d.id === id)?.name ?? id;
  const contained = paths.filter((p) => p.contained).length;

  return (
    <div className="split">
      <div className="paths-pane">
        <div className="segmented-control" role="group" aria-label="What to look at">
          <button type="button" className="btn small" aria-pressed={mode === 'paths'} onClick={() => setMode('paths')}>
            Ways in
          </button>
          <button type="button" className="btn small" aria-pressed={mode === 'blast'} onClick={() => setMode('blast')}>
            If a component is taken over
          </button>
        </div>
        {mode === 'paths' ? (
          <div className="row wrap">
            <div className="field">
              <label htmlFor="p-start">Who starts</label>
              <select id="p-start" value={start} onChange={(e) => setStart(e.target.value)}>
                {L.who.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
                {(m.components ?? []).map((c) => (
                  <option key={c.id} value={`controls:${c.id}`}>
                    Someone who controls {c.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="p-target">What they’re after</label>
              <select id="p-target" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Any data</option>
                {(m.data ?? []).map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
        ) : (
          <div className="field">
            <label htmlFor="p-comp">Component</label>
            <select id="p-comp" value={component} onChange={(e) => setComponent(e.target.value)}>
              {(m.components ?? []).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
        )}

        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}

        {mode === 'blast' && blast && <BlastSummary blast={blast} name={name} />}

        {(mode === 'paths' ? result : blast) && (
          <>
            <p className="count" aria-live="polite">
              {paths.length
                ? `${paths.length} ${paths.length === 1 ? 'way' : 'ways'} to the data${contained ? `, ${contained} of them can’t get it out` : ''}. Steps are numbered in order.`
                : mode === 'paths'
                  ? 'No way in from here with the threats in the model.'
                  : 'No paths to data from this component.'}
            </p>
            <PathList paths={paths} focus={focus} onFocus={setFocus} />
          </>
        )}

        {mode === 'paths' && result && result.fixes.length > 0 && (
          <section className="panel-section">
            <h3>Fixes that cut or slow these paths</h3>
            <ul className="plain">
              {result.fixes.map((f) => (
                <li key={f.mitigation}>
                  {f.title}{' '}
                  <span className="muted">
                    ({L.label(L.mitigationStatuses, f.status)})
                    {f.breaks.length > 0 && <> cuts off {f.breaks.map(name).join(', ')}</>}
                    {f.breaks.length > 0 && (f.harder ?? []).length > 0 && ';'}
                    {(f.harder ?? []).length > 0 && <> makes the easiest way to {f.harder.map(name).join(', ')} harder</>}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {mode === 'paths' && result && result.unreachable.length > 0 && (
          <section className="panel-section">
            <h3>Out of reach</h3>
            <p className="muted">{result.unreachable.map(name).join(', ')}</p>
          </section>
        )}
      </div>
      <div className="split-main">
        <Diagram />
      </div>
    </div>
  );
}
