// The threat card. Order matters and is fixed by the spec: title, how it
// works, who could do it, how bad, why this risk, fixes, then the security
// mappings, collapsed.
import { useState, type FormEvent } from 'react';
import { app } from '../../lib/app';
import { dialogs } from '../../lib/dialogs';
import { core } from '../../core/client';
import * as L from '../../lib/labels';
import { isExpired, isOverdue, riskClass, targetName } from '../../lib/query';
import { lens } from '../../lib/lens';
import { useStore } from '../../lib/store';
import type { View } from '../../core/types';

type Mode = 'none' | 'na' | 'accept';

export function ThreatCard({ view, id }: { view: View; id: string }) {
  useStore(lens);
  const m = view.model;
  const t = m.threats?.find((x) => x.id === id);
  const a = view.risks[id];
  const [mode, setMode] = useState<Mode>('none');
  const [naReason, setNaReason] = useState('');
  const [acceptBy, setAcceptBy] = useState('');
  const [acceptReason, setAcceptReason] = useState('');
  const [acceptUntil, setAcceptUntil] = useState('');
  const [formError, setFormError] = useState('');
  const today = new Date().toISOString().slice(0, 10);

  if (!t) return <p className="muted">That threat is no longer in the model.</p>;

  const cls = riskClass(t, a);
  const fixes = (t.mitigations ?? []).map((mid) => ({
    id: mid,
    mitigation: m.mitigations?.find((x) => x.id === mid),
    change: a?.changes?.find((c) => c.mitigation === mid),
  }));
  const refs = Object.entries(t.refs ?? {});

  const setStatus = (status: 'open' | 'mitigated') => {
    setMode('none');
    void app.edit((s) => core.setStatus(s, { id, status }));
  };

  const startMode = (next: Mode) => {
    setFormError('');
    setMode(mode === next ? 'none' : next);
  };

  const markNotApplicable = async (e: FormEvent) => {
    e.preventDefault();
    const reason = naReason.trim();
    if (!reason) return setFormError('Say in one line why it doesn’t apply.');
    if (await app.edit((s) => core.setStatus(s, { id, status: 'not-applicable', reason }))) {
      setMode('none');
      setNaReason('');
    }
  };

  const accept = async (e: FormEvent) => {
    e.preventDefault();
    const by = acceptBy.trim();
    const reason = acceptReason.trim();
    if (!by || !reason || !acceptUntil) return setFormError('Accepting a risk needs who decided, why, and until when.');
    // The only place allow_accept is true: a person filling in this form.
    const ok = await app.edit((s) => core.setStatus(s, { id, status: 'accepted', accepted: { by, reason, until: acceptUntil } }, true));
    if (ok) {
      setMode('none');
      setAcceptReason('');
    }
  };

  const remove = async () => {
    if (!confirm(`Delete the threat “${t.title}”?`)) return;
    if (await app.edit((s) => core.delete(s, 'threats', id))) app.clearSelection();
  };

  return (
    <article className="card" aria-labelledby="threat-title">
      <header className="card-header">
        <div className="badges">
          <span className={`risk risk-lg risk-${cls}`}>{cls === 'na' ? 'Doesn’t apply' : L.riskLabel(a?.level)}</span>
          {a?.override && (
            <span className="flag" title="This risk level was set by hand">
              Set by hand
            </span>
          )}
          {t.status !== 'open' && <span className="flag">{L.label(L.threatStatuses, t.status)}</span>}
        </div>
        <h2 id="threat-title">{t.title}</h2>
        {t.affects?.length ? (
          <p className="where">
            On{' '}
            {t.affects.map((target, i) => (
              <span key={target}>
                {i > 0 && ', '}
                <button type="button" className="link-btn" onClick={() => app.select(m.flows?.some((f) => f.id === target) ? 'flow' : 'component', target)}>
                  {targetName(m, target)}
                </button>
              </span>
            ))}
          </p>
        ) : null}

        <div className="status-group" role="group" aria-label="Status">
          <button type="button" className="btn small" aria-pressed={t.status === 'open'} onClick={() => setStatus('open')}>
            Open
          </button>
          <button type="button" className="btn small" aria-pressed={t.status === 'mitigated'} onClick={() => setStatus('mitigated')}>
            Mitigated
          </button>
          <button type="button" className="btn small" aria-pressed={t.status === 'not-applicable'} aria-expanded={mode === 'na'} onClick={() => startMode('na')}>
            Doesn’t apply…
          </button>
          <button type="button" className="btn small" aria-pressed={t.status === 'accepted'} aria-expanded={mode === 'accept'} onClick={() => startMode('accept')}>
            Accept risk…
          </button>
        </div>

        {mode === 'na' && (
          <form className="inline-form" onSubmit={markNotApplicable}>
            <div className="field">
              <label htmlFor="na-reason">Why doesn’t it apply?</label>
              <textarea id="na-reason" rows={2} value={naReason} onChange={(e) => setNaReason(e.target.value)} required autoFocus />
            </div>
            {formError && (
              <p className="form-error" role="alert">
                {formError}
              </p>
            )}
            <div className="row">
              <button type="submit" className="btn primary small">
                Mark as doesn’t apply
              </button>
              <button type="button" className="btn small" onClick={() => setMode('none')}>
                Cancel
              </button>
            </div>
          </form>
        )}
        {mode === 'accept' && (
          <form className="inline-form" onSubmit={accept}>
            <p className="muted">Accepting a risk is a decision a person makes: who, why, and until when it should be looked at again.</p>
            <div className="field">
              <label htmlFor="acc-by">Who is accepting it?</label>
              <input id="acc-by" type="text" value={acceptBy} onChange={(e) => setAcceptBy(e.target.value)} placeholder="@alice" required autoFocus />
            </div>
            <div className="field">
              <label htmlFor="acc-reason">Why is it OK for now?</label>
              <textarea id="acc-reason" rows={2} value={acceptReason} onChange={(e) => setAcceptReason(e.target.value)} required />
            </div>
            <div className="field">
              <label htmlFor="acc-until">Until</label>
              <input id="acc-until" type="date" value={acceptUntil} min={today} onChange={(e) => setAcceptUntil(e.target.value)} required />
            </div>
            {formError && (
              <p className="form-error" role="alert">
                {formError}
              </p>
            )}
            <div className="row">
              <button type="submit" className="btn primary small">
                Accept risk
              </button>
              <button type="button" className="btn small" onClick={() => setMode('none')}>
                Cancel
              </button>
            </div>
          </form>
        )}

        {t.status === 'accepted' && t.accepted ? (
          <p className={`decision${isExpired(t.accepted.until) ? ' expired' : ''}`}>
            Accepted by <strong>{t.accepted.by}</strong> until <strong>{t.accepted.until}</strong>
            {isExpired(t.accepted.until) && ' (expired, so it needs another look)'}: {t.accepted.reason}
          </p>
        ) : t.status === 'not-applicable' && t.reason ? (
          <p className="decision">Doesn’t apply: {t.reason}</p>
        ) : null}
      </header>

      <section className="panel-section">
        <h3>How it works</h3>
        {t.attack?.length ? (
          <ol className="steps">
            {t.attack.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        ) : (
          <p className="muted">No steps written yet. If you can’t write the steps, the threat may not be real yet.</p>
        )}
      </section>

      <section className="panel-section">
        <h3>Who could do it</h3>
        {t.who ? (
          <p>
            <strong>{L.label(L.who, t.who)}</strong> <span className="muted">({L.hint(L.who, t.who)})</span>
          </p>
        ) : (
          <p className="muted">Not said yet.</p>
        )}
        {t.effort && (
          <p>
            How hard: <strong>{L.label(L.efforts, t.effort)}</strong> <span className="muted">{L.hint(L.efforts, t.effort)}</span>
          </p>
        )}
      </section>

      <section className="panel-section">
        <h3>How bad</h3>
        {t.impact ? (
          <p>
            <strong>{L.label(L.impacts, t.impact)}</strong> <span className="muted">{L.hint(L.impacts, t.impact)}</span>
          </p>
        ) : (
          <p className="muted">Not said yet.</p>
        )}
        {t.impact_note && <p>{t.impact_note}</p>}
      </section>

      <section className="panel-section">
        <h3>Why this risk</h3>
        <p>{a?.why ?? ''}</p>
      </section>

      <section className="panel-section">
        <h3>Fixes</h3>
        {fixes.length ? (
          <ul className="fixes">
            {fixes.map((f) => (
              <li key={f.id} className={`fix status-${f.mitigation?.status ?? 'missing'}`}>
                {f.mitigation ? (
                  <>
                    <p className="fix-title">
                      {f.mitigation.title}
                      {isOverdue(f.mitigation) && <span className="overdue-tag">overdue</span>}
                    </p>
                    {(f.mitigation.owner || f.mitigation.due) && (
                      <p className="muted small">
                        {[f.mitigation.owner, f.mitigation.due && `due ${f.mitigation.due}`].filter(Boolean).join(' · ')}
                      </p>
                    )}
                    <div className="fix-meta">
                      <label className="sr-only" htmlFor={`fix-${f.id}`}>
                        Status of {f.mitigation.title}
                      </label>
                      <select
                        id={`fix-${f.id}`}
                        className="fix-status"
                        value={f.mitigation.status}
                        onChange={(e) => {
                          const status = e.target.value;
                          void app.edit((s) => core.setStatus(s, { id: f.id, status }));
                        }}
                      >
                        {L.mitigationStatuses.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                      {f.change?.to ? (
                        f.mitigation.status === 'done' ? (
                          <span className="change">Done: {f.change.effect}</span>
                        ) : (
                          <span className="change">
                            → <span className={`risk risk-${f.change.to}`}>{f.change.to}</span> once done
                          </span>
                        )
                      ) : !f.mitigation.effect ? (
                        <span className="muted small">Doesn’t say what it changes yet.</span>
                      ) : null}
                      <button type="button" className="btn ghost small" onClick={() => dialogs.openForm({ section: 'mitigations', id: f.id })}>
                        Edit
                      </button>
                    </div>
                    {f.change?.effect && f.mitigation.status !== 'done' && <p className="muted small">What it changes: {f.change.effect}.</p>}
                  </>
                ) : (
                  <p className="muted">
                    Fix <code>{f.id}</code> isn’t defined in the file.
                  </p>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">No fixes yet.</p>
        )}
        <button type="button" className="btn small" onClick={() => dialogs.openForm({ section: 'mitigations', linkToThreat: id })}>
          Add a fix
        </button>
      </section>

      {/* Reviewers see the mappings straight away; developers can open them. */}
      <details className="panel-section security" open={lens.reviewer || undefined}>
        <summary>For security teams</summary>
        <dl>
          {t.kind && (
            <>
              <dt>Kind</dt>
              <dd>
                <code>{t.kind}</code> — {L.hint(L.threatKinds, t.kind)}
              </dd>
            </>
          )}
          {refs.map(([scheme, ids]) => (
            <div key={scheme} className="dl-row">
              <dt>{scheme.toUpperCase()}</dt>
              <dd>{ids.join(', ')}</dd>
            </div>
          ))}
          {a?.inherent_level && (
            <>
              <dt>Before fixes</dt>
              <dd>
                {a.inherent_level}
                {a.likelihood && `, likelihood ${a.likelihood}`}
              </dd>
            </>
          )}
          {t.from && (
            <>
              <dt>From the library</dt>
              <dd>
                <code>{t.from}</code>
              </dd>
            </>
          )}
          <dt>ID</dt>
          <dd>
            <code>{t.id}</code>
          </dd>
        </dl>
        {!refs.length && <p className="muted small">No STRIDE, CWE or other mappings.</p>}
      </details>

      <footer className="card-actions">
        <button type="button" className="btn small" onClick={() => dialogs.openForm({ section: 'threats', id })}>
          Edit
        </button>
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
