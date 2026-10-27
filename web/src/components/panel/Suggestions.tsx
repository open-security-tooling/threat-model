// Library threats that match the model. The tool suggests; a person adds
// one or dismisses it with a reason, so the file only holds decisions.
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { app } from '../../lib/app';
import { useStore } from '../../lib/store';
import { core } from '../../core/client';
import * as L from '../../lib/labels';
import type { Suggestion } from '../../core/types';
import { ReasonDialog } from '../ReasonDialog';

const keyOf = (s: Suggestion) => `${s.from}|${s.target}`;

const add = (s: Suggestion) => app.edit((src) => core.acceptSuggestion(src, s.from, s.target));
const dismiss = (s: Suggestion, reason: string) => app.edit((src) => core.dismissSuggestion(src, s.from, s.target, reason));

function Level({ s }: { s: Suggestion }) {
  return <span className={`risk risk-${s.level || 'none'}`}>{s.level ? L.riskLabel(s.level) : 'Not rated'}</span>;
}

function Details({ s }: { s: Suggestion }) {
  return (
    <div className="suggestion-details">
      {s.threat.attack?.length ? (
        <ol className="steps">
          {s.threat.attack.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
        </ol>
      ) : null}
      {s.mitigations.length > 0 && (
        <>
          <p className="small strong">Fixes it would add</p>
          <ul className="small">
            {s.mitigations.map((m) => (
              <li key={m.id}>{m.title}</li>
            ))}
          </ul>
        </>
      )}
      {s.advice &&
        Object.entries(s.advice).map(([k, v]) => (
          <p key={k} className="small">
            <strong>{k}:</strong> {v}
          </p>
        ))}
    </div>
  );
}

function SuggestionItem({ s }: { s: Suggestion }) {
  const [dismissing, setDismissing] = useState(false);
  const [reason, setReason] = useState('');
  const [open, setOpen] = useState(false);

  const onAdd = async () => {
    if (await add(s)) app.select('threat', s.threat.id);
  };
  const onDismiss = async (e: FormEvent) => {
    e.preventDefault();
    const r = reason.trim();
    if (r) await dismiss(s, r);
  };
  const id = `dismiss-${keyOf(s).replace(/[^a-z0-9-]/gi, '-')}`;

  return (
    <li className="suggestion">
      <p className="muted small">
        <Level s={s} /> {L.label(L.threatKinds, s.threat.kind)}
      </p>
      <p className="suggestion-title">{s.threat.title}</p>
      {s.why_it_matters && <p className="small">{s.why_it_matters}</p>}
      <button type="button" className="link-btn small" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? 'Hide details' : 'How it works and fixes'}
      </button>
      {open && <Details s={s} />}
      {dismissing ? (
        <form className="inline-form" onSubmit={onDismiss}>
          <div className="field">
            <label htmlFor={id}>Why doesn’t it apply?</label>
            <input id={id} type="text" value={reason} onChange={(e) => setReason(e.target.value)} required autoFocus />
          </div>
          <div className="row">
            <button type="submit" className="btn small primary" disabled={!reason.trim()}>
              Dismiss
            </button>
            <button type="button" className="btn small" onClick={() => setDismissing(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="row">
          <button type="button" className="btn small primary" onClick={() => void onAdd()}>
            Add
          </button>
          <button type="button" className="btn small" onClick={() => setDismissing(true)}>
            Dismiss…
          </button>
        </div>
      )}
    </li>
  );
}

/** Suggestions grouped by the component (or flow, or identity) they're for, highest risk first. */
export function SuggestionList({ suggestions, grouped = true }: { suggestions: Suggestion[]; grouped?: boolean }) {
  const [bulk, setBulk] = useState<{ name: string; items: Suggestion[] } | null>(null);
  if (!suggestions.length) return <p className="muted">No suggestions right now.</p>;
  if (!grouped) {
    return (
      <ul className="suggestions">
        {suggestions.map((s) => (
          <SuggestionItem key={keyOf(s)} s={s} />
        ))}
      </ul>
    );
  }
  // The core sorts highest risk first; groups keep that order.
  const groups = new Map<string, { name: string; items: Suggestion[] }>();
  for (const s of suggestions) {
    const g = groups.get(s.target) ?? { name: s.target_name, items: [] };
    g.items.push(s);
    groups.set(s.target, g);
  }
  return (
    <>
      {[...groups.entries()].map(([target, g]) => (
        <section key={target} className="suggestion-group" aria-label={`Suggestions for ${g.name}`}>
          <div className="suggestion-group-head">
            <h3>
              {g.name} <span className="muted">({g.items.length})</span>
            </h3>
            {g.items.length > 1 && (
              <button type="button" className="btn ghost small" onClick={() => setBulk(g)}>
                Dismiss all…
              </button>
            )}
          </div>
          <ul className="suggestions">
            {g.items.map((s) => (
              <SuggestionItem key={keyOf(s)} s={s} />
            ))}
          </ul>
        </section>
      ))}
      {bulk && (
        <ReasonDialog
          title={`Dismiss all ${bulk.items.length} suggestions for ${bulk.name}`}
          label="Why don’t they apply? (Recorded on each one.)"
          confirm={`Dismiss ${bulk.items.length}`}
          // One edit: every dismissal applies, or none does.
          onSubmit={(r) => app.edit(...bulk.items.map((s) => (src: string) => core.dismissSuggestion(src, s.from, s.target, r)))}
          onClose={() => setBulk(null)}
        />
      )}
    </>
  );
}

/** One suggestion at a time: Add, Dismiss with a reason, or Skip. */
function TriageQueue({ onDone }: { onDone: () => void }) {
  useStore(app);
  // The queue is fixed when it starts; handled ones drop out of app.suggestions.
  const [queue] = useState(() => app.suggestions.map(keyOf));
  const [index, setIndex] = useState(0);
  const [counts, setCounts] = useState({ added: 0, dismissed: 0, skipped: 0 });
  const [dismissing, setDismissing] = useState(false);
  const [reason, setReason] = useState('');
  const box = useRef<HTMLDivElement>(null);

  const current = queue.slice(index).map((k) => app.suggestions.find((s) => keyOf(s) === k)).find((s): s is Suggestion => !!s);
  const position = current ? queue.indexOf(keyOf(current)) : queue.length;

  useEffect(() => {
    if (!dismissing) box.current?.focus();
  }, [position, dismissing]);

  const next = (what: 'added' | 'dismissed' | 'skipped') => {
    setCounts((c) => ({ ...c, [what]: c[what] + 1 }));
    setDismissing(false);
    setReason('');
    setIndex(position + 1);
  };
  const doAdd = async () => {
    if (current && (await add(current))) next('added');
  };
  const doDismiss = async (e?: FormEvent) => {
    e?.preventDefault();
    const r = reason.trim();
    if (current && r && (await dismiss(current, r))) next('dismissed');
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.target instanceof HTMLInputElement || e.metaKey || e.ctrlKey || e.altKey) return;
    const k = e.key.toLowerCase();
    if (k === 'a') {
      e.preventDefault();
      void doAdd();
    } else if (k === 'd') {
      e.preventDefault();
      setDismissing(true);
    } else if (k === 's' || k === 'arrowright') {
      e.preventDefault();
      next('skipped');
    } else if (k === 'arrowleft' && position > 0) {
      e.preventDefault();
      setIndex(Math.max(0, position - 1));
    }
  };

  if (!current) {
    return (
      <div className="triage" ref={box} tabIndex={-1}>
        <h3>All done</h3>
        <p>
          {counts.added} added, {counts.dismissed} dismissed, {counts.skipped} skipped.
        </p>
        <button type="button" className="btn small" onClick={onDone}>
          Back to the list
        </button>
      </div>
    );
  }

  return (
    <div className="triage" ref={box} tabIndex={-1} onKeyDown={onKey} aria-label="Suggestion triage" role="group">
      <p className="muted small" aria-live="polite">
        {position + 1} of {queue.length} · on {current.target_name}
      </p>
      <p>
        <Level s={current} /> <span className="muted small">{L.label(L.threatKinds, current.threat.kind)}</span>
      </p>
      <h3 className="suggestion-title">{current.threat.title}</h3>
      {current.why_it_matters && <p className="small">{current.why_it_matters}</p>}
      <Details s={current} />
      {dismissing ? (
        <form className="inline-form" onSubmit={doDismiss}>
          <div className="field">
            <label htmlFor="triage-reason">Why doesn’t it apply?</label>
            <input
              id="triage-reason"
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => e.key === 'Escape' && (e.preventDefault(), setDismissing(false))}
              required
              autoFocus
            />
          </div>
          <div className="row">
            <button type="submit" className="btn small primary" disabled={!reason.trim()}>
              Dismiss
            </button>
            <button type="button" className="btn small" onClick={() => setDismissing(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="row wrap">
          <button type="button" className="btn small primary" onClick={() => void doAdd()} aria-keyshortcuts="A">
            Add <kbd>A</kbd>
          </button>
          <button type="button" className="btn small" onClick={() => setDismissing(true)} aria-keyshortcuts="D">
            Dismiss… <kbd>D</kbd>
          </button>
          <button type="button" className="btn small" onClick={() => next('skipped')} aria-keyshortcuts="S">
            Skip <kbd>S</kbd>
          </button>
          <button type="button" className="btn ghost small" onClick={onDone}>
            Stop
          </button>
        </div>
      )}
      <p className="muted small">Keys: A add · D dismiss · S or → skip · ← back</p>
    </div>
  );
}

export function SuggestionsPanel() {
  useStore(app);
  const [triage, setTriage] = useState(false);
  return (
    <article>
      <h2>Suggested threats</h2>
      <p className="muted panel-intro">
        Threats from the library that match what you’ve drawn, highest risk first. Add the ones that are real, and dismiss the rest with a reason so reviewers can see you thought
        about them.
      </p>
      {triage ? (
        <TriageQueue onDone={() => setTriage(false)} />
      ) : (
        <>
          {app.suggestions.length > 1 && (
            <button type="button" className="btn small primary space-bottom" onClick={() => setTriage(true)}>
              Go through them one by one
            </button>
          )}
          <SuggestionList suggestions={app.suggestions} />
        </>
      )}
    </article>
  );
}
