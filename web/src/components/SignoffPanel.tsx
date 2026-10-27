// A sign-off is a person's statement that they reviewed the whole model. It
// goes in the file (`signoff`), so it shows up in the PR like any change.
import { useState, type FormEvent } from 'react';
import { app } from '../lib/app';
import { core } from '../core/client';
import type { Model } from '../core/types';

export function SignoffPanel({ model }: { model: Model }) {
  const s = model.signoff;
  const today = new Date().toISOString().slice(0, 10);
  const [editing, setEditing] = useState(false);
  const [by, setBy] = useState('');
  const [on, setOn] = useState(today);
  const [note, setNote] = useState('');
  const [confirmed, setConfirmed] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!confirmed || !by.trim() || !on) return;
    const ok = await app.edit((src) => core.setSignoff(src, { by: by.trim(), on, ...(note.trim() ? { note: note.trim() } : {}) }));
    if (ok) {
      setEditing(false);
      setConfirmed(false);
    }
  };

  const remove = () => {
    if (confirm('Remove the sign-off from the model?')) void app.edit((src) => core.setSignoff(src, null));
  };

  return (
    <section className="signoff-panel" aria-labelledby="signoff-title">
      <h3 id="signoff-title">Sign-off</h3>
      {s ? (
        <p className="signoff-current">
          Reviewed and signed off by <strong>{s.by}</strong> on <strong>{s.on}</strong>
          {s.note ? `: ${s.note}` : '.'}
        </p>
      ) : (
        <p className="muted">Nobody has signed off on this model yet.</p>
      )}
      {editing ? (
        <form className="inline-form" onSubmit={submit}>
          <p className="small">A sign-off says that you, a person, reviewed this model: its components, flows, threats and decisions. It’s saved in the file.</p>
          <div className="row wrap">
            <div className="field">
              <label htmlFor="so-by">Your name or handle</label>
              <input id="so-by" type="text" value={by} onChange={(e) => setBy(e.target.value)} placeholder="@alice" required />
            </div>
            <div className="field">
              <label htmlFor="so-on">Date</label>
              <input id="so-on" type="date" value={on} max={today} onChange={(e) => setOn(e.target.value)} required />
            </div>
          </div>
          <div className="field">
            <label htmlFor="so-note">Note (optional)</label>
            <input id="so-note" type="text" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Reviewed for the Q4 release" />
          </div>
          <label className="check">
            <input type="checkbox" name="signoff-confirm" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            <span>I’ve reviewed this model.</span>
          </label>
          <div className="row">
            <button type="submit" className="btn small primary" disabled={!confirmed || !by.trim() || !on}>
              Sign off
            </button>
            <button type="button" className="btn small" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="row">
          <button type="button" className="btn small" onClick={() => setEditing(true)}>
            {s ? 'Sign off again' : 'Sign off…'}
          </button>
          {s && (
            <button type="button" className="btn small danger" onClick={remove}>
              Remove sign-off
            </button>
          )}
        </div>
      )}
    </section>
  );
}
