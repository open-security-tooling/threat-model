import { useEffect, useRef, useState, type FormEvent } from 'react';
import { app, type Step } from '../lib/app';
import { dialogs, type FormRequest } from '../lib/dialogs';
import { core } from '../core/client';
import { CoreError, type Diagnostic, type Section, type View } from '../core/types';
import { FormError, permissionTargets, specs, toPatch, toValues, type EffectValue, type FieldSpec, type FormValue, type FormValues, type PermRow, type ReviewedValue } from '../lib/forms';
import { ID_PATTERN, slugify, takenIds, uniqueId } from '../lib/ids';
import * as L from '../lib/labels';
import { DiagnosticList } from './DiagnosticList';

function findItem(view: View, req: FormRequest): Record<string, unknown> | undefined {
  const m = view.model;
  if (req.section === 'system') return m.system as unknown as Record<string, unknown>;
  if (!req.id) return undefined;
  const list = (m[req.section] ?? []) as { id: string }[];
  return list.find((i) => i.id === req.id) as Record<string, unknown> | undefined;
}

function suggestId(req: FormRequest, values: FormValues, view: View): string {
  const spec = specs[req.section];
  if (req.section === 'flows') {
    const from = values.from as string;
    const to = values.to as string;
    return from && to ? `${from}-to-${to}` : '';
  }
  const name = values[spec.nameField];
  const base = typeof name === 'string' ? slugify(name.split(/\s+/).slice(0, 8).join(' '), '') : '';
  return base ? uniqueId(base, takenIds(view.model)) : '';
}

function Field({ f, value, onChange, view }: { f: FieldSpec; value: FormValue; onChange: (v: FormValue) => void; view: View }) {
  const id = `f-${f.name}`;
  const help = f.help ? <span className="help">{f.help}</span> : null;
  const options = f.options?.(view.model) ?? [];
  switch (f.kind) {
    case 'textarea':
    case 'lines':
    case 'evidence':
    case 'refmap':
      return (
        <div className="field">
          <label htmlFor={id}>
            {f.label}
            {f.required && ' *'}
          </label>
          {help}
          <textarea id={id} rows={f.kind === 'textarea' ? 2 : 4} value={value as string} onChange={(e) => onChange(e.target.value)} placeholder={f.placeholder} required={f.required} />
        </div>
      );
    case 'select':
      return (
        <div className="field">
          <label htmlFor={id}>
            {f.label}
            {f.required && ' *'}
          </label>
          {help}
          <select id={id} value={value as string} onChange={(e) => onChange(e.target.value)} required={f.required}>
            <option value="">{f.required ? 'Choose…' : 'Not set'}</option>
            {options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
                {o.hint ? ` — ${o.hint}` : ''}
              </option>
            ))}
          </select>
        </div>
      );
    case 'refs': {
      const selected = value as string[];
      return (
        <fieldset className="field refs">
          <legend>{f.label}</legend>
          {help}
          {options.length ? (
            <div className="checks">
              {options.map((o) => (
                <label key={o.value} className="check">
                  <input
                    type="checkbox"
                    name={`${id}-${o.value}`}
                    checked={selected.includes(o.value)}
                    onChange={(e) => onChange(e.target.checked ? [...selected, o.value] : selected.filter((x) => x !== o.value))}
                  />
                  <span>
                    {o.label}
                    {o.hint && <span className="muted"> ({o.hint})</span>}
                  </span>
                </label>
              ))}
            </div>
          ) : (
            <span className="muted small">Nothing to pick from yet.</span>
          )}
        </fieldset>
      );
    }
    case 'reviewed': {
      const r = value as ReviewedValue;
      return (
        <fieldset className="field">
          <legend>{f.label}</legend>
          <div className="row wrap">
            <label className="field">
              <span className="help">On</span>
              <input type="date" name="reviewed-on" value={r.on} onChange={(e) => onChange({ ...r, on: e.target.value })} />
            </label>
            <label className="field">
              <span className="help">By (optional)</span>
              <input type="text" name="reviewed-by" value={r.by} placeholder="@alice" onChange={(e) => onChange({ ...r, by: e.target.value })} />
            </label>
          </div>
        </fieldset>
      );
    }
    case 'tristate':
      return (
        <fieldset className="field">
          <legend>{f.label}</legend>
          {help}
          <div className="row wrap tristate">
            {(
              [
                ['yes', 'Yes'],
                ['no', 'No'],
                ['', 'Don’t know'],
              ] as const
            ).map(([v, text]) => (
              <label key={v || 'unknown'} className="check">
                <input type="radio" name={id} checked={value === v} onChange={() => onChange(v)} />
                <span>{text}</span>
              </label>
            ))}
          </div>
        </fieldset>
      );
    case 'perms': {
      const rows = value as PermRow[];
      const targets = permissionTargets(view.model);
      const setRow = (i: number, patch: Partial<PermRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
      return (
        <fieldset className="field">
          <legend>{f.label}</legend>
          {help}
          {rows.length > 0 && (
            <ul className="perm-rows">
              {rows.map((r, i) => (
                <li key={i} className="perm-row">
                  <select name={`can-${i}-do`} aria-label={`Permission ${i + 1}: what it can do`} value={r.do} onChange={(e) => setRow(i, { do: e.target.value })}>
                    <option value="">Can…</option>
                    {L.permissions.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  <select name={`can-${i}-on`} aria-label={`Permission ${i + 1}: on what`} value={r.on} onChange={(e) => setRow(i, { on: e.target.value })}>
                    <option value="">On…</option>
                    {targets.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                        {o.hint ? ` (${o.hint})` : ''}
                      </option>
                    ))}
                  </select>
                  <button type="button" className="btn ghost small" aria-label={`Remove permission ${i + 1}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          )}
          <button type="button" className="btn small" onClick={() => onChange([...rows, { do: '', on: '' }])}>
            Add a permission
          </button>
        </fieldset>
      );
    }
    case 'effect': {
      const e = value as EffectValue;
      const set = (patch: Partial<EffectValue>) => onChange({ ...e, ...patch });
      return (
        <fieldset className="field">
          <legend>{f.label}</legend>
          <select name="effect-mode" aria-label="What the fix does" value={e.mode} onChange={(ev) => set({ mode: ev.target.value as EffectValue['mode'] })}>
            <option value="">Not said yet</option>
            <option value="eliminates">Makes the attack impossible</option>
            <option value="detects">Lets you notice it happening</option>
            <option value="change">Changes who could do it, how hard it is, or how bad it is</option>
          </select>
          {e.mode === 'change' && (
            <div className="effect-grid">
              <label>
                Only
                <select name="effect-who" value={e.who} onChange={(ev) => set({ who: ev.target.value })}>
                  <option value="">(unchanged)</option>
                  {L.who.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                How hard
                <select name="effect-effort" value={e.effort} onChange={(ev) => set({ effort: ev.target.value })}>
                  <option value="">(unchanged)</option>
                  {L.efforts.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                How bad
                <select name="effect-impact" value={e.impact} onChange={(ev) => set({ impact: ev.target.value })}>
                  <option value="">(unchanged)</option>
                  {L.impacts.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}
        </fieldset>
      );
    }
    default:
      return (
        <div className="field">
          <label htmlFor={id}>
            {f.label}
            {f.required && ' *'}
          </label>
          {help}
          <input id={id} type={f.kind === 'date' ? 'date' : 'text'} value={value as string} onChange={(e) => onChange(e.target.value)} placeholder={f.placeholder} required={f.required} />
        </div>
      );
  }
}

export function ItemForm({ request, view }: { request: FormRequest; view: View }) {
  const spec = specs[request.section];
  const item = findItem(view, request);
  const editing = request.section === 'system' || !!request.id;
  // Captured once: the patch is what changed since the form opened.
  const [original] = useState(() => (editing ? toValues(spec, item) : null));
  const [values, setValues] = useState<FormValues>(() => {
    const v = toValues(spec, editing ? item : request.preset);
    if (!editing && request.section === 'components' && !v.kind) v.kind = 'service';
    if (!editing && request.section === 'mitigations' && !v.status) v.status = 'planned';
    if (!editing && request.section === 'data' && !v.sensitivity) v.sensitivity = 'confidential';
    if (!editing && request.section === 'zones' && !v.trust) v.trust = 'trusted';
    return v;
  });
  const [id, setId] = useState('');
  const [idTouched, setIdTouched] = useState(false);
  const [error, setError] = useState<{ message: string; diagnostics: Diagnostic[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const d = dialog.current;
    if (!d || d.open) return;
    d.showModal();
    // showModal() focuses the first focusable element, the close button; start in the first field instead.
    d.querySelector<HTMLElement>('.dialog-body input, .dialog-body select, .dialog-body textarea')?.focus();
  }, []);

  const effectiveId = editing ? (request.id ?? '') : idTouched ? id : suggestId(request, values, view);
  const basic = spec.fields.filter((f) => !f.advanced);
  const advanced = spec.fields.filter((f) => f.advanced);
  const missing = editing && !item;
  const title = `${editing ? 'Edit' : 'Add'} ${spec.noun}`;

  const close = () => dialogs.closeForm();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    let patch;
    try {
      patch = toPatch(spec, values, original);
    } catch (err) {
      if (err instanceof FormError) return setError({ message: err.message, diagnostics: [] });
      throw err;
    }
    if (!editing && !ID_PATTERN.test(effectiveId)) return setError({ message: 'The ID should be lowercase letters, digits and dashes, like invoice-api.', diagnostics: [] });
    if (!Object.keys(patch).length) return close();
    const steps: Step[] = [];
    if (request.section === 'system') {
      steps.push((s) => core.setSystem(s, patch));
    } else {
      const section = request.section as Section;
      if (section === 'threats' && !editing) patch.status = 'open';
      steps.push((s) => core.upsert(s, section, effectiveId, patch));
      const link = request.linkToThreat;
      if (link && !editing) {
        const current = view.model.threats?.find((t) => t.id === link)?.mitigations ?? [];
        steps.push((s) => core.upsert(s, 'threats', link, { mitigations: [...current, effectiveId] }));
      }
    }
    setBusy(true);
    try {
      await app.editOrThrow(...steps);
      close();
      if (!editing && request.section === 'threats') app.select('threat', effectiveId);
      else if (!editing && request.section === 'components') app.select('component', effectiveId);
      else if (!editing && request.section === 'flows') app.select('flow', effectiveId);
      else if (!editing && request.section === 'zones') app.select('zone', effectiveId);
    } catch (err) {
      setError(err instanceof CoreError ? { message: err.message, diagnostics: err.diagnostics } : { message: err instanceof Error ? err.message : String(err), diagnostics: [] });
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (request.section === 'system' || !request.id) return;
    const section = request.section;
    const itemId = request.id;
    if (!confirm(`Delete this ${spec.noun}?`)) return;
    setError(null);
    try {
      await app.editOrThrow((s) => core.delete(s, section, itemId));
      if (app.selection?.id === itemId) app.clearSelection();
      close();
    } catch (err) {
      setError(err instanceof CoreError ? { message: err.message, diagnostics: err.diagnostics } : { message: String(err), diagnostics: [] });
    }
  };

  const set = (name: string) => (v: FormValue) => setValues((prev) => ({ ...prev, [name]: v }));

  return (
    <dialog
      ref={dialog}
      className="form-dialog"
      aria-labelledby="form-title"
      onCancel={(e) => {
        e.preventDefault();
        close();
      }}
    >
      <form onSubmit={submit}>
        <header className="dialog-head">
          <h2 id="form-title">{title}</h2>
          <button type="button" className="btn ghost small" onClick={close} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="dialog-body">
          {missing ? (
            <p className="muted">That item is no longer in the model.</p>
          ) : (
            <>
              {basic.map((f) => (
                <Field key={f.name} f={f} value={values[f.name]!} onChange={set(f.name)} view={view} />
              ))}
              {request.section !== 'system' && (
                <div className="field">
                  <label htmlFor="f-id">ID</label>
                  <span className="help">{editing ? 'IDs can’t be changed here, because other items refer to them.' : 'How other items and tools refer to it.'}</span>
                  <input
                    id="f-id"
                    type="text"
                    className="mono"
                    value={effectiveId}
                    readOnly={editing}
                    onChange={(e) => {
                      setIdTouched(true);
                      setId(e.target.value);
                    }}
                  />
                </div>
              )}
              {advanced.length > 0 && (
                <details className="more-fields">
                  <summary>More</summary>
                  {advanced.map((f) => (
                    <Field key={f.name} f={f} value={values[f.name]!} onChange={set(f.name)} view={view} />
                  ))}
                </details>
              )}
            </>
          )}
          {error && (
            <div className="form-error" role="alert">
              <p>{error.message}</p>
              {error.diagnostics.length > 0 && <DiagnosticList diagnostics={error.diagnostics} />}
            </div>
          )}
        </div>
        <footer className="dialog-foot">
          {editing && request.section !== 'system' && !missing && (
            <button type="button" className="btn danger" onClick={() => void remove()}>
              Delete
            </button>
          )}
          <span className="spacer" />
          <button type="button" className="btn" onClick={close}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={busy || missing}>
            {editing ? 'Save changes' : title}
          </button>
        </footer>
      </form>
    </dialog>
  );
}
