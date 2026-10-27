import { app, type Tab } from '../lib/app';
import { useStore } from '../lib/store';
import { dialogs } from '../lib/dialogs';
import { theme, type ThemeChoice } from '../lib/theme';
import { exports } from '../lib/exports';
import { palette } from '../lib/palette';
import { lens } from '../lib/lens';
import { Menu, Popover } from './Menu';
import type { KeyboardEvent } from 'react';

const allTabs: [Tab, string][] = [
  ['diagram', 'Diagram'],
  ['threats', 'Threats'],
  ['coverage', 'Coverage'],
  ['paths', 'Paths'],
  ['register', 'Register'],
  ['yaml', 'YAML'],
];

/** The Register tab is part of the reviewer lens. */
export const visibleTabs = () => allTabs.filter(([t]) => t !== 'register' || lens.reviewer);

/** "N problems": jumps to the first one in the YAML view. */
function Problems() {
  const ds = app.diagnostics;
  if (!ds.length) return null;
  const errors = ds.filter((d) => d.severity === 'error').length;
  const first = ds.find((d) => d.severity === 'error') ?? ds[0]!;
  return (
    <button
      type="button"
      className={`btn problems-btn${errors ? ' has-errors' : ''}`}
      onClick={() => (first.line ? app.revealLine(first.line) : app.setTab('yaml'))}
      title={`${errors} errors, ${ds.length - errors} warnings. Go to the first one.`}
    >
      {ds.length} {ds.length === 1 ? 'problem' : 'problems'}
    </button>
  );
}

function Status() {
  const b = app.backend;
  if (!b) return null;
  if (b.writesThrough) {
    const s = app.watchStatus;
    const text = s === 'live' ? (app.dirty ? 'Writing to disk…' : 'Live: synced with the file on disk') : s === 'offline' ? 'Lost connection to threat serve, retrying…' : 'Connecting to threat serve…';
    return <span className={`status-pill${s === 'offline' ? ' warn' : ''}`}>{text}</span>;
  }
  const a = app.autosaveStatus;
  const text =
    a === 'off'
      ? 'Autosave off'
      : a === 'failed'
        ? 'Couldn’t autosave in this browser'
        : a === 'saved' && app.autosavedAt
          ? `Autosaved ${new Date(app.autosavedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
          : 'Autosaving…';
  return (
    <span className={`status-pill${a === 'failed' ? ' warn' : ''}`} title="A copy is kept only in this browser’s storage on this computer. Change it in Settings.">
      {text}
    </span>
  );
}

export function TopBar() {
  useStore(app);
  useStore(theme);
  useStore(lens);
  const tabs = visibleTabs();
  const name = app.view?.model.system.name ?? app.backend?.name ?? 'Threat model';
  const b = app.backend;

  const onTabKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex(([t]) => t === app.tab);
    const next = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : null;
    if (next === null) return;
    e.preventDefault();
    const [t] = tabs[(next + tabs.length) % tabs.length]!;
    app.setTab(t);
    document.getElementById(`tab-${t}`)?.focus();
  };

  return (
    <header className="topbar">
      <div className="topbar-title">
        <button type="button" className="model-name" onClick={() => app.view && dialogs.openForm({ section: 'system' })} title="Edit the system’s name and description">
          {name}
        </button>
        <span className="file-name">
          {b?.name}
          {app.dirty && !b?.writesThrough && (
            <span className="unsaved" title="Changes not saved to the file yet">
              {' '}
              · unsaved
            </span>
          )}
        </span>
      </div>
      <nav className="tabs" role="tablist" aria-label="Views" onKeyDown={onTabKey}>
        {tabs.map(([t, label]) => (
          <button
            key={t}
            id={`tab-${t}`}
            type="button"
            role="tab"
            aria-selected={app.tab === t}
            aria-controls="view"
            tabIndex={app.tab === t ? 0 : -1}
            disabled={!app.view && t !== 'yaml'}
            onClick={() => app.setTab(t)}
          >
            {label}
          </button>
        ))}
      </nav>
      <div className="topbar-actions">
        <Status />
        <Problems />
        <button type="button" className="btn" onClick={() => palette.open()} aria-keyshortcuts="Control+K Meta+K" title="All commands (Ctrl/⌘ K)">
          <span aria-hidden="true">⌘K</span>
          <span className="sr-only">Command palette</span>
        </button>
        {app.suggestions.length > 0 && (
          <button type="button" className="btn badge-btn" onClick={() => app.select('suggestions', '')}>
            {app.suggestions.length} {app.suggestions.length === 1 ? 'suggestion' : 'suggestions'}
          </button>
        )}
        <Menu
          label="Add"
          items={[
            { label: 'Component', onSelect: () => dialogs.openForm({ section: 'components' }) },
            { label: 'Flow', onSelect: () => dialogs.openForm({ section: 'flows' }) },
            { label: 'Zone', onSelect: () => dialogs.openForm({ section: 'zones' }) },
            { label: 'Data', onSelect: () => dialogs.openForm({ section: 'data' }) },
            { label: 'Actor', onSelect: () => dialogs.openForm({ section: 'actors' }) },
            { label: 'Identity', onSelect: () => dialogs.openForm({ section: 'identities' }) },
            { label: 'Threat', onSelect: () => dialogs.openForm({ section: 'threats' }) },
            { label: 'Fix', onSelect: () => dialogs.openForm({ section: 'mitigations' }) },
          ].map((i) => ({ ...i, disabled: !app.view }))}
        />
        {!b?.writesThrough && (
          <button type="button" className="btn primary" onClick={() => void app.save()} disabled={app.saving} title={b?.savesInPlace ? `Write back to ${b.name} (Ctrl/⌘ S)` : 'Download the file (Ctrl/⌘ S)'}>
            {b?.savesInPlace ? 'Save' : 'Save…'}
          </button>
        )}
        <Menu
          label="Export"
          items={[
            { label: 'YAML file', onSelect: () => void exports.yaml() },
            { label: 'Report (Markdown)', onSelect: () => void exports.markdown(), disabled: !app.view },
            { label: 'Report (HTML, printable)', onSelect: () => void exports.html(), disabled: !app.view },
            { label: 'Diagram (SVG)', onSelect: () => void exports.svg(), disabled: !app.view },
            { label: 'Diagram (PNG)', onSelect: () => void exports.png(), disabled: !app.view },
            { label: 'JSON (model, risks and coverage)', onSelect: () => void exports.json(), disabled: !app.view },
          ]}
        />
        <Popover label="⚙" ariaLabel="Settings">
          <fieldset className="setting">
            <legend>Theme</legend>
            {(['system', 'light', 'dark'] as ThemeChoice[]).map((c) => (
              <label key={c} className="check">
                <input type="radio" name="theme" checked={theme.choice === c} onChange={() => theme.set(c)} />
                <span>{c === 'system' ? 'Match the system' : c === 'light' ? 'Light' : 'Dark'}</span>
              </label>
            ))}
          </fieldset>
          <fieldset className="setting">
            <legend>View</legend>
            <label className="check">
              <input type="checkbox" name="reviewer" checked={lens.reviewer} onChange={(e) => lens.setReviewer(e.target.checked)} />
              <span>Reviewer view, for security teams</span>
            </label>
            <p className="help">Adds a risk register, sign-off, and more detail on every threat. Kept in this browser only; nothing is written to the file.</p>
          </fieldset>
          <fieldset className="setting">
            <legend>Browser storage</legend>
            <label className="check">
              <input type="checkbox" name="autosave" checked={app.autosaveEnabled} onChange={(e) => app.setAutosave(e.target.checked)} disabled={b?.writesThrough} />
              <span>Autosave a copy in this browser</span>
            </label>
            <p className="help">
              {b?.writesThrough
                ? 'With threat serve, the file on disk is the copy; nothing is kept in the browser.'
                : 'The copy stays in this browser (IndexedDB) on this computer and is never sent anywhere. Turning autosave off deletes it.'}
            </p>
            <button type="button" className="btn small" onClick={() => void app.clearStored()}>
              Clear data stored in this browser
            </button>
          </fieldset>
          {!b?.writesThrough && (
            <button
              type="button"
              className="btn small"
              onClick={() => {
                if (!app.dirty || confirm('Close this model? Changes not saved to a file are lost unless autosave is on.')) app.close();
              }}
            >
              Close model
            </button>
          )}
        </Popover>
      </div>
    </header>
  );
}
