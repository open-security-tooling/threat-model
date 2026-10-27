// Every main action, for the command palette (⌘K / Ctrl+K).
import { app, type Tab } from './app';
import { dialogs } from './dialogs';
import { theme } from './theme';
import { exports } from './exports';
import { canPickFiles, DownloadBackend, openFile, pickFile } from '../backend/local';
import * as L from './labels';
import { flowName } from './query';
import type { FormSection } from './forms';
import { lens } from './lens';

export interface Command {
  id: string;
  group: string;
  label: string;
  /** Extra words to match on, e.g. an item's ID. */
  keywords?: string;
  run: () => void;
}

async function openAFile() {
  if (app.dirty && app.backend && !app.backend.writesThrough && !confirm('Open another file? Changes not saved to a file are lost unless autosave is on.')) return;
  try {
    if (canPickFiles()) {
      const o = await pickFile();
      if (o) await app.open(o.source, o.backend);
      return;
    }
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.yaml,.yml,text/yaml';
    input.addEventListener('change', () => {
      const f = input.files?.[0];
      if (f) void openFile(f).then((o) => app.open(o.source, o.backend));
    });
    input.click();
  } catch (err) {
    app.setNotice({ kind: 'error', message: err instanceof Error ? err.message : String(err), diagnostics: [] });
  }
}

async function openExample() {
  const res = await fetch('examples/invoice-service.threatmodel.yaml');
  if (res.ok) await app.open(await res.text(), new DownloadBackend('threatmodel.yaml'));
}

export function commands(): Command[] {
  const out: Command[] = [];
  const add = (c: Command) => out.push(c);
  const v = app.view;

  add({ id: 'open', group: 'File', label: 'Open a file…', run: () => void openAFile() });
  if (!app.backend) {
    add({ id: 'example', group: 'File', label: 'Try the example', run: () => void openExample() });
  } else {
    if (!app.backend.writesThrough) add({ id: 'save', group: 'File', label: app.backend.savesInPlace ? 'Save' : 'Save…', keywords: 'write download', run: () => void app.save() });
    add({ id: 'close', group: 'File', label: 'Close model', run: () => (!app.dirty || app.backend?.writesThrough || confirm('Close this model? Changes not saved to a file are lost unless autosave is on.')) && app.close() });
  }

  if (app.backend) {
    const tabs: [Tab, string][] = [
      ['diagram', 'Diagram'],
      ['threats', 'Threats'],
      ['coverage', 'Coverage'],
      ['paths', 'Paths'],
      ...(lens.reviewer ? ([['register', 'Register']] as [Tab, string][]) : []),
      ['yaml', 'YAML'],
    ];
    for (const [t, label] of tabs) if (v || t === 'yaml') add({ id: `tab-${t}`, group: 'View', label: `Go to ${label}`, keywords: 'view tab switch', run: () => app.setTab(t) });
    if (v) {
      add({ id: 'paths', group: 'View', label: 'Show ways in for anyone on the internet', keywords: 'attack paths simulation run', run: () => app.setTab('paths') });
      if (app.suggestions.length) add({ id: 'suggestions', group: 'View', label: `Review ${app.suggestions.length} suggested threats`, keywords: 'suggestions library', run: () => app.select('suggestions', '') });
    }
    const first = app.diagnostics[0];
    if (first) add({ id: 'problems', group: 'View', label: `Go to the first of ${app.diagnostics.length} problems`, keywords: 'errors warnings diagnostics', run: () => (first.line ? app.revealLine(first.line) : app.setTab('yaml')) });
  }

  if (v) {
    const addables: [FormSection, string][] = [
      ['components', 'component'],
      ['flows', 'flow'],
      ['zones', 'zone'],
      ['data', 'data'],
      ['actors', 'actor'],
      ['identities', 'identity'],
      ['threats', 'threat'],
      ['mitigations', 'fix'],
    ];
    for (const [section, noun] of addables) add({ id: `add-${section}`, group: 'Add', label: `Add ${noun}`, keywords: 'new create', run: () => dialogs.openForm({ section }) });
    add({ id: 'edit-system', group: 'Add', label: 'Edit system name and description', run: () => dialogs.openForm({ section: 'system' }) });

    add({ id: 'export-yaml', group: 'Export', label: 'Export YAML file', keywords: 'download', run: () => void exports.yaml() });
    add({ id: 'export-md', group: 'Export', label: 'Export report (Markdown)', keywords: 'download', run: () => void exports.markdown() });
    add({ id: 'export-html', group: 'Export', label: 'Export report (HTML, printable)', keywords: 'download print', run: () => void exports.html() });
    add({ id: 'export-svg', group: 'Export', label: 'Export diagram (SVG)', keywords: 'download image', run: () => void exports.svg() });
    add({ id: 'export-png', group: 'Export', label: 'Export diagram (PNG)', keywords: 'download image', run: () => void exports.png() });
    add({ id: 'export-json', group: 'Export', label: 'Export JSON', keywords: 'download', run: () => void exports.json() });

    const m = v.model;
    for (const c of m.components ?? []) add({ id: `c-${c.id}`, group: 'Go to', label: c.name, keywords: `${c.id} component ${L.label(L.componentKinds, c.kind)}`, run: () => app.select('component', c.id) });
    for (const f of m.flows ?? []) add({ id: `f-${f.id}`, group: 'Go to', label: flowName(m, f), keywords: `${f.id} flow`, run: () => app.select('flow', f.id) });
    for (const z of m.zones ?? []) add({ id: `z-${z.id}`, group: 'Go to', label: z.name, keywords: `${z.id} zone`, run: () => app.select('zone', z.id) });
    for (const t of m.threats ?? []) add({ id: `t-${t.id}`, group: 'Go to', label: t.title, keywords: `${t.id} threat`, run: () => app.select('threat', t.id) });
    const forms: [FormSection, { id: string; name?: string; title?: string }[] | undefined, string][] = [
      ['mitigations', m.mitigations, 'fix'],
      ['data', m.data, 'data'],
      ['actors', m.actors, 'actor'],
      ['identities', m.identities, 'identity'],
    ];
    for (const [section, items, noun] of forms) {
      for (const i of items ?? []) add({ id: `${section}-${i.id}`, group: 'Go to', label: i.title ?? i.name ?? i.id, keywords: `${i.id} ${noun}`, run: () => dialogs.openForm({ section, id: i.id }) });
    }
  }

  add({ id: 'reviewer', group: 'Settings', label: lens.reviewer ? 'Turn the reviewer view off' : 'Turn the reviewer view on (for security teams)', keywords: 'security register sign-off lens', run: () => lens.setReviewer(!lens.reviewer) });
  add({ id: 'theme-light', group: 'Settings', label: 'Use the light theme', keywords: 'theme color', run: () => theme.set('light') });
  add({ id: 'theme-dark', group: 'Settings', label: 'Use the dark theme', keywords: 'theme color', run: () => theme.set('dark') });
  add({ id: 'theme-system', group: 'Settings', label: 'Match the system theme', keywords: 'theme color', run: () => theme.set('system') });
  if (app.backend && !app.backend.writesThrough) {
    add({ id: 'autosave', group: 'Settings', label: app.autosaveEnabled ? 'Turn autosave off' : 'Turn autosave on', keywords: 'storage browser', run: () => app.setAutosave(!app.autosaveEnabled) });
  }
  add({ id: 'clear', group: 'Settings', label: 'Clear data stored in this browser', keywords: 'autosave storage delete', run: () => void app.clearStored() });
  return out;
}

/** Every word typed must appear in the label or keywords. */
export function matches(c: Command, query: string): boolean {
  const hay = `${c.label} ${c.keywords ?? ''} ${c.group}`.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => hay.includes(w));
}
