// Form definitions for adding and editing items. Forms produce upsert
// patches: only changed fields are sent, and a cleared field is sent as null
// so the core removes it.
import type { Effect, Evidence, Fields, Model, Permission, Refs, Section } from '../core/types';
import * as L from './labels';
import type { Option } from './labels';
import { flowName } from './query';

export type FieldKind = 'text' | 'textarea' | 'select' | 'refs' | 'lines' | 'csv' | 'date' | 'effect' | 'evidence' | 'refmap' | 'tristate' | 'perms' | 'reviewed';

export interface FieldSpec {
  name: string;
  label: string;
  kind: FieldKind;
  required?: boolean;
  help?: string;
  placeholder?: string;
  options?: (m: Model) => Option[];
  /** Shown in a collapsed "More" group. */
  advanced?: boolean;
}

export type FormSection = Section | 'system';

export interface FormSpec {
  section: FormSection;
  noun: string;
  /** The field the ID is suggested from. */
  nameField: string;
  fields: FieldSpec[];
}

export interface EffectValue {
  mode: '' | 'eliminates' | 'detects' | 'change';
  who: string;
  effort: string;
  impact: string;
}

/** A tri-state answer: '' means "don't know" and is sent as null. */
export type TriState = '' | 'yes' | 'no';

export interface PermRow {
  do: string;
  on: string;
}

export interface ReviewedValue {
  on: string;
  by: string;
}

export type FormValue = string | string[] | EffectValue | PermRow[] | ReviewedValue;
export type FormValues = Record<string, FormValue>;

const fixed = (o: Option[]) => () => o;
const componentOptions = (m: Model): Option[] => (m.components ?? []).map((c) => ({ value: c.id, label: c.name }));
const zoneOptions = (m: Model): Option[] => (m.zones ?? []).map((z) => ({ value: z.id, label: z.name }));
const dataOptions = (m: Model): Option[] => (m.data ?? []).map((d) => ({ value: d.id, label: d.name, hint: d.sensitivity }));
const identityOptions = (m: Model): Option[] => (m.identities ?? []).map((i) => ({ value: i.id, label: i.name, hint: L.label(L.identityKinds, i.kind) }));
/** What a permission can be on: a component or data. */
export const permissionTargets = (m: Model): Option[] => [
  ...componentOptions(m),
  ...(m.data ?? []).map((d) => ({ value: d.id, label: d.name, hint: 'data' })),
];
const mitigationOptions = (m: Model): Option[] => (m.mitigations ?? []).map((x) => ({ value: x.id, label: x.title }));
const targetOptions = (m: Model): Option[] => [
  ...componentOptions(m),
  ...(m.flows ?? []).map((f) => ({ value: f.id, label: flowName(m, f), hint: 'flow' })),
];

export const specs: Record<FormSection, FormSpec> = {
  system: {
    section: 'system',
    noun: 'system',
    nameField: 'name',
    fields: [
      { name: 'name', label: 'What are you building?', kind: 'text', required: true },
      { name: 'description', label: 'Description', kind: 'textarea' },
      { name: 'owners', label: 'Owners', kind: 'csv', help: 'Who maintains this model, e.g. @org/team. Separate with commas.' },
      { name: 'links', label: 'Links', kind: 'lines', help: 'One per line.' },
    ],
  },
  components: {
    section: 'components',
    noun: 'component',
    nameField: 'name',
    fields: [
      { name: 'name', label: 'Name', kind: 'text', required: true, placeholder: 'Invoice API' },
      { name: 'kind', label: 'What is it?', kind: 'select', required: true, options: fixed(L.componentKinds) },
      { name: 'zone', label: 'Zone', kind: 'select', options: zoneOptions, help: 'Which group of things that trust each other it lives in.' },
      { name: 'exposure', label: 'Who can reach it?', kind: 'select', options: fixed(L.exposures) },
      { name: 'stores', label: 'Data it keeps', kind: 'refs', options: dataOptions },
      { name: 'identity', label: 'Runs as', kind: 'select', options: identityOptions, help: 'The service account, role or key it uses. Its permissions are what an attacker gets if they take it over.' },
      { name: 'encrypted_at_rest', label: 'Is the data it keeps encrypted on disk?', kind: 'tristate' },
      { name: 'monitored', label: 'Are security events logged and alerted on?', kind: 'tristate' },
      { name: 'patching', label: 'How does it get updates?', kind: 'select', options: fixed(L.patching) },
      { name: 'managed', label: 'Managed service (the provider patches it)?', kind: 'tristate' },
      { name: 'tech', label: 'Tech', kind: 'csv', placeholder: 'go, postgres', advanced: true },
      { name: 'code', label: 'Code paths', kind: 'lines', help: 'Paths or globs, one per line.', advanced: true },
      { name: 'reviewed', label: 'Last reviewed', kind: 'reviewed', advanced: true },
      { name: 'notes', label: 'Notes', kind: 'textarea', advanced: true },
    ],
  },
  flows: {
    section: 'flows',
    noun: 'flow',
    nameField: 'from',
    fields: [
      { name: 'from', label: 'From', kind: 'select', required: true, options: componentOptions },
      { name: 'to', label: 'To', kind: 'select', required: true, options: componentOptions },
      { name: 'carries', label: 'What it carries', kind: 'refs', options: dataOptions },
      { name: 'over', label: 'Over', kind: 'text', placeholder: 'HTTPS' },
      { name: 'auth', label: 'How the caller proves who it is', kind: 'select', options: fixed(L.flowAuths) },
      { name: 'encrypted', label: 'Is it encrypted in transit (e.g. TLS)?', kind: 'tristate' },
      { name: 'notes', label: 'Notes', kind: 'textarea', advanced: true },
    ],
  },
  data: {
    section: 'data',
    noun: 'data',
    nameField: 'name',
    fields: [
      { name: 'name', label: 'Name', kind: 'text', required: true, placeholder: 'Customer invoices' },
      { name: 'sensitivity', label: 'How sensitive is it?', kind: 'select', required: true, options: fixed(L.sensitivities) },
      { name: 'description', label: 'Description', kind: 'textarea' },
    ],
  },
  zones: {
    section: 'zones',
    noun: 'zone',
    nameField: 'name',
    fields: [
      { name: 'name', label: 'Name', kind: 'text', required: true, placeholder: 'Production AWS account' },
      { name: 'trust', label: 'How much do you trust it?', kind: 'select', required: true, options: fixed(L.trusts) },
      { name: 'network', label: 'Inside the zone', kind: 'select', options: fixed(L.networks), help: 'Not set means a flat network.' },
      { name: 'egress', label: 'Outbound internet access', kind: 'select', options: fixed(L.egress), help: 'Not set means open.' },
    ],
  },
  identities: {
    section: 'identities',
    noun: 'identity',
    nameField: 'name',
    fields: [
      { name: 'name', label: 'Name', kind: 'text', required: true, placeholder: 'Invoice API task role' },
      { name: 'kind', label: 'What is it?', kind: 'select', required: true, options: fixed(L.identityKinds) },
      { name: 'can', label: 'What it’s allowed to do', kind: 'perms', help: 'Everything here is what someone gets if they take over a component that runs as it.' },
      { name: 'notes', label: 'Notes', kind: 'textarea', advanced: true },
    ],
  },
  actors: {
    section: 'actors',
    noun: 'actor',
    nameField: 'name',
    fields: [
      { name: 'name', label: 'Name', kind: 'text', required: true, placeholder: 'Customer' },
      { name: 'access', label: 'What access do they have?', kind: 'select', options: fixed(L.who) },
    ],
  },
  threats: {
    section: 'threats',
    noun: 'threat',
    nameField: 'title',
    fields: [
      {
        name: 'title',
        label: 'What could someone do?',
        kind: 'textarea',
        required: true,
        help: 'Who could do what, by how.',
        placeholder: "A logged-in customer could read other customers' invoices by changing the ID in the URL",
      },
      { name: 'kind', label: 'Kind', kind: 'select', options: fixed(L.threatKinds) },
      { name: 'affects', label: 'Where', kind: 'refs', options: targetOptions },
      { name: 'attack', label: 'How it works', kind: 'lines', help: 'The attack as a few concrete steps, one per line.' },
      { name: 'who', label: 'Who could do it?', kind: 'select', options: fixed(L.who) },
      { name: 'effort', label: 'How hard is it?', kind: 'select', options: fixed(L.efforts) },
      { name: 'impact', label: 'How bad is it?', kind: 'select', options: fixed(L.impacts) },
      { name: 'impact_note', label: 'What specifically breaks?', kind: 'text' },
      { name: 'mitigations', label: 'Fixes', kind: 'refs', options: mitigationOptions },
      { name: 'refs', label: 'Security mappings', kind: 'refmap', help: 'One scheme per line, e.g. "cwe: CWE-639".', advanced: true },
    ],
  },
  mitigations: {
    section: 'mitigations',
    noun: 'fix',
    nameField: 'title',
    fields: [
      {
        name: 'title',
        label: 'What will you change?',
        kind: 'textarea',
        required: true,
        placeholder: "Check the invoice belongs to the caller's account before returning it",
      },
      { name: 'status', label: 'Status', kind: 'select', required: true, options: fixed(L.mitigationStatuses) },
      { name: 'effect', label: 'What does it change?', kind: 'effect' },
      { name: 'owner', label: 'Owner', kind: 'text', placeholder: '@someone' },
      { name: 'due', label: 'Due by', kind: 'date' },
      { name: 'evidence', label: 'Evidence', kind: 'evidence', help: 'Where it lives, one per line: "code: path#Symbol", "test: ..." or "link: https://...".', advanced: true },
      { name: 'notes', label: 'Notes', kind: 'textarea', advanced: true },
    ],
  },
};

const splitLines = (s: string) => s.split('\n').map((l) => l.trim()).filter(Boolean);
const splitCsv = (s: string) => s.split(',').map((l) => l.trim()).filter(Boolean);

function effectToValue(e: Effect | undefined): EffectValue {
  if (e === 'eliminates' || e === 'detects') return { mode: e, who: '', effort: '', impact: '' };
  if (e && typeof e === 'object') return { mode: 'change', who: e.who ?? '', effort: e.effort ?? '', impact: e.impact ?? '' };
  return { mode: '', who: '', effort: '', impact: '' };
}

/** Form values for an existing item (or defaults for a new one). */
export function toValues(spec: FormSpec, item: Record<string, unknown> | undefined): FormValues {
  const out: FormValues = {};
  for (const f of spec.fields) {
    const v = item?.[f.name];
    switch (f.kind) {
      case 'refs':
        out[f.name] = Array.isArray(v) ? (v as string[]) : [];
        break;
      case 'lines':
        out[f.name] = Array.isArray(v) ? (v as string[]).join('\n') : '';
        break;
      case 'csv':
        out[f.name] = Array.isArray(v) ? (v as string[]).join(', ') : '';
        break;
      case 'evidence':
        out[f.name] = Array.isArray(v) ? (v as Evidence[]).map((e) => `${e.type}: ${e.target}`).join('\n') : '';
        break;
      case 'refmap':
        out[f.name] = v && typeof v === 'object' ? Object.entries(v as Refs).map(([k, ids]) => `${k}: ${ids.join(', ')}`).join('\n') : '';
        break;
      case 'effect':
        out[f.name] = effectToValue(v as Effect | undefined);
        break;
      case 'tristate':
        out[f.name] = v === true ? 'yes' : v === false ? 'no' : '';
        break;
      case 'perms':
        out[f.name] = Array.isArray(v) ? (v as Permission[]).map((p) => ({ do: p.do, on: p.on })) : [];
        break;
      case 'reviewed':
        // The model gives the date in `reviewed` and the person in `reviewed_by`.
        out[f.name] = { on: typeof v === 'string' ? v : '', by: typeof item?.reviewed_by === 'string' ? item.reviewed_by : '' };
        break;
      default:
        out[f.name] = typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
    }
  }
  return out;
}

export class FormError extends Error {}

/** Converts one field's form value to what goes in the file, or null for "not set". */
function toFileValue(f: FieldSpec, v: FormValue): unknown {
  switch (f.kind) {
    case 'refs': {
      const a = v as string[];
      return a.length ? a : null;
    }
    case 'lines': {
      const a = splitLines(v as string);
      return a.length ? a : null;
    }
    case 'csv': {
      const a = splitCsv(v as string);
      return a.length ? a : null;
    }
    case 'evidence': {
      const out: Record<string, string>[] = [];
      for (const line of splitLines(v as string)) {
        const m = /^(code|test|link)\s*:\s*(.+)$/.exec(line);
        if (!m) throw new FormError(`Evidence "${line}" should start with code:, test: or link:.`);
        out.push({ [m[1]!]: m[2]!.trim() });
      }
      return out.length ? out : null;
    }
    case 'refmap': {
      const out: Record<string, string[]> = {};
      for (const line of splitLines(v as string)) {
        const i = line.indexOf(':');
        if (i <= 0) throw new FormError(`Mapping "${line}" should look like "cwe: CWE-639".`);
        const ids = splitCsv(line.slice(i + 1));
        if (ids.length) out[line.slice(0, i).trim()] = ids;
      }
      return Object.keys(out).length ? out : null;
    }
    case 'tristate':
      return v === 'yes' ? true : v === 'no' ? false : null;
    case 'reviewed': {
      const r = v as ReviewedValue;
      if (!r.on) {
        if (r.by.trim()) throw new FormError('Say when it was reviewed, as well as by whom.');
        return null;
      }
      // The file takes `reviewed: date` or `reviewed: {on, by}`.
      return r.by.trim() ? { on: r.on, by: r.by.trim() } : r.on;
    }
    case 'perms': {
      const rows = (v as PermRow[]).filter((r) => r.do || r.on);
      if (rows.some((r) => !r.do || !r.on)) throw new FormError('Each permission needs both what it can do and what it’s on.');
      return rows.length ? rows.map((r) => ({ do: r.do, on: r.on })) : null;
    }
    case 'effect': {
      const e = v as EffectValue;
      if (e.mode === 'eliminates' || e.mode === 'detects') return e.mode;
      if (e.mode === 'change') {
        const m: Record<string, string> = {};
        if (e.who) m.who = e.who;
        if (e.effort) m.effort = e.effort;
        if (e.impact) m.impact = e.impact;
        if (!Object.keys(m).length) throw new FormError('Pick at least one thing the fix changes: who, how hard, or how bad.');
        return m;
      }
      return null;
    }
    default: {
      const s = (v as string).trim();
      return s === '' ? null : s;
    }
  }
}

/**
 * The upsert patch for these values: on create every set field, on edit only
 * the fields that changed (null where a field was cleared).
 */
export function toPatch(spec: FormSpec, values: FormValues, original: FormValues | null): Fields {
  const fields: Fields = {};
  for (const f of spec.fields) {
    const v = values[f.name];
    if (v === undefined) continue;
    const next = toFileValue(f, v);
    if (f.required && next === null) throw new FormError(`${f.label.replace(/\?$/, '')} is required.`);
    if (original) {
      const before = original[f.name] === undefined ? null : toFileValue(f, original[f.name]!);
      if (JSON.stringify(before) === JSON.stringify(next)) continue;
      fields[f.name] = next;
    } else if (next !== null) {
      fields[f.name] = next;
    }
  }
  return fields;
}
