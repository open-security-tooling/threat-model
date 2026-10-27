// Read-only lookups over the model returned by `show`.
import type { Assessment, Flow, Model, Threat, View } from '../core/types';
import { capitalize, riskRank } from './labels';

export function componentName(m: Model, id: string): string {
  return m.components?.find((c) => c.id === id)?.name ?? id;
}

export function flowName(m: Model, f: Flow): string {
  return `${componentName(m, f.from)} → ${componentName(m, f.to)}`;
}

/** Name of anything a threat can affect: a component or a flow. */
export function targetName(m: Model, id: string): string {
  const c = m.components?.find((x) => x.id === id);
  if (c) return c.name;
  const f = m.flows?.find((x) => x.id === id);
  return f ? flowName(m, f) : id;
}

export function dataName(m: Model, id: string): string {
  return m.data?.find((d) => d.id === id)?.name ?? id;
}

export function threatsAffecting(m: Model, id: string): Threat[] {
  return (m.threats ?? []).filter((t) => t.affects?.includes(id));
}

/** Sort key for a threat: dismissed ones last, then by residual risk. */
export function riskOrder(t: Threat, a: Assessment | undefined): number {
  if (t.status === 'not-applicable') return -2;
  if (!a?.level) return -1;
  return riskRank(a.level);
}

export function byRisk(view: View, threats: Threat[]): Threat[] {
  return [...threats].sort((x, y) => riskOrder(y, view.risks[y.id]) - riskOrder(x, view.risks[x.id]));
}

/** CSS class suffix for a threat's dot/badge. */
export function riskClass(t: Threat, a: Assessment | undefined): string {
  if (t.status === 'not-applicable') return 'na';
  return a?.level ?? 'none';
}

export function isExpired(until: string | undefined): boolean {
  if (!until) return false;
  const today = new Date().toISOString().slice(0, 10);
  return until < today;
}

/** A threat as a dot on the diagram. */
export interface Dot {
  id: string;
  title: string;
  cls: string;
  level: string;
  status: string;
}

export function dotsFor(view: View, id: string): Dot[] {
  return byRisk(view, threatsAffecting(view.model, id)).map((t) => {
    const a = view.risks[t.id];
    const cls = riskClass(t, a);
    return {
      id: t.id,
      title: t.title,
      cls,
      level: cls === 'na' ? "Doesn't apply" : a?.level ? capitalize(a.level) : 'Not assessed',
      status: t.status,
    };
  });
}

const today = () => new Date().toISOString().slice(0, 10);

/** A fix that isn't done and whose due date has passed. */
export function isOverdue(m: { due?: string; status: string }): boolean {
  return !!m.due && m.status !== 'done' && m.due < today();
}

/** "Encrypted (HTTPS)", "Not encrypted" or "Not said", from show's transit. */
export function transitLabel(view: View, f: Flow): string {
  const t = view.transit?.[f.id] ?? 'unknown';
  if (t === 'unencrypted') return 'Not encrypted';
  if (t === 'unknown') return 'Not said';
  if (f.encrypted === true) return 'Encrypted';
  // Inferred by the core from the transport or mutual TLS.
  return f.auth === 'mtls' ? 'Encrypted (mutual TLS)' : `Encrypted (${f.over ?? 'TLS'})`;
}
