// Diagram geometry. Positions in the file's `layout` win; anything without
// one is placed automatically, but that placement is never written back
// until the user moves something.
import { Graph, layout as dagreLayout } from '@dagrejs/dagre';
import type { Model } from '../core/types';

export const NODE_W = 188;
export const NODE_H = 76;
export const ZONE_PAD = 24;
export const ZONE_HEADER = 34;
const EMPTY_ZONE_W = 240;
const EMPTY_ZONE_H = 140;
const STACK_GAP = 28;

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Placed extends Rect {
  /** True when the file has no position for it and it was placed automatically. */
  auto: boolean;
}

export interface DiagramLayout {
  components: Map<string, Placed>;
  zones: Map<string, Placed>;
}

const right = (r: Rect) => r.x + r.w;
const bottom = (r: Rect) => r.y + r.h;

function union(a: Rect | null, b: Rect): Rect {
  if (!a) return { ...b };
  const x = Math.min(a.x, b.x);
  const y = Math.min(a.y, b.y);
  return { x, y, w: Math.max(right(a), right(b)) - x, h: Math.max(bottom(a), bottom(b)) - y };
}

/** The zone a component is drawn inside, if that zone exists. */
export function zoneOf(m: Model, componentZone: string | undefined): string | undefined {
  return componentZone && (m.zones ?? []).some((z) => z.id === componentZone) ? componentZone : undefined;
}

function autoLayout(m: Model): Map<string, Rect> {
  const g = new Graph({ compound: true });
  g.setGraph({ rankdir: 'LR', nodesep: 70, ranksep: 120, marginx: 0, marginy: 0 });
  g.setDefaultEdgeLabel(() => ({}));
  const comps = m.components ?? [];
  const populated = new Set(comps.map((c) => zoneOf(m, c.zone)).filter((z): z is string => !!z));
  for (const z of m.zones ?? []) {
    g.setNode(z.id, populated.has(z.id) ? {} : { width: EMPTY_ZONE_W, height: EMPTY_ZONE_H });
  }
  for (const c of comps) {
    g.setNode(c.id, { width: NODE_W, height: NODE_H });
    const z = zoneOf(m, c.zone);
    if (z) g.setParent(c.id, z);
  }
  const ids = new Set(comps.map((c) => c.id));
  for (const f of m.flows ?? []) {
    if (f.from !== f.to && ids.has(f.from) && ids.has(f.to)) g.setEdge(f.from, f.to);
  }
  dagreLayout(g);
  const out = new Map<string, Rect>();
  for (const c of comps) {
    const n = g.node(c.id) as { x: number; y: number } | undefined;
    if (n) out.set(c.id, { x: n.x - NODE_W / 2, y: n.y - NODE_H / 2, w: NODE_W, h: NODE_H });
  }
  for (const z of m.zones ?? []) {
    const n = g.node(z.id) as { x: number; y: number } | undefined;
    if (n && !populated.has(z.id)) out.set(z.id, { x: n.x - EMPTY_ZONE_W / 2, y: n.y - EMPTY_ZONE_H / 2, w: EMPTY_ZONE_W, h: EMPTY_ZONE_H });
  }
  return out;
}

export function computeLayout(m: Model): DiagramLayout {
  const saved = m.layout ?? {};
  const comps = m.components ?? [];
  const zones = m.zones ?? [];
  const components = new Map<string, Placed>();

  let savedBox: Rect | null = null;
  for (const c of comps) {
    const l = saved[c.id];
    if (!l) continue;
    const r = { x: l.x, y: l.y, w: NODE_W, h: NODE_H };
    components.set(c.id, { ...r, auto: false });
    savedBox = union(savedBox, r);
  }
  const savedZoneRect = new Map<string, Rect>();
  for (const z of zones) {
    const l = saved[z.id];
    if (!l) continue;
    const r = { x: l.x, y: l.y, w: l.w ?? EMPTY_ZONE_W, h: l.h ?? EMPTY_ZONE_H };
    savedZoneRect.set(z.id, r);
    savedBox = union(savedBox, r);
  }

  const unplaced = comps.filter((c) => !saved[c.id]);
  const emptyZones = zones.filter((z) => !saved[z.id] && !comps.some((c) => zoneOf(m, c.zone) === z.id));
  const auto = unplaced.length || emptyZones.length ? autoLayout(m) : new Map<string, Rect>();

  // A new component in a zone that already has a position goes inside that
  // zone, below what's there, so an agent's additions land somewhere sensible.
  const toAuto: string[] = [];
  const stackY = new Map<string, number>();
  for (const c of unplaced) {
    const z = zoneOf(m, c.zone);
    const siblings = z ? comps.filter((s) => s.id !== c.id && zoneOf(m, s.zone) === z && saved[s.id]) : [];
    const zr = z ? savedZoneRect.get(z) : undefined;
    if (!z || (!siblings.length && !zr)) {
      toAuto.push(c.id);
      continue;
    }
    let x: number;
    let y = stackY.get(z) ?? -Infinity;
    if (siblings.length) {
      x = Math.min(...siblings.map((s) => saved[s.id]!.x));
      y = Math.max(y, ...siblings.map((s) => saved[s.id]!.y + NODE_H + STACK_GAP));
    } else {
      x = zr!.x + ZONE_PAD;
      y = Math.max(y, zr!.y + ZONE_HEADER);
    }
    components.set(c.id, { x, y, w: NODE_W, h: NODE_H, auto: true });
    stackY.set(z, y + NODE_H + STACK_GAP);
  }

  // Everything else uses the automatic layout, shifted to the right of what
  // the file already positions so the two never overlap.
  let autoBox: Rect | null = null;
  for (const id of [...toAuto, ...emptyZones.map((z) => z.id)]) {
    const r = auto.get(id);
    if (r) autoBox = union(autoBox, r);
  }
  const dx = savedBox && autoBox ? right(savedBox) + 120 - autoBox.x : 0;
  const dy = savedBox && autoBox ? savedBox.y - autoBox.y : 0;
  for (const id of toAuto) {
    const r = auto.get(id) ?? { x: 0, y: 0, w: NODE_W, h: NODE_H };
    components.set(id, { ...r, x: r.x + dx, y: r.y + dy, auto: true });
  }

  const zoneRects = new Map<string, Placed>();
  for (const z of zones) {
    let r: Rect | null = savedZoneRect.get(z.id) ?? null;
    for (const c of comps) {
      if (zoneOf(m, c.zone) !== z.id) continue;
      const p = components.get(c.id);
      if (!p) continue;
      r = union(r, { x: p.x - ZONE_PAD, y: p.y - ZONE_HEADER, w: p.w + 2 * ZONE_PAD, h: p.h + ZONE_HEADER + ZONE_PAD });
    }
    if (!r) {
      const a = auto.get(z.id) ?? { x: 0, y: 0, w: EMPTY_ZONE_W, h: EMPTY_ZONE_H };
      r = { ...a, x: a.x + dx, y: a.y + dy };
    }
    zoneRects.set(z.id, { ...r, auto: !saved[z.id] });
  }
  return { components, zones: zoneRects };
}

/** The innermost zone whose rectangle contains the point. */
export function zoneAt(zones: Map<string, Rect>, x: number, y: number, skip?: string): string | undefined {
  let best: string | undefined;
  let bestArea = Infinity;
  for (const [id, r] of zones) {
    if (id === skip) continue;
    if (x >= r.x && x <= right(r) && y >= r.y && y <= bottom(r) && r.w * r.h < bestArea) {
      best = id;
      bestArea = r.w * r.h;
    }
  }
  return best;
}
