// Edge geometry shared by the on-screen diagram and the SVG export, so both
// draw exactly the same lines.
import { NODE_H, NODE_W } from './layout';

export interface Point {
  x: number;
  y: number;
}

export interface EdgeGeometry {
  path: string;
  /** Where the line starts and ends, on the node borders. */
  a: Point;
  b: Point;
  /** Label position. */
  lx: number;
  ly: number;
  /** Labels wider than the gap between the two boxes would run over them. */
  labelMaxWidth: number;
}

/** The point on a node's border on the way from its centre towards (tx, ty). */
function toBorder(cx: number, cy: number, tx: number, ty: number): Point {
  const dx = tx - cx;
  const dy = ty - cy;
  if (!dx && !dy) return { x: cx, y: cy };
  const hw = NODE_W / 2 + 3;
  const hh = NODE_H / 2 + 3;
  const s = Math.min(dx ? hw / Math.abs(dx) : Infinity, dy ? hh / Math.abs(dy) : Infinity);
  return { x: cx + dx * s, y: cy + dy * s };
}

/** A straight line between two node centres, offset sideways for parallel flows. */
export function edgeGeometry(source: Point, target: Point, offset: number, selfLoop: boolean): EdgeGeometry {
  if (selfLoop) {
    const top = source.y - NODE_H / 2;
    const a = { x: source.x + 30, y: top };
    const b = { x: source.x - 30, y: top };
    return {
      path: `M ${a.x} ${a.y} C ${source.x + 40} ${top - 60}, ${source.x - 40} ${top - 60}, ${b.x} ${b.y}`,
      a,
      b,
      lx: source.x,
      ly: top - 52,
      labelMaxWidth: 220,
    };
  }
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const len = Math.hypot(dx, dy) || 1;
  const ox = (-dy / len) * offset;
  const oy = (dx / len) * offset;
  const a = toBorder(source.x + ox, source.y + oy, target.x + ox, target.y + oy);
  const b = toBorder(target.x + ox, target.y + oy, source.x + ox, source.y + oy);
  return {
    path: `M ${a.x} ${a.y} L ${b.x} ${b.y}`,
    a,
    b,
    lx: (a.x + b.x) / 2,
    ly: (a.y + b.y) / 2,
    labelMaxWidth: Math.abs(dx) > Math.abs(dy) ? Math.max(56, Math.min(220, Math.abs(b.x - a.x) - 10)) : 220,
  };
}

/**
 * What a flow label shows in the space it has: the full text if it fits in
 * two lines, else the first item and a count. The full text is always
 * available on hover and focus.
 */
export function shortLabel(carried: string[], fallback: string, maxWidth: number): string {
  const full = carried.join(', ') || fallback;
  // About 6.4 px per character at the label's 11.5 px font, minus padding.
  const perLine = Math.max(4, Math.floor((maxWidth - 16) / 6.4));
  if (fitsTwoLines(full, perLine)) return full;
  if (carried.length > 1) {
    const first = `${carried[0]} +${carried.length - 1}`;
    if (fitsTwoLines(first, perLine)) return first;
  }
  // Too tight for words: a count, with the full list on hover and focus.
  return carried.length ? `Data (${carried.length})` : full;
}

/** Whether text wraps into two lines at spaces, without breaking a word. */
function fitsTwoLines(text: string, perLine: number): boolean {
  let lines = 1;
  let used = 0;
  for (const word of text.split(/\s+/)) {
    if (word.length > perLine) return false;
    if (used && used + 1 + word.length > perLine) {
      lines++;
      used = word.length;
    } else used += (used ? 1 : 0) + word.length;
  }
  return lines <= 2;
}

/** Sideways offsets so flows between the same two components fan out. */
export function flowOffsets(flows: { id: string; from: string; to: string }[]): Map<string, number> {
  const key = (a: string, b: string) => [a, b].sort().join('\u0000');
  const groups = new Map<string, string[]>();
  for (const f of flows) groups.set(key(f.from, f.to), [...(groups.get(key(f.from, f.to)) ?? []), f.id]);
  const out = new Map<string, number>();
  for (const f of flows) {
    const g = groups.get(key(f.from, f.to))!;
    out.set(f.id, (g.indexOf(f.id) - (g.length - 1) / 2) * 26 * (f.from <= f.to ? 1 : -1));
  }
  return out;
}
