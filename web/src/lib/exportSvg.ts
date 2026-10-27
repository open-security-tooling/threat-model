// Draws the diagram as a standalone SVG from the model and its layout (the
// same geometry as the screen). Paint order matches the screen: zone areas,
// then arrows, then zone titles, components and flow labels, so no arrow is
// ever drawn over text. Every piece of model text is XML-escaped.
import type { View } from '../core/types';
import { computeLayout, NODE_H, NODE_W } from './layout';
import { edgeGeometry, flowOffsets, shortLabel } from './geometry';
import * as L from './labels';
import { dataName, dotsFor } from './query';

export interface Palette {
  bg: string;
  surface: string;
  surface2: string;
  border: string;
  borderStrong: string;
  text: string;
  muted: string;
  edge: string;
  edgeCrossing: string;
  zone: Record<string, { line: string; fill: string }>;
  risk: Record<string, { bg: string; fg: string; border?: string }>;
  warn: { bg: string; fg: string; border: string };
}

// Mirrors the tokens in app.css.
export const palettes: Record<'light' | 'dark', Palette> = {
  light: {
    bg: '#f5f6f8',
    surface: '#ffffff',
    surface2: '#eceff3',
    border: '#c9ced6',
    borderStrong: '#7d8794',
    text: '#1b1f24',
    muted: '#4d5764',
    edge: '#5b6573',
    edgeCrossing: '#1b1f24',
    zone: {
      untrusted: { line: '#b3261e', fill: 'rgba(198,40,40,0.05)' },
      partial: { line: '#8f5600', fill: 'rgba(178,106,0,0.06)' },
      trusted: { line: '#0b5cd5', fill: 'rgba(11,92,213,0.05)' },
    },
    risk: {
      critical: { bg: '#a50e0e', fg: '#ffffff' },
      high: { bg: '#c2410c', fg: '#ffffff' },
      medium: { bg: '#f9b81b', fg: '#1b1f24', border: '#8a6100' },
      low: { bg: '#2e7d32', fg: '#ffffff' },
      none: { bg: '#646c78', fg: '#ffffff' },
      na: { bg: '#ffffff', fg: '#4d5764', border: '#7d8794' },
    },
    warn: { bg: '#fff5d9', fg: '#5c4300', border: '#e6c56c' },
  },
  dark: {
    bg: '#121519',
    surface: '#1b1f25',
    surface2: '#262b33',
    border: '#3b424d',
    borderStrong: '#7a8594',
    text: '#e7eaee',
    muted: '#aab3bf',
    edge: '#9aa4b2',
    edgeCrossing: '#e7eaee',
    zone: {
      untrusted: { line: '#f28b82', fill: 'rgba(242,139,130,0.06)' },
      partial: { line: '#e0b050', fill: 'rgba(224,176,80,0.06)' },
      trusted: { line: '#7aaeff', fill: 'rgba(122,174,255,0.06)' },
    },
    risk: {
      critical: { bg: '#ff6b6b', fg: '#14171b' },
      high: { bg: '#ff9a4d', fg: '#14171b' },
      medium: { bg: '#ffcb45', fg: '#14171b', border: '#ffcb45' },
      low: { bg: '#6cc070', fg: '#14171b' },
      none: { bg: '#a0a8b4', fg: '#14171b' },
      na: { bg: '#1b1f25', fg: '#aab3bf', border: '#7a8594' },
    },
    warn: { bg: '#352a0c', fg: '#f5d77a', border: '#6d5713' },
  },
};

const FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";

export function xmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]!);
}

let ctx: CanvasRenderingContext2D | null = null;
function measure(text: string, size: number, weight = 400): number {
  ctx ??= document.createElement('canvas').getContext('2d');
  if (!ctx) return text.length * size * 0.55;
  ctx.font = `${weight} ${size}px ${FONT}`;
  return ctx.measureText(text).width;
}

/** Cuts text to fit a width, ending in an ellipsis. */
function fit(text: string, max: number, size: number, weight = 400): string {
  if (measure(text, size, weight) <= max) return text;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measure(text.slice(0, mid) + '…', size, weight) <= max) lo = mid;
    else hi = mid - 1;
  }
  return text.slice(0, lo) + '…';
}

const letters: Record<string, string> = { critical: 'C', high: 'H', medium: 'M', low: 'L', na: '–' };

export function diagramSvg(view: View, p: Palette): { svg: string; width: number; height: number } {
  const m = view.model;
  const placed = computeLayout(m);
  const parts: string[] = [];
  const t = (x: number, y: number, s: string, size: number, fill: string, weight = 400, anchor = 'start') =>
    `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" font-size="${size}" font-weight="${weight}" fill="${fill}" text-anchor="${anchor}" dominant-baseline="central">${xmlEscape(s)}</text>`;
  const dots = (x: number, y: number, list: ReturnType<typeof dotsFor>, max: number) => {
    const out: string[] = [];
    list.slice(0, max).forEach((d, i) => {
      const c = p.risk[d.cls] ?? p.risk.none!;
      const cx = x + 9 + i * 21;
      out.push(`<circle cx="${cx}" cy="${y}" r="9" fill="${c.bg}" stroke="${c.border ?? c.bg}"/>`);
      out.push(t(cx, y + 0.5, letters[d.cls] ?? '?', 10, c.fg, 700, 'middle'));
    });
    return { svg: out.join(''), width: Math.min(list.length, max) * 21 };
  };

  // Zone areas
  const zoneLayer: string[] = [];
  const titleLayer: string[] = [];
  for (const z of m.zones ?? []) {
    const r = placed.zones.get(z.id);
    if (!r) continue;
    const c = p.zone[z.trust] ?? { line: p.borderStrong, fill: 'none' };
    const dash = z.trust === 'trusted' ? '' : ' stroke-dasharray="6 4"';
    zoneLayer.push(`<rect x="${r.x}" y="${r.y}" width="${r.w}" height="${r.h}" rx="12" fill="${c.fill}" stroke="${c.line}" stroke-width="2"${dash}/>`);
    if (z.network === 'segmented') zoneLayer.push(`<rect x="${r.x + 7}" y="${r.y + 7}" width="${r.w - 14}" height="${r.h - 14}" rx="8" fill="none" stroke="${c.line}" stroke-width="2"/>`);
    // Title on an opaque plate, above the arrows.
    const tags = [L.label(L.trusts, z.trust), z.network === 'segmented' ? 'segmented' : '', z.egress === 'restricted' ? 'egress restricted' : ''].filter(Boolean).join(' · ');
    const name = fit(z.name, r.w - 40, 13, 700);
    const nameW = measure(name, 13, 700);
    const tagText = fit(tags, Math.max(0, r.w - nameW - 40), 11.5);
    const w = Math.min(r.w - 4, nameW + (tagText ? measure(tagText, 11.5) + 8 : 0) + 20);
    titleLayer.push(`<rect x="${r.x + 2}" y="${r.y + 2}" width="${w}" height="26" rx="8" fill="${p.surface}"/>`);
    titleLayer.push(t(r.x + 12, r.y + 15, name, 13, p.text, 700));
    if (tagText) titleLayer.push(t(r.x + 20 + nameW, r.y + 15, tagText, 11.5, p.muted));
  }

  // Arrows
  const ids = new Set((m.components ?? []).map((c) => c.id));
  const flows = (m.flows ?? []).filter((f) => ids.has(f.from) && ids.has(f.to));
  const offsets = flowOffsets(flows);
  const crossings = new Set(view.crossings);
  const edgeLayer: string[] = [];
  const labelLayer: string[] = [];
  const center = (id: string) => {
    const r = placed.components.get(id)!;
    return { x: r.x + NODE_W / 2, y: r.y + NODE_H / 2 };
  };
  for (const f of flows) {
    const g = edgeGeometry(center(f.from), center(f.to), offsets.get(f.id) ?? 0, f.from === f.to);
    const crossing = crossings.has(f.id);
    edgeLayer.push(
      `<path d="${g.path}" fill="none" stroke="${crossing ? p.edgeCrossing : p.edge}" stroke-width="${crossing ? 3.5 : 1.5}" marker-end="url(#${crossing ? 'arrow-x' : 'arrow'})"/>`,
    );
    const carriedList = (f.carries ?? []).map((d) => dataName(m, d));
    const flowDots = dotsFor(view, f.id);
    const unenc = view.transit?.[f.id] === 'unencrypted';
    if (!carriedList.length && !f.over && !flowDots.length && !unenc) continue;
    const tagW = unenc ? measure('unencrypted', 10.5, 600) + 12 : 0;
    const dotsW = Math.min(flowDots.length, 4) * 21;
    const textMax = Math.max(24, g.labelMaxWidth - tagW - dotsW - 16);
    const carried = carriedList.length || f.over ? shortLabel(carriedList, f.over ?? '', textMax + 16) : '';
    const text = carried ? fit(carried, textMax, 11.5, 500) : '';
    const textW = text ? measure(text, 11.5, 500) + 12 : 0;
    const gap = 4;
    const total = tagW + textW + dotsW + gap * ([tagW, textW, dotsW].filter(Boolean).length - 1) + 4;
    let x = g.lx - total / 2;
    const y = g.ly;
    labelLayer.push(`<rect x="${x}" y="${y - 12}" width="${total}" height="24" rx="6" fill="${p.surface}"/>`);
    x += 2;
    if (unenc) {
      labelLayer.push(`<rect x="${x}" y="${y - 9}" width="${tagW}" height="18" rx="4" fill="${p.warn.bg}" stroke="${p.warn.border}"/>`);
      labelLayer.push(t(x + tagW / 2, y, 'unencrypted', 10.5, p.warn.fg, 600, 'middle'));
      x += tagW + gap;
    }
    if (text) {
      labelLayer.push(`<rect x="${x}" y="${y - 9}" width="${textW}" height="18" rx="4" fill="${p.surface}" stroke="${p.border}"/>`);
      labelLayer.push(t(x + 6, y, text, 11.5, p.text, 500));
      x += textW + gap;
    }
    if (flowDots.length) labelLayer.push(dots(x, y, flowDots, 4).svg);
  }

  // Components
  const compLayer: string[] = [];
  for (const c of m.components ?? []) {
    const r = placed.components.get(c.id);
    if (!r) continue;
    compLayer.push(`<rect x="${r.x}" y="${r.y}" width="${NODE_W}" height="${NODE_H}" rx="8" fill="${p.surface}" stroke="${p.borderStrong}" stroke-width="1.5"/>`);
    compLayer.push(t(r.x + 12, r.y + 18, fit(c.name, NODE_W - 24, 13, 600), 13, p.text, 600));
    const kind = L.label(L.componentKinds, c.kind) + (c.exposure === 'internet' ? ' · internet' : '');
    compLayer.push(t(r.x + 12, r.y + 35, fit(kind, NODE_W - 24, 11.5), 11.5, p.muted));
    const d = dotsFor(view, c.id);
    if (d.length) compLayer.push(dots(r.x + 10, r.y + NODE_H - 16, d, 7).svg);
  }

  // Bounds: everything placed, plus a margin.
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const r of [...placed.zones.values(), ...placed.components.values()]) {
    minX = Math.min(minX, r.x);
    minY = Math.min(minY, r.y);
    maxX = Math.max(maxX, r.x + r.w);
    maxY = Math.max(maxY, r.y + r.h);
  }
  if (!isFinite(minX)) [minX, minY, maxX, maxY] = [0, 0, 400, 200];
  const pad = 70;
  const vx = minX - pad;
  const vy = minY - pad;
  const width = Math.ceil(maxX - minX + 2 * pad);
  const height = Math.ceil(maxY - minY + 2 * pad);

  parts.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vx} ${vy} ${width} ${height}" width="${width}" height="${height}" font-family="${xmlEscape(FONT)}">`,
    `<title>${xmlEscape(m.system.name)}</title>`,
    `<defs>`,
    `<marker id="arrow" viewBox="-10 -10 20 20" markerWidth="16" markerHeight="16" markerUnits="userSpaceOnUse" orient="auto-start-reverse" refX="0" refY="0"><polyline points="-5,-4 0,0 -5,4 -5,-4" fill="${p.edge}" stroke="${p.edge}" stroke-width="1"/></marker>`,
    `<marker id="arrow-x" viewBox="-10 -10 20 20" markerWidth="22" markerHeight="22" markerUnits="userSpaceOnUse" orient="auto-start-reverse" refX="0" refY="0"><polyline points="-5,-4 0,0 -5,4 -5,-4" fill="${p.edgeCrossing}" stroke="${p.edgeCrossing}" stroke-width="1"/></marker>`,
    `</defs>`,
    `<rect x="${vx}" y="${vy}" width="${width}" height="${height}" fill="${p.bg}"/>`,
    `<g>${zoneLayer.join('')}</g>`,
    `<g>${edgeLayer.join('')}</g>`,
    `<g>${titleLayer.join('')}</g>`,
    `<g>${compLayer.join('')}</g>`,
    `<g>${labelLayer.join('')}</g>`,
    `</svg>`,
  );
  return { svg: parts.join('\n'), width, height };
}

/** Rasterises the SVG. The image comes from a same-origin blob, so the canvas isn't tainted. */
export async function svgToPng(svg: string, width: number, height: number, scale = 2): Promise<Blob> {
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
  try {
    const img = new Image();
    img.decoding = 'async';
    img.src = url;
    await img.decode();
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    const c = canvas.getContext('2d');
    if (!c) throw new Error('This browser can’t draw images.');
    c.drawImage(img, 0, 0, canvas.width, canvas.height);
    return await new Promise<Blob>((resolve, reject) => canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('Couldn’t make the PNG.'))), 'image/png'));
  } finally {
    URL.revokeObjectURL(url);
  }
}
