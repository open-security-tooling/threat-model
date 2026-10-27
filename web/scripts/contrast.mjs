// Checks WCAG contrast for the colour pairs the UI uses, in both themes.
// Reads the tokens from src/app.css. Run: npm run contrast
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../src/app.css', import.meta.url), 'utf8');

function block(selector) {
  const i = css.indexOf(selector);
  if (i < 0) throw new Error(`no ${selector} in app.css`);
  const start = css.indexOf('{', i);
  let depth = 0;
  for (let j = start; j < css.length; j++) {
    if (css[j] === '{') depth++;
    if (css[j] === '}' && --depth === 0) return css.slice(start + 1, j);
  }
  throw new Error('unbalanced braces');
}

function tokens(text) {
  const out = {};
  for (const m of text.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}

const light = tokens(block(':root {'));
const dark = { ...light, ...tokens(block(":root[data-theme='dark'] {")) };

// The dark tokens are written twice (system preference, and the explicit
// toggle); they must stay identical.
const systemDark = { ...light, ...tokens(block(":root:not([data-theme='light']) {")) };
const drift = Object.keys(dark).filter((k) => dark[k] !== systemDark[k]);
if (drift.length) {
  console.log(`FAIL dark tokens differ between the two dark blocks: ${drift.join(', ')}`);
  process.exitCode = 1;
}

function rgba(v, t) {
  const ref = /^var\(--([\w-]+)\)$/.exec(v);
  if (ref) return rgba(t[ref[1]], t);
  let m = /^#([0-9a-f]{6})$/i.exec(v);
  if (m) return [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16)).concat(1);
  m = /^rgb\(\s*(\d+)\s+(\d+)\s+(\d+)(?:\s*\/\s*([\d.]+))?\s*\)$/.exec(v);
  if (m) return [+m[1], +m[2], +m[3], m[4] ? +m[4] : 1];
  throw new Error(`can't read colour ${v}`);
}

/** Composites a translucent colour over an opaque one. */
const over = (fg, bg) => [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat(1);

function lum([r, g, b]) {
  const f = (c) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

function ratio(fgName, bgName, t, under = 'bg') {
  const base = rgba(`var(--${under})`, t);
  const bg = over(rgba(`var(--${bgName})`, t), base);
  const fg = over(rgba(`var(--${fgName})`, t), bg);
  const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
}

// [foreground, background, minimum, what it is]. 4.5 = normal text, 3 = UI parts and graphics.
const TEXT = 4.5;
const UI = 3;
const pairs = [
  ['text', 'bg', TEXT, 'body text'],
  ['text', 'surface', TEXT, 'panel text'],
  ['text', 'surface-2', TEXT, 'text on raised areas'],
  ['muted', 'bg', TEXT, 'secondary text'],
  ['muted', 'surface', TEXT, 'secondary text in panels'],
  ['muted', 'surface-2', TEXT, 'table headers, inline forms'],
  ['text', 'accent-soft', TEXT, 'selected rows'],
  ['muted', 'accent-soft', TEXT, 'secondary text in selected rows'],
  ['accent', 'surface', TEXT, 'links'],
  ['accent', 'bg', TEXT, 'links on the page'],
  ['accent-fg', 'accent', TEXT, 'primary buttons'],
  ['error-fg', 'error-bg', TEXT, 'error notices'],
  ['error-fg', 'surface', TEXT, '"gets out" label'],
  ['warn-fg', 'warn-bg', TEXT, 'warnings, unencrypted tag'],
  ['warn-fg', 'surface', TEXT, '"unsaved" marker'],
  ['info-fg', 'info-bg', TEXT, 'info banners, suggestion badge'],
  ['zone-untrusted', 'surface', TEXT, '"internet" on components'],
  ['risk-low-bg', 'surface', TEXT, '"stays in" label'],
  ['risk-critical-fg', 'risk-critical-bg', TEXT, 'critical pill'],
  ['risk-high-fg', 'risk-high-bg', TEXT, 'high pill'],
  ['risk-medium-fg', 'risk-medium-bg', TEXT, 'medium pill'],
  ['risk-low-fg', 'risk-low-bg', TEXT, 'low pill, contained tag'],
  ['risk-none-fg', 'risk-none-bg', TEXT, 'not-assessed pill'],
  ['cm-key', 'surface', TEXT, 'YAML keys'],
  ['cm-string', 'surface', TEXT, 'YAML strings'],
  ['cm-atom', 'surface', TEXT, 'YAML numbers'],
  ['cm-comment', 'surface', TEXT, 'YAML comments'],
  ['cm-meta', 'surface', TEXT, 'YAML meta'],
  ['muted', 'surface-2', TEXT, 'editor line numbers'],
  ['border-strong', 'surface', UI, 'input and component borders'],
  ['focus', 'bg', UI, 'focus ring on the page'],
  ['focus', 'surface', UI, 'focus ring in panels'],
  ['zone-untrusted', 'bg', UI, 'untrusted zone border'],
  ['zone-partial', 'bg', UI, 'partly trusted zone border'],
  ['zone-trusted', 'bg', UI, 'trusted zone border'],
  ['edge', 'bg', UI, 'arrows'],
  ['edge-crossing', 'bg', UI, 'zone-crossing arrows'],
  ['risk-critical-bg', 'surface', UI, 'critical dot'],
  ['risk-high-bg', 'surface', UI, 'high dot'],
  ['risk-medium-border', 'surface', UI, 'medium dot outline'],
  ['risk-low-bg', 'surface', UI, 'low dot'],
  ['risk-none-bg', 'surface', UI, 'not-assessed dot'],
];

let failures = 0;
for (const [name, t] of [
  ['light', light],
  ['dark', dark],
]) {
  console.log(`\n${name}`);
  for (const [fg, bg, min, what] of pairs) {
    const r = ratio(fg, bg, t);
    const ok = r >= min;
    if (!ok) failures++;
    console.log(`${ok ? '  ok ' : 'FAIL '} ${r.toFixed(2).padStart(5)} (needs ${min})  ${fg} on ${bg}: ${what}`);
  }
}
// Risk colours must read in order: critical is red, high orange, medium
// yellow, low green. (They once read backwards: critical purple, high red.)
function hue(v, t) {
  const [r, g, b] = rgba(v, t).map((c) => c / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max === min) return 0;
  const d = max - min;
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return (h * 60 + 360) % 360;
}
const bands = { critical: [345, 12], high: [16, 35], medium: [38, 55], low: [90, 160] };
for (const [name, t] of [
  ['light', light],
  ['dark', dark],
]) {
  for (const [level, [lo, hi]] of Object.entries(bands)) {
    const h = hue(`var(--risk-${level}-bg)`, t);
    const ok = lo <= hi ? h >= lo && h <= hi : h >= lo || h <= hi;
    if (!ok) {
      failures++;
      console.log(`FAIL ${name}: risk-${level}-bg has hue ${h.toFixed(0)}°, expected ${lo}–${hi}°`);
    }
  }
}

console.log(failures ? `\n${failures} checks failed` : '\nAll pairs meet WCAG AA, and risk colours read in order');
if (failures) process.exitCode = 1;
