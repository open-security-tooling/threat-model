// Security checks for the web app, run in CI (`npm run security`).
//
// They back two mitigations in the repo's own threatmodel.yaml:
//   render-text-only  no source file may use an HTML injection sink, so model
//                     text from a pull request can never become markup
//   strict-csp        index.html must ship a Content-Security-Policy that
//                     blocks inline and third-party scripts and all outbound
//                     connections
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const problems = [];

// 1. No HTML injection sinks.
const sinks = [
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
  ['innerHTML', /\.innerHTML\s*[+]?=/],
  ['outerHTML', /\.outerHTML\s*[+]?=/],
  ['insertAdjacentHTML', /insertAdjacentHTML\s*\(/],
  ['document.write', /document\.write(ln)?\s*\(/],
  ['eval', /(^|[^.\w])eval\s*\(/],
  ['new Function', /new\s+Function\s*\(/],
  ['createContextualFragment', /createContextualFragment\s*\(/],
];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else if (/\.(ts|tsx|js|jsx|mjs)$/.test(name)) {
      readFileSync(path, 'utf8').split('\n').forEach((line, i) => {
        for (const [what, re] of sinks) {
          if (re.test(line)) problems.push(`${relative(root, path)}:${i + 1}: uses ${what}; render model text as text instead`);
        }
      });
    }
  }
}
walk(join(root, 'src'));

// 2. The Content-Security-Policy in index.html.
const html = readFileSync(join(root, 'index.html'), 'utf8');
const meta = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/);
if (!meta) {
  problems.push('index.html: no Content-Security-Policy meta tag');
} else {
  const csp = Object.fromEntries(
    meta[1].split(';').map((d) => d.trim()).filter(Boolean).map((d) => {
      const [name, ...values] = d.split(/\s+/);
      return [name, values];
    }),
  );
  const require = {
    'default-src': ["'self'"],
    'connect-src': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'none'"],
    'form-action': ["'none'"],
  };
  for (const [name, want] of Object.entries(require)) {
    const got = csp[name];
    if (!got || got.join(' ') !== want.join(' ')) {
      problems.push(`index.html CSP: ${name} must be exactly ${want.join(' ')} (is ${got ? got.join(' ') : 'missing'})`);
    }
  }
  const scripts = csp['script-src'] ?? [];
  for (const bad of ["'unsafe-inline'", "'unsafe-eval'", '*', 'http:', 'https:', 'data:', 'blob:']) {
    if (scripts.includes(bad)) problems.push(`index.html CSP: script-src must not allow ${bad}`);
  }
  if (!scripts.includes("'self'")) problems.push("index.html CSP: script-src must be 'self' (plus 'wasm-unsafe-eval')");
}

if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('No HTML injection sinks, and the CSP blocks inline scripts and outbound connections.');
