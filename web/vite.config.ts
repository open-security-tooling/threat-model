import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

// Files copied from public/ that the app needs offline.
const PUBLIC_FILES = ['core.wasm', 'wasm_exec.js', 'favicon.svg', 'icon-192.png', 'icon-512.png', 'manifest.webmanifest', 'examples/invoice-service.threatmodel.yaml'];

/**
 * Emits sw.js with the exact list of built files and a cache version derived
 * from their names and the public files' contents, so every build that
 * changes anything gets a new cache and old ones are dropped.
 */
function serviceWorker(): Plugin {
  return {
    name: 'threat-model-service-worker',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const built = Object.keys(bundle).filter((f) => !f.endsWith('.map'));
      const hash = createHash('sha256');
      for (const f of built.sort()) hash.update(f);
      for (const f of PUBLIC_FILES) hash.update(f).update(readFileSync(new URL(`public/${f}`, import.meta.url)));
      const version = hash.digest('hex').slice(0, 16);
      const files = ['./', ...built, ...PUBLIC_FILES];
      const template = readFileSync(new URL('sw.template.js', import.meta.url), 'utf8');
      this.emitFile({
        type: 'asset',
        fileName: 'sw.js',
        source: template.replace('__VERSION__', version).replace('__FILES__', JSON.stringify(files)),
      });
    },
  };
}

export default defineConfig({
  // Relative base: the same build is served under /threat-model/ on GitHub
  // Pages and at / by `threat serve`.
  base: './',
  plugins: [react(), serviceWorker()],
  worker: { format: 'es' },
  build: {
    target: 'es2022',
    // Every supported browser has modulepreload; the polyfill is dead weight.
    modulePreload: { polyfill: false },
    // Keep everything as files so the CSP never needs data: scripts.
    assetsInlineLimit: 0,
  },
});
