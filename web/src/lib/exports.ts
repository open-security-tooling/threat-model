// Everything the Export menu and the command palette can produce.
import { app } from './app';
import { theme } from './theme';
import { core } from '../core/client';
import { CoreError } from '../core/types';
import { download } from '../backend/local';
import { diagramSvg, palettes, svgToPng } from './exportSvg';
import { htmlReport } from './htmlReport';

function baseName() {
  return (app.backend?.name ?? 'threatmodel').replace(/\.(ya?ml)$/i, '') || 'threatmodel';
}

function downloadBlob(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function guarded(fn: () => Promise<void> | void) {
  try {
    await fn();
  } catch (err) {
    app.setNotice({ kind: 'error', message: err instanceof Error ? err.message : String(err), diagnostics: err instanceof CoreError ? err.diagnostics : [] });
  }
}

export const exports = {
  yaml: () => guarded(() => download(app.backend?.name ?? 'threatmodel.yaml', app.source, 'text/yaml')),
  json: () =>
    guarded(() => {
      const v = app.view;
      if (!v) return;
      const { model, risks, crossings, summary, coverage, diagnostics } = v;
      download(`${baseName()}.json`, JSON.stringify({ model, risks, crossings, summary, coverage, diagnostics }, null, 2), 'application/json');
    }),
  markdown: () =>
    guarded(async () => {
      const r = await core.report(app.source);
      download(`${baseName()}-report.md`, r.markdown, 'text/markdown');
    }),
  html: () =>
    guarded(() => {
      if (app.view) download(`${baseName()}-report.html`, htmlReport(app.view), 'text/html');
    }),
  svg: () =>
    guarded(() => {
      if (app.view) download(`${baseName()}-diagram.svg`, diagramSvg(app.view, palettes[theme.resolved]).svg, 'image/svg+xml');
    }),
  png: () =>
    guarded(async () => {
      if (!app.view) return;
      const { svg, width, height } = diagramSvg(app.view, palettes[theme.resolved]);
      downloadBlob(`${baseName()}-diagram.png`, await svgToPng(svg, width, height));
    }),
};
