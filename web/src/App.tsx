import { lazy, Suspense, useEffect, useState } from 'react';
import { app } from './lib/app';
import { useStore } from './lib/store';
import { dialogs } from './lib/dialogs';
import { core } from './core/client';
import { ServerBackend, takeServeToken } from './backend/server';
import { Start } from './components/Start';
import { NoticeBar } from './components/NoticeBar';
import { ItemForm } from './components/ItemForm';
import { palette } from './lib/palette';
import { pwa } from './lib/pwa';

// The diagram and editor are most of the code; the first screen doesn't need them.
const Workspace = lazy(() => import('./components/Workspace').then((m) => ({ default: m.Workspace })));
const CommandPalette = lazy(() => import('./components/CommandPalette').then((m) => ({ default: m.CommandPalette })));

// Read once at load, before anything renders, so the token leaves the
// address bar immediately.
const serveToken = takeServeToken();

export function App() {
  useStore(app);
  useStore(dialogs);
  useStore(palette);
  useStore(pwa);
  const [serverError, setServerError] = useState<string | null>(null);

  useEffect(() => {
    // Start loading the engine while the first screen is up.
    core.start().catch(() => undefined);
    if (!serveToken) {
      pwa.register();
      return;
    }
    const backend = new ServerBackend(serveToken);
    app.setLoading('Connecting to threat serve…');
    backend
      .open()
      .then((o) => app.open(o.source, o.backend))
      .catch((err: unknown) => {
        app.setLoading(null);
        setServerError(err instanceof Error ? err.message : String(err));
      });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        void app.save();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        palette.toggle();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    document.title = app.view ? `${app.view.model.system.name} · Threat model` : 'Threat model';
  }, [app.view]);

  return (
    <>
      {app.backend ? (
        <Suspense fallback={<div className="loading">Loading…</div>}>
          <Workspace />
        </Suspense>
      ) : app.loading ? (
        <div className="loading" role="status">
          {app.loading}
        </div>
      ) : serveToken ? (
        <div className="loading" role="alert">
          <p>Couldn’t load the file from threat serve.</p>
          <p className="muted">{serverError}</p>
          <p className="muted">Restart `threat serve` and open the link it prints.</p>
        </div>
      ) : (
        <Start />
      )}
      <NoticeBar />
      {pwa.updateReady && (
        <div className="update-prompt" role="status">
          <p>A new version of the app is ready.</p>
          <button
            type="button"
            className="btn small primary"
            onClick={() => {
              const unsaved = app.dirty && app.backend && !app.backend.writesThrough && !app.autosaveEnabled;
              if (!unsaved || confirm('Reload now? Your changes aren’t saved to a file and autosave is off, so they’d be lost.')) pwa.reload();
            }}
          >
            Reload
          </button>
          <button type="button" className="btn ghost small" onClick={() => pwa.dismiss()}>
            Later
          </button>
        </div>
      )}
      {palette.isOpen && (
        <Suspense fallback={null}>
          <CommandPalette onClose={() => palette.close()} />
        </Suspense>
      )}
      {dialogs.form && app.view && <ItemForm key={`${dialogs.form.section}:${dialogs.form.id ?? 'new'}`} request={dialogs.form} view={app.view} />}
    </>
  );
}
