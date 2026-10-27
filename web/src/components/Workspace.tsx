import { lazy, Suspense } from 'react';
import { app } from '../lib/app';
import { dialogs } from '../lib/dialogs';
import { useStore } from '../lib/store';
import { TopBar } from './TopBar';
import { Diagram } from './diagram/Diagram';
import { SidePanel } from './panel/SidePanel';
import { ThreatsView } from './ThreatsView';
import { CoverageView } from './CoverageView';
import { PathsView } from './PathsView';
import { RegisterView } from './RegisterView';
import { lens } from '../lib/lens';

const YamlView = lazy(() => import('./YamlView').then((m) => ({ default: m.YamlView })));

function AutosaveNotice() {
  if (app.autosaveNoticeSeen || app.backend?.writesThrough || !app.autosaveEnabled) return null;
  return (
    <div className="banner" role="status">
      <p>
        <strong>Autosave is on.</strong> A copy of this model is kept only in this browser’s storage (IndexedDB) on this computer, so you can pick up where you left off. It’s never sent
        anywhere. On a shared computer, turn it off or clear it in Settings (⚙).
      </p>
      <div className="row">
        <button type="button" className="btn small" onClick={() => app.dismissAutosaveNotice()}>
          Got it
        </button>
        <button
          type="button"
          className="btn small"
          onClick={() => {
            app.setAutosave(false);
            app.dismissAutosaveNotice();
          }}
        >
          Turn autosave off
        </button>
      </div>
    </div>
  );
}

export function Workspace() {
  useStore(app);
  useStore(lens);
  const v = app.view;
  // The Register only exists with the reviewer lens on.
  const tab = !v ? 'yaml' : app.tab === 'register' && !lens.reviewer ? 'diagram' : app.tab;
  const showPanel = !!v && (tab !== 'yaml' || !!app.selection);
  return (
    <div className="workspace">
      <TopBar />
      <AutosaveNotice />
      {app.stale && tab !== 'yaml' && (
        <div className="banner warn" role="alert">
          <p>The file has problems, so this shows the last version that could be read.</p>
          <button type="button" className="btn small" onClick={() => app.setTab('yaml')}>
            See the problems
          </button>
        </div>
      )}
      {v && !(v.model.threats ?? []).length && tab !== 'yaml' && (
        <div className="banner" role="status">
          <p>
            <strong>No threats yet.</strong>{' '}
            {app.suggestions.length
              ? `${app.suggestions.length} threats from the library match what you’ve drawn. Go through them and add the real ones.`
              : 'Add the first one: who could do what, by how.'}
          </p>
          <div className="row">
            {app.suggestions.length > 0 && (
              <button type="button" className="btn small primary" onClick={() => app.select('suggestions', '')}>
                Review {app.suggestions.length} suggestions
              </button>
            )}
            <button type="button" className="btn small" onClick={() => dialogs.openForm({ section: 'threats' })}>
              Add a threat
            </button>
          </div>
        </div>
      )}
      <main className={`main${showPanel ? ' with-panel' : ''}`}>
        <div className="view" id="view" role="tabpanel" aria-labelledby={`tab-${tab}`}>
          {tab === 'yaml' ? (
            <Suspense fallback={<div className="loading">Loading the editor…</div>}>
              <YamlView />
            </Suspense>
          ) : !v ? null : tab === 'threats' ? (
            <ThreatsView view={v} />
          ) : tab === 'coverage' ? (
            <CoverageView view={v} />
          ) : tab === 'paths' ? (
            <PathsView view={v} />
          ) : tab === 'register' ? (
            <RegisterView view={v} />
          ) : (
            <Diagram />
          )}
        </div>
        {showPanel && <SidePanel />}
      </main>
    </div>
  );
}
