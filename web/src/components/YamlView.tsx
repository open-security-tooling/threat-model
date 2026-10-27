import { app } from '../lib/app';
import { useStore } from '../lib/store';
import { YamlEditor } from './YamlEditor';
import { DiagnosticList } from './DiagnosticList';
import { Diagram } from './diagram/Diagram';

export function YamlView() {
  useStore(app);
  const errors = app.diagnostics.filter((d) => d.severity === 'error').length;
  const warnings = app.diagnostics.length - errors;
  return (
    <div className="split yaml-split">
      <div className="yaml-pane">
        <YamlEditor
          value={app.source}
          revision={app.externalRevision}
          diagnostics={app.diagnostics}
          reveal={app.reveal}
          onChange={(text) => app.setSourceFromEditor(text)}
        />
        <div className="yaml-problems" aria-live="polite">
          {app.diagnostics.length ? (
            <>
              <p className="problems-head">
                {errors ? `${errors} ${errors === 1 ? 'problem' : 'problems'} to fix` : 'No problems'}
                {warnings ? `, ${warnings} ${warnings === 1 ? 'suggestion' : 'suggestions'}` : ''}
                {app.stale && ' — the diagram shows the last version that could be read'}
              </p>
              <DiagnosticList diagnostics={app.diagnostics} onLine={(l) => app.revealLine(l)} />
            </>
          ) : (
            <p className="problems-head ok">No problems found.</p>
          )}
        </div>
      </div>
      <div className="split-main">{app.view ? <Diagram /> : <p className="muted pad">The diagram appears once the file can be read as a threat model.</p>}</div>
    </div>
  );
}
