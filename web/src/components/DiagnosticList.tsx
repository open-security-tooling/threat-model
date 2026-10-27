import type { Diagnostic } from '../core/types';

export function DiagnosticList({ diagnostics, onLine }: { diagnostics: Diagnostic[]; onLine?: (line: number) => void }) {
  return (
    <ul className="diagnostics">
      {diagnostics.map((d, i) => (
        <li key={i} className={`diag diag-${d.severity}`}>
          <span className="diag-sev">{d.severity === 'error' ? 'Error' : 'Warning'}</span>
          {d.line ? (
            onLine ? (
              <button type="button" className="link-btn diag-line" onClick={() => onLine(d.line!)}>
                Line {d.line}
              </button>
            ) : (
              <span className="diag-line">Line {d.line}</span>
            )
          ) : null}
          <span className="diag-msg">
            {d.message}
            {d.hint ? ` ${d.hint}` : ''}
          </span>
        </li>
      ))}
    </ul>
  );
}
