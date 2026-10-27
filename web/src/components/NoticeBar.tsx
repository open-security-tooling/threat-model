import { app } from '../lib/app';
import { useStore } from '../lib/store';
import { DiagnosticList } from './DiagnosticList';

export function NoticeBar() {
  useStore(app);
  const n = app.notice;
  if (!n) return null;
  return (
    <div className={`notice notice-${n.kind}`} role={n.kind === 'error' ? 'alert' : 'status'}>
      <div className="notice-body">
        <p className="notice-message">{n.message}</p>
        {n.diagnostics.length > 0 && <DiagnosticList diagnostics={n.diagnostics} />}
      </div>
      <button type="button" className="btn ghost small" onClick={() => app.setNotice(null)} aria-label="Dismiss">
        ✕
      </button>
    </div>
  );
}
