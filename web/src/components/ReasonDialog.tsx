import { useEffect, useRef, useState, type FormEvent } from 'react';

/**
 * Asks for a one-line reason, for decisions the file records with a why:
 * "doesn't apply", dismissing suggestions. A modal <dialog>, so focus stays
 * inside and Escape cancels; focus goes back to where it was.
 */
export function ReasonDialog({
  title,
  label,
  confirm,
  onSubmit,
  onClose,
}: {
  title: string;
  label: string;
  confirm: string;
  onSubmit: (reason: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const returnTo = useRef<HTMLElement | null>(document.activeElement instanceof HTMLElement ? document.activeElement : null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const d = dialog.current;
    if (!d || d.open) return;
    d.showModal();
    d.querySelector('input')?.focus();
    const back = returnTo.current;
    return () => {
      if (back?.isConnected) setTimeout(() => back.focus(), 0);
    };
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = reason.trim();
    if (!r) return;
    setBusy(true);
    const ok = await onSubmit(r);
    setBusy(false);
    if (ok) onClose();
  };

  return (
    <dialog
      ref={dialog}
      className="form-dialog reason-dialog"
      aria-labelledby="reason-title"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <form onSubmit={submit}>
        <header className="dialog-head">
          <h2 id="reason-title">{title}</h2>
        </header>
        <div className="dialog-body">
          <div className="field">
            <label htmlFor="reason-input">{label}</label>
            <input id="reason-input" type="text" value={reason} onChange={(e) => setReason(e.target.value)} required />
          </div>
        </div>
        <footer className="dialog-foot">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={busy || !reason.trim()}>
            {confirm}
          </button>
        </footer>
      </form>
    </dialog>
  );
}
