import { useEffect, useRef, useState, type FormEvent } from 'react';
import { app } from '../lib/app';
import { DownloadBackend } from '../backend/local';
import { actorTiles, buildModel, dataTiles, pieceTiles, type Answers } from '../lib/newModel';
import { KindIcon } from './diagram/KindIcon';

const steps = ['What are you building?', 'Who uses it?', 'What are the main pieces?', 'Which of these can be reached from the internet?', 'What data is worth protecting?'];

function Tiles({ items, selected, onToggle }: { items: { key: string; name: string; kind?: string }[]; selected: string[]; onToggle: (k: string) => void }) {
  return (
    <div className="tiles">
      {items.map((t) => (
        <button key={t.key} type="button" className="tile" aria-pressed={selected.includes(t.key)} onClick={() => onToggle(t.key)}>
          {t.kind && <KindIcon kind={t.kind} size={22} />}
          <span>{t.name}</span>
        </button>
      ))}
    </div>
  );
}

export function GuidedStart({ onCancel }: { onCancel: () => void }) {
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [a, setA] = useState<Answers>({ name: '', description: '', actors: ['customers'], pieces: ['web', 'api', 'db'], internet: ['api'], data: ['personal', 'passwords'] });
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => heading.current?.focus(), [step]);

  const toggle = (field: 'actors' | 'pieces' | 'internet' | 'data') => (k: string) =>
    setA((prev) => ({ ...prev, [field]: prev[field].includes(k) ? prev[field].filter((x) => x !== k) : [...prev[field], k] }));

  const exposable = pieceTiles.filter((p) => p.canExpose && a.pieces.includes(p.key));
  const last = step === steps.length - 1;

  const finish = async () => {
    setBusy(true);
    setError(null);
    try {
      const source = await buildModel({ ...a, internet: a.internet.filter((k) => a.pieces.includes(k)) });
      await app.open(source, new DownloadBackend('threatmodel.yaml'));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  };

  const next = (e: FormEvent) => {
    e.preventDefault();
    if (last) void finish();
    else setStep(step + 1);
  };

  return (
    <main className="start">
      <form className="start-inner guided" onSubmit={next}>
        <p className="muted">
          Step {step + 1} of {steps.length} · every question can be skipped
        </p>
        <h1 ref={heading} tabIndex={-1}>
          {steps[step]}
        </h1>
        {step === 0 && (
          <>
            <div className="field">
              <label htmlFor="g-name">Name</label>
              <input id="g-name" type="text" value={a.name} onChange={(e) => setA({ ...a, name: e.target.value })} placeholder="Invoice service" autoFocus />
            </div>
            <div className="field">
              <label htmlFor="g-desc">In a sentence, what does it do?</label>
              <textarea id="g-desc" rows={2} value={a.description} onChange={(e) => setA({ ...a, description: e.target.value })} placeholder="Lets small businesses send and get paid for invoices." />
            </div>
          </>
        )}
        {step === 1 && <Tiles items={actorTiles} selected={a.actors} onToggle={toggle('actors')} />}
        {step === 2 && <Tiles items={pieceTiles} selected={a.pieces} onToggle={toggle('pieces')} />}
        {step === 3 &&
          (exposable.length ? (
            <Tiles items={exposable} selected={a.internet} onToggle={toggle('internet')} />
          ) : (
            <p className="muted">None of the pieces you picked run in your own infrastructure. Apps and browsers are on the internet already.</p>
          ))}
        {step === 4 && (
          <>
            <Tiles items={dataTiles} selected={a.data} onToggle={toggle('data')} />
            <p className="muted">You’ll get a diagram to adjust. Add threats from the suggestions or by hand.</p>
          </>
        )}
        {error && (
          <p className="start-error" role="alert">
            {error}
          </p>
        )}
        <div className="row">
          <button type="button" className="btn" onClick={() => (step ? setStep(step - 1) : onCancel())}>
            {step ? 'Back' : 'Cancel'}
          </button>
          <button type="submit" className="btn primary" disabled={busy}>
            {last ? (busy ? 'Creating…' : 'Create model') : 'Next'}
          </button>
        </div>
      </form>
    </main>
  );
}
