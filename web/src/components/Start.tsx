import { useEffect, useRef, useState, type DragEvent } from 'react';
import { app } from '../lib/app';
import { canPickFiles, DownloadBackend, FileHandleBackend, openDropped, openFile, pickFile } from '../backend/local';
import type { Opened } from '../backend/backend';
import { clearAll, loadDraft, type Draft } from '../lib/storage';
import { GuidedStart } from './GuidedStart';

const EXAMPLE = 'examples/invoice-service.threatmodel.yaml';

export function Start() {
  const [guided, setGuided] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [draft, setDraft] = useState<Draft | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void loadDraft().then(setDraft);
  }, []);

  const run = async (fn: () => Promise<Opened | null>) => {
    setError(null);
    try {
      const o = await fn();
      if (o) await app.open(o.source, o.backend);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const open = () => {
    if (canPickFiles()) void run(pickFile);
    else input.current?.click();
  };

  const example = () =>
    run(async () => {
      const res = await fetch(EXAMPLE);
      if (!res.ok) throw new Error('Couldn’t load the example.');
      return { source: await res.text(), backend: new DownloadBackend('threatmodel.yaml') };
    });

  const restore = (d: Draft) =>
    run(async () => ({ source: d.source, backend: d.handle ? new FileHandleBackend(d.handle) : new DownloadBackend(d.name) }));

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    // openDropped reads the DataTransfer synchronously before awaiting.
    const p = openDropped(e.dataTransfer);
    void run(() => p);
  };

  if (guided) return <GuidedStart onCancel={() => setGuided(false)} />;

  return (
    <main
      className={`start${dragging ? ' dragging' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <div className="start-inner">
        <h1>Threat model</h1>
        <p className="lede">Draw what you’re building, and see what someone could do to it. Everything stays in this browser.</p>
        <div className="choices">
          <button type="button" className="choice" onClick={open}>
            <span className="choice-title">Open a file</span>
            <span className="choice-text">Pick a threatmodel.yaml, or drop it anywhere on this page.</span>
          </button>
          <button type="button" className="choice" onClick={() => setGuided(true)}>
            <span className="choice-title">Start a new model</span>
            <span className="choice-text">A few quick questions and you have a first diagram.</span>
          </button>
          <button type="button" className="choice" onClick={() => void example()}>
            <span className="choice-title">Try an example</span>
            <span className="choice-text">An invoicing service with threats and fixes.</span>
          </button>
        </div>
        <input
          ref={input}
          type="file"
          name="model-file"
          accept=".yaml,.yml,text/yaml"
          hidden
          onChange={(e) => {
            const f = e.currentTarget.files?.[0];
            e.currentTarget.value = '';
            if (f) void run(() => openFile(f));
          }}
        />
        {error && (
          <p className="start-error" role="alert">
            {error}
          </p>
        )}
        {draft && (
          <div className="draft">
            <p>
              This browser kept a copy of <strong>{draft.name}</strong> from {new Date(draft.savedAt).toLocaleString()}.
            </p>
            <div className="row">
              <button type="button" className="btn small" onClick={() => void restore(draft)}>
                Continue where you left off
              </button>
              <button
                type="button"
                className="btn small"
                onClick={() => {
                  void clearAll().then(() => setDraft(null));
                }}
              >
                Delete the copy
              </button>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
