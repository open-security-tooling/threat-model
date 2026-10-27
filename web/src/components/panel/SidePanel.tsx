import { useEffect, useRef } from 'react';
import { app } from '../../lib/app';
import { useStore } from '../../lib/store';
import { ThreatCard } from './ThreatCard';
import { ItemPanel } from './ItemPanel';
import { Overview } from './Overview';
import { SuggestionsPanel } from './Suggestions';

export function SidePanel() {
  useStore(app);
  const el = useRef<HTMLElement>(null);
  const sel = app.selection;
  const key = sel ? `${sel.type}:${sel.id}` : '';

  useEffect(() => {
    // Start each newly selected item at the top.
    el.current?.scrollTo({ top: 0 });
  }, [key]);

  if (!app.view) return null;
  return (
    <aside className="side" ref={el} aria-label="Details">
      {sel && (
        <button type="button" className="btn ghost small close" onClick={() => app.clearSelection()} aria-label="Close details">
          ✕
        </button>
      )}
      {!sel ? (
        <Overview view={app.view} />
      ) : sel.type === 'threat' ? (
        <ThreatCard key={key} view={app.view} id={sel.id} />
      ) : sel.type === 'suggestions' ? (
        <SuggestionsPanel />
      ) : (
        <ItemPanel key={key} view={app.view} type={sel.type} id={sel.id} />
      )}
    </aside>
  );
}
