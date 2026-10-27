import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { commands, matches } from '../lib/commands';

const MAX = 60;

/**
 * A modal <dialog>: the browser keeps focus inside it and Escape closes it.
 * The input is a combobox driving a listbox, so screen readers announce the
 * highlighted command while focus stays in the input.
 */
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  // Built once per opening, from the app's state at that moment.
  const all = useMemo(() => commands(), []);
  const shown = useMemo(() => all.filter((c) => matches(c, query)).slice(0, MAX), [all, query]);

  useEffect(() => {
    const d = dialog.current;
    if (d && !d.open) d.showModal();
  }, []);

  useEffect(() => setActive(0), [query]);

  useEffect(() => {
    list.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const run = (i: number) => {
    const c = shown[i];
    if (!c) return;
    onClose();
    // After the dialog has closed, so focus and any new dialog behave.
    setTimeout(c.run, 0);
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, shown.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Home') {
      e.preventDefault();
      setActive(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setActive(shown.length - 1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      run(active);
    }
  };

  let lastGroup = '';
  return (
    <dialog
      ref={dialog}
      className="palette"
      aria-label="Command palette"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        // A click on the backdrop (the dialog element itself) closes it.
        if (e.target === dialog.current) onClose();
      }}
    >
      <input
        className="palette-input"
        type="text"
        name="command"
        role="combobox"
        aria-expanded="true"
        aria-controls="palette-list"
        aria-activedescendant={shown[active] ? `cmd-${shown[active].id}` : undefined}
        aria-autocomplete="list"
        aria-label="Type a command or the name of an item"
        placeholder="Type a command or the name of an item…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={onKey}
        autoFocus
      />
      <ul className="palette-list" id="palette-list" role="listbox" ref={list} aria-label="Commands">
        {shown.map((c, i) => {
          const header = c.group !== lastGroup ? c.group : null;
          lastGroup = c.group;
          return (
            <li
              key={c.id}
              id={`cmd-${c.id}`}
              role="option"
              aria-selected={i === active}
              data-index={i}
              className={i === active ? 'active' : undefined}
              onMouseMove={() => setActive(i)}
              onClick={() => run(i)}
            >
              {header && <span className="palette-group">{header}</span>}
              <span className="palette-label">{c.label}</span>
            </li>
          );
        })}
        {!shown.length && (
          <li className="palette-empty" role="option" aria-selected="false" aria-disabled="true">
            Nothing matches “{query}”.
          </li>
        )}
      </ul>
      <p className="palette-hint muted small" aria-hidden="true">
        ↑↓ to move · Enter to run · Esc to close
      </p>
    </dialog>
  );
}
