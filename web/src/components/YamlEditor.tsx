// A small hand-written CodeMirror 6 wrapper. The editor owns its document;
// React only pushes in external changes (diagram edits, live sync) and
// diagnostics, and gets typed text back.
import { useEffect, useRef } from 'react';
import { Annotation, EditorState, type Extension } from '@codemirror/state';
import { EditorView, highlightActiveLine, highlightActiveLineGutter, keymap, lineNumbers, drawSelection } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { bracketMatching, HighlightStyle, indentOnInput, syntaxHighlighting } from '@codemirror/language';
import { yaml } from '@codemirror/lang-yaml';
import { lintGutter, setDiagnostics, type Diagnostic as CmDiagnostic } from '@codemirror/lint';
import { tags } from '@lezer/highlight';
import type { Diagnostic } from '../core/types';

const external = Annotation.define<boolean>();

const highlight = HighlightStyle.define([
  { tag: [tags.propertyName, tags.definition(tags.propertyName)], color: 'var(--cm-key)' },
  { tag: [tags.string, tags.special(tags.string)], color: 'var(--cm-string)' },
  { tag: [tags.number, tags.bool, tags.null, tags.atom], color: 'var(--cm-atom)' },
  { tag: [tags.comment, tags.lineComment], color: 'var(--cm-comment)', fontStyle: 'italic' },
  { tag: [tags.punctuation, tags.separator, tags.bracket], color: 'var(--muted)' },
  { tag: [tags.meta, tags.keyword], color: 'var(--cm-meta)' },
]);

// Colors come from CSS variables so one theme follows light and dark.
const editorTheme = EditorView.theme({
  '&': { height: '100%', backgroundColor: 'var(--surface)', color: 'var(--text)', fontSize: '13px' },
  '.cm-scroller': { fontFamily: 'var(--mono)', lineHeight: '1.55' },
  '.cm-content': { caretColor: 'var(--text)' },
  '.cm-cursor': { borderLeftColor: 'var(--text)' },
  '.cm-gutters': { backgroundColor: 'var(--surface-2)', color: 'var(--muted)', borderRight: '1px solid var(--border)' },
  '.cm-activeLine': { backgroundColor: 'var(--cm-active)' },
  '.cm-activeLineGutter': { backgroundColor: 'var(--cm-active)' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: 'var(--cm-selection) !important' },
  '.cm-tooltip': { backgroundColor: 'var(--surface)', color: 'var(--text)', border: '1px solid var(--border)' },
  '.cm-lintRange-error': { backgroundImage: 'none', textDecoration: 'underline wavy var(--risk-high-bg)' },
  '.cm-lintRange-warning': { backgroundImage: 'none', textDecoration: 'underline wavy var(--risk-medium-border)' },
});

function toCm(state: EditorState, diags: Diagnostic[]): CmDiagnostic[] {
  const out: CmDiagnostic[] = [];
  for (const d of diags) {
    const n = Math.min(Math.max(d.line ?? 1, 1), state.doc.lines);
    const line = state.doc.line(n);
    const from = d.line && d.column ? Math.min(line.from + d.column - 1, line.to) : line.from;
    out.push({ from, to: Math.max(line.to, from), severity: d.severity, message: d.hint ? `${d.message} ${d.hint}` : d.message });
  }
  return out;
}

interface Props {
  value: string;
  /** Changes when `value` was changed from outside the editor. */
  revision: number;
  diagnostics: Diagnostic[];
  reveal: { line: number; seq: number } | null;
  onChange: (text: string) => void;
}

export function YamlEditor({ value, revision, diagnostics, reveal, onChange }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    const extensions: Extension[] = [
      lineNumbers(),
      highlightActiveLineGutter(),
      highlightActiveLine(),
      drawSelection(),
      history(),
      indentOnInput(),
      bracketMatching(),
      yaml(),
      syntaxHighlighting(highlight),
      lintGutter(),
      keymap.of([...defaultKeymap, ...historyKeymap]),
      editorTheme,
      EditorView.contentAttributes.of({ 'aria-label': 'Threat model YAML' }),
      EditorView.updateListener.of((u) => {
        if (u.docChanged && !u.transactions.some((t) => t.annotation(external))) onChangeRef.current(u.state.doc.toString());
      }),
    ];
    const view = new EditorView({ parent: host.current!, state: EditorState.create({ doc: value, extensions }) });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // The editor is created once; later values arrive through the effect below.
  }, []);

  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const current = view.state.doc.toString();
    if (current === value) return;
    // Replace only the part that differs, so the cursor and scroll position survive.
    let start = 0;
    while (start < current.length && start < value.length && current[start] === value[start]) start++;
    let endA = current.length;
    let endB = value.length;
    while (endA > start && endB > start && current[endA - 1] === value[endB - 1]) {
      endA--;
      endB--;
    }
    view.dispatch({ changes: { from: start, to: endA, insert: value.slice(start, endB) }, annotations: external.of(true) });
  }, [value, revision]);

  useEffect(() => {
    const view = viewRef.current;
    if (view) view.dispatch(setDiagnostics(view.state, toCm(view.state, diagnostics)));
  }, [diagnostics, value]);

  useEffect(() => {
    const view = viewRef.current;
    if (!view || !reveal) return;
    const n = Math.min(Math.max(reveal.line, 1), view.state.doc.lines);
    const line = view.state.doc.line(n);
    view.dispatch({ selection: { anchor: line.from }, effects: EditorView.scrollIntoView(line.from, { y: 'center' }) });
    view.focus();
  }, [reveal]);

  return <div className="yaml-editor" ref={host} />;
}

