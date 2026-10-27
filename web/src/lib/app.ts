// The app's state. The single source of truth is the YAML source string:
// every UI edit runs an op in the core, which returns the new source, which
// is shown again. That keeps the web app, the CLI and agents identical.
import { core } from '../core/client';
import { CoreError, type Diagnostic, type EditResult, type Suggestion, type View } from '../core/types';
import { ConflictError, type Backend, type WatchStatus } from '../backend/backend';
import { canSaveAs, FileHandleBackend, pickSaveTarget } from '../backend/local';
import { clearAll, getPref, saveDraft, setPref } from './storage';
import { Store } from './store';

export type Tab = 'diagram' | 'threats' | 'coverage' | 'paths' | 'register' | 'yaml';

export type SelectionType = 'threat' | 'component' | 'flow' | 'zone' | 'suggestions';
export interface Selection {
  type: SelectionType;
  id: string;
}

export interface Notice {
  kind: 'error' | 'info';
  message: string;
  diagnostics: Diagnostic[];
}

export type AutosaveStatus = 'off' | 'pending' | 'saved' | 'failed' | 'server';

/** One step of an edit: takes the current source, returns the edited one. */
export type Step = (source: string) => Promise<EditResult>;

const SHOW_DEBOUNCE_MS = 250;
const AUTOSAVE_DEBOUNCE_MS = 800;
const WRITE_DEBOUNCE_MS = 300;

function errorNotice(err: unknown): Notice {
  if (err instanceof CoreError) return { kind: 'error', message: err.message, diagnostics: err.diagnostics };
  return { kind: 'error', message: err instanceof Error ? err.message : String(err), diagnostics: [] };
}

class App extends Store {
  source = '';
  /** The last view the core could produce. Kept while the source is broken. */
  view: View | null = null;
  diagnostics: Diagnostic[] = [];
  /** The source can't currently be read as a model; `view` is from before. */
  stale = false;
  backend: Backend | null = null;
  savedSource = '';
  tab: Tab = 'diagram';
  selection: Selection | null = null;
  notice: Notice | null = null;
  loading: string | null = null;
  saving = false;
  watchStatus: WatchStatus | null = null;

  autosaveEnabled = getPref('autosave') !== 'off';
  autosaveStatus: AutosaveStatus = 'off';
  autosavedAt: number | null = null;
  autosaveNoticeSeen = getPref('autosave-notice') === 'seen';

  /** Bumped when the source changes from outside the YAML editor. */
  externalRevision = 0;
  /** A request for the YAML editor to scroll to a line. */
  reveal: { line: number; seq: number } | null = null;
  /** Library threats that match the model and haven't been decided on. */
  suggestions: Suggestion[] = [];
  /** Threats and components to emphasise on the diagram (attack paths). */
  highlight: { threats: Set<string>; components: Set<string> } | null = null;

  private showSeq = 0;
  private showTimer: ReturnType<typeof setTimeout> | undefined;
  private autosaveTimer: ReturnType<typeof setTimeout> | undefined;
  private writeTimer: ReturnType<typeof setTimeout> | undefined;
  private writing: Promise<void> | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  private unwatch: (() => void) | null = null;
  private noticeTimer: ReturnType<typeof setTimeout> | undefined;

  get dirty() {
    return this.source !== this.savedSource;
  }

  get model() {
    return this.view?.model;
  }

  // --- opening and closing ---

  setLoading(message: string | null) {
    this.loading = message;
    this.emit();
  }

  async open(source: string, backend: Backend) {
    this.close();
    this.backend = backend;
    this.source = source;
    this.savedSource = source;
    this.externalRevision++;
    this.loading = 'Reading the model…';
    this.emit();
    try {
      await this.refresh();
    } finally {
      this.loading = null;
    }
    if (!this.view) this.tab = 'yaml';
    if (backend.writesThrough) {
      this.autosaveStatus = 'server';
    } else {
      this.autosaveStatus = this.autosaveEnabled ? 'pending' : 'off';
      this.scheduleAutosave();
    }
    if (backend.watch) {
      this.unwatch = backend.watch(
        (s) => this.applyRemote(s),
        (s) => {
          this.watchStatus = s;
          this.emit();
        },
      );
    }
    this.emit();
  }

  close() {
    this.unwatch?.();
    this.unwatch = null;
    clearTimeout(this.showTimer);
    clearTimeout(this.autosaveTimer);
    clearTimeout(this.writeTimer);
    this.writeTimer = undefined;
    this.backend = null;
    this.view = null;
    this.source = '';
    this.savedSource = '';
    this.diagnostics = [];
    this.stale = false;
    this.selection = null;
    this.tab = 'diagram';
    this.watchStatus = null;
    this.notice = null;
    this.suggestions = [];
    this.highlight = null;
    this.emit();
  }

  // --- reading ---

  /** Runs `show` on the current source. Stale responses are dropped. */
  async refresh() {
    const seq = ++this.showSeq;
    const source = this.source;
    try {
      const v = await core.show(source);
      if (seq !== this.showSeq) return;
      this.view = v;
      this.diagnostics = v.diagnostics;
      this.stale = false;
      this.pruneSelection();
      void this.loadSuggestions(source, seq);
    } catch (err) {
      if (seq !== this.showSeq) return;
      if (err instanceof CoreError) {
        this.diagnostics = err.diagnostics.length ? err.diagnostics : [{ severity: 'error', code: 'core', message: err.message }];
        this.stale = true;
      } else {
        this.setNotice(errorNotice(err));
      }
    }
    this.emit();
  }

  private async loadSuggestions(source: string, seq: number) {
    try {
      const r = await core.suggest(source);
      if (seq !== this.showSeq) return;
      this.suggestions = r.suggestions;
    } catch {
      // Suggestions are optional; a model that shows but can't be matched just has none.
      if (seq === this.showSeq) this.suggestions = [];
    }
    this.emit();
  }

  setHighlight(h: { threats: Set<string>; components: Set<string> } | null) {
    this.highlight = h;
    this.emit();
  }

  private pruneSelection() {
    const s = this.selection;
    const m = this.view?.model;
    if (!s || !m || s.type === 'suggestions') return;
    const lists = { threat: m.threats, component: m.components, flow: m.flows, zone: m.zones };
    if (!(lists[s.type] ?? []).some((i) => i.id === s.id)) this.selection = null;
  }

  // --- changing the source ---

  /** Text typed in the YAML editor. */
  setSourceFromEditor(text: string) {
    if (text === this.source) return;
    this.source = text;
    clearTimeout(this.showTimer);
    this.showTimer = setTimeout(() => void this.refresh(), SHOW_DEBOUNCE_MS);
    this.afterChange();
    this.emit();
  }

  /**
   * A change made outside the app (live sync from `threat serve`). Returns
   * whether it was taken.
   */
  private applyRemote(text: string): boolean {
    if (text === this.source) {
      if (this.savedSource !== text) {
        this.savedSource = text;
        this.emit();
      }
      return true;
    }
    // A local change is waiting to be written. Leave the disk version
    // unacknowledged: the write is then refused as a conflict and the disk
    // version loaded, rather than silently overwriting it.
    if (this.writing || this.writeTimer !== undefined) return false;
    this.loadExternal(text);
    return true;
  }

  private loadExternal(text: string) {
    this.source = text;
    this.savedSource = text;
    this.externalRevision++;
    clearTimeout(this.showTimer);
    void this.refresh();
  }

  /** The server refused a write because the file changed on disk. No retry. */
  private onConflict(err: ConflictError) {
    clearTimeout(this.writeTimer);
    this.writeTimer = undefined;
    this.loadExternal(err.source);
    this.setNotice({ kind: 'error', message: err.message, diagnostics: [] });
  }

  private commit(source: string) {
    if (source === this.source) return;
    this.source = source;
    this.externalRevision++;
    clearTimeout(this.showTimer);
    void this.refresh();
    this.afterChange();
    this.emit();
  }

  /**
   * Runs edit steps in order against the current source and commits the
   * result. All or nothing: if a step is refused, nothing changes and the
   * core's plain-language reason is shown. Resolves to whether it applied.
   */
  edit(...steps: Step[]): Promise<boolean> {
    const run = async () => {
      let source = this.source;
      try {
        for (const step of steps) source = (await step(source)).source;
      } catch (err) {
        this.setNotice(errorNotice(err));
        return false;
      }
      this.commit(source);
      return true;
    };
    const p = this.queue.then(run, run);
    this.queue = p;
    return p;
  }

  /** Like edit(), but rejects with the error instead of showing it (for forms). */
  editOrThrow(...steps: Step[]): Promise<void> {
    const run = async () => {
      let source = this.source;
      for (const step of steps) source = (await step(source)).source;
      this.commit(source);
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  private afterChange() {
    if (this.backend?.writesThrough) this.scheduleWrite();
    else this.scheduleAutosave();
  }

  // --- saving ---

  async save() {
    const backend = this.backend;
    if (!backend || this.saving) return;
    this.saving = true;
    this.emit();
    try {
      if (backend.kind === 'download' && canSaveAs()) {
        const handle = await pickSaveTarget(backend.name);
        if (!handle) return;
        const fileBackend = new FileHandleBackend(handle);
        await fileBackend.save(this.source);
        this.backend = fileBackend;
        this.savedSource = this.source;
        this.scheduleAutosave();
        this.info(`Saved to ${handle.name}.`);
        return;
      }
      clearTimeout(this.writeTimer);
      this.writeTimer = undefined;
      const source = this.source;
      const echoed = await backend.save(source);
      this.savedSource = source;
      if (echoed && this.source === source) this.commit(echoed);
      this.info(backend.savesInPlace ? `Saved to ${backend.name}.` : `Downloaded ${backend.name}.`);
    } catch (err) {
      if (err instanceof ConflictError) this.onConflict(err);
      else this.setNotice(errorNotice(err));
    } finally {
      this.saving = false;
      this.emit();
    }
  }

  private scheduleWrite() {
    clearTimeout(this.writeTimer);
    this.writeTimer = setTimeout(() => {
      this.writeTimer = undefined;
      void this.writeThrough();
    }, WRITE_DEBOUNCE_MS);
  }

  private async writeThrough() {
    const backend = this.backend;
    if (!backend) return;
    if (this.writing) await this.writing;
    const source = this.source;
    if (source === this.savedSource) return;
    this.writing = (async () => {
      try {
        const echoed = await backend.save(source);
        this.savedSource = echoed ?? source;
        if (echoed && this.source === source) this.commit(echoed);
      } catch (err) {
        if (err instanceof ConflictError) this.onConflict(err);
        else this.setNotice(errorNotice(err));
      }
    })();
    await this.writing;
    this.writing = null;
    this.emit();
  }

  // --- autosave (browser storage) ---

  private scheduleAutosave() {
    if (!this.autosaveEnabled || !this.backend || this.backend.writesThrough) return;
    this.autosaveStatus = 'pending';
    clearTimeout(this.autosaveTimer);
    this.autosaveTimer = setTimeout(async () => {
      const backend = this.backend;
      if (!backend || !this.autosaveEnabled) return;
      const ok = await saveDraft({
        source: this.source,
        name: backend.name,
        savedAt: Date.now(),
        handle: backend instanceof FileHandleBackend ? backend.handle : undefined,
      });
      if (!this.autosaveEnabled || this.backend !== backend) return;
      this.autosaveStatus = ok ? 'saved' : 'failed';
      if (ok) this.autosavedAt = Date.now();
      this.emit();
    }, AUTOSAVE_DEBOUNCE_MS);
  }

  /** Turning autosave off also deletes the copy it kept. */
  setAutosave(on: boolean) {
    this.autosaveEnabled = on;
    setPref('autosave', on ? 'on' : 'off');
    if (!this.backend?.writesThrough) {
      if (on) {
        this.scheduleAutosave();
      } else {
        clearTimeout(this.autosaveTimer);
        this.autosaveStatus = 'off';
        this.autosavedAt = null;
        void clearAll();
      }
    }
    this.emit();
  }

  async clearStored() {
    clearTimeout(this.autosaveTimer);
    const ok = await clearAll();
    this.autosavedAt = null;
    if (this.autosaveStatus !== 'server') this.autosaveStatus = this.autosaveEnabled && this.backend ? 'pending' : 'off';
    this.info(
      !ok
        ? "Couldn't clear browser storage."
        : this.autosaveEnabled && this.backend && !this.backend.writesThrough
          ? 'Cleared the copy kept in this browser. Autosave is still on, so the open model is saved again on your next edit.'
          : 'Cleared everything this app kept in this browser.',
    );
  }

  dismissAutosaveNotice() {
    this.autosaveNoticeSeen = true;
    setPref('autosave-notice', 'seen');
    this.emit();
  }

  // --- notices and navigation ---

  setNotice(n: Notice | null) {
    clearTimeout(this.noticeTimer);
    this.notice = n;
    if (n?.kind === 'info') {
      this.noticeTimer = setTimeout(() => {
        this.notice = null;
        this.emit();
      }, 4000);
    }
    this.emit();
  }

  info(message: string) {
    this.setNotice({ kind: 'info', message, diagnostics: [] });
  }

  select(type: SelectionType, id: string) {
    if (this.selection?.type === type && this.selection.id === id) return;
    this.selection = { type, id };
    this.emit();
  }

  clearSelection() {
    this.selection = null;
    this.emit();
  }

  setTab(tab: Tab) {
    this.tab = tab;
    this.emit();
  }

  revealLine(line: number) {
    this.tab = 'yaml';
    this.reveal = { line, seq: (this.reveal?.seq ?? 0) + 1 };
    this.emit();
  }
}

export const app = new App();
