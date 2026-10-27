// Promise-based client for the Go core running in a Web Worker.
import type { FromWorker, ToWorker } from './protocol';
import {
  CoreError,
  type Diagnostic,
  type EditResult,
  type ExplainResult,
  type Fields,
  type FormatResult,
  type BlastResult,
  type Op,
  type OpResults,
  type PathsResult,
  type ReportResult,
  type Signoff,
  type Position,
  type Request,
  type Section,
  type StatusRequest,
  type SuggestResult,
  type ValidateResult,
  type View,
} from './types';

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
}

type Response = { result: unknown } | { error: { message: string; diagnostics?: Diagnostic[] } };

export interface CoreOptions {
  /** A call taking longer than this kills the worker (e.g. a hostile file). */
  timeoutMs?: number;
}

export class Core {
  private worker: Worker | null = null;
  private ready: Promise<void> | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private readonly timeoutMs: number;
  version = '';

  constructor(opts: CoreOptions = {}) {
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  /** Starts the worker if it isn't running. Safe to call repeatedly. */
  start(): Promise<void> {
    if (this.ready) return this.ready;
    const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module', name: 'threat-core' });
    this.worker = worker;
    this.ready = new Promise<void>((resolve, reject) => {
      worker.addEventListener('message', (e: MessageEvent<FromWorker>) => {
        const msg = e.data;
        if (msg.type === 'ready') {
          this.version = msg.version;
          resolve();
        } else if (msg.type === 'fatal') {
          this.kill(new CoreError(`The model engine failed to load: ${msg.message}`));
          reject(new CoreError(`The model engine failed to load: ${msg.message}`));
        } else {
          this.settle(msg.id, msg.response);
        }
      });
      worker.addEventListener('error', (e) => {
        const err = new CoreError(`The model engine crashed${e.message ? `: ${e.message}` : '.'}`);
        this.kill(err);
        reject(err);
      });
    });
    // Resolve against the document, not this module: the worker is emitted
    // into assets/ but the wasm files sit next to index.html.
    const init: ToWorker = {
      type: 'init',
      wasmUrl: new URL('core.wasm', document.baseURI).href,
      execUrl: new URL('wasm_exec.js', document.baseURI).href,
    };
    worker.postMessage(init);
    return this.ready;
  }

  private settle(id: number, raw: string) {
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    clearTimeout(p.timer);
    let res: Response;
    try {
      res = JSON.parse(raw) as Response;
    } catch {
      p.reject(new CoreError('The model engine returned something unreadable.'));
      return;
    }
    if ('error' in res) p.reject(new CoreError(res.error.message, res.error.diagnostics ?? []));
    else p.resolve(res.result);
  }

  private kill(reason: CoreError) {
    this.worker?.terminate();
    this.worker = null;
    this.ready = null;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(reason);
    }
    this.pending.clear();
  }

  async call<O extends Op>(op: O, request: Request): Promise<OpResults[O]> {
    await this.start();
    const worker = this.worker;
    if (!worker) throw new CoreError('The model engine is not running.');
    const id = this.nextId++;
    return new Promise<OpResults[O]>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.kill(new CoreError('Processing the model took too long, so it was stopped. The file may be too large or malformed.'));
      }, this.timeoutMs);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      const msg: ToWorker = { type: 'call', id, op, request: JSON.stringify(request) };
      worker.postMessage(msg);
    });
  }

  validate(source: string): Promise<ValidateResult> {
    return this.call('validate', { source });
  }

  format(source: string): Promise<FormatResult> {
    return this.call('format', { source });
  }

  show(source: string): Promise<View> {
    return this.call('show', { source });
  }

  explain(source: string, id: string): Promise<ExplainResult> {
    return this.call('explain', { source, id });
  }

  upsert(source: string, section: Section, id: string, fields: Fields): Promise<EditResult> {
    return this.call('upsert', { source, section, id, fields });
  }

  delete(source: string, section: Section, id: string): Promise<EditResult> {
    return this.call('delete', { source, section, id });
  }

  setSystem(source: string, fields: Fields): Promise<EditResult> {
    return this.call('set_system', { source, fields });
  }

  setLayout(source: string, id: string, position: Position | null): Promise<EditResult> {
    return this.call('set_layout', { source, id, position });
  }

  /** Many positions in one edit; null removes one. */
  setLayouts(source: string, positions: Record<string, Position | null>): Promise<EditResult> {
    return this.call('set_layouts', { source, positions });
  }

  /** A person's sign-off on the whole model; null removes it. */
  setSignoff(source: string, signoff: Signoff | null): Promise<EditResult> {
    return this.call('set_signoff', { source, signoff });
  }

  /** The model as a Markdown report. */
  report(source: string): Promise<ReportResult> {
    return this.call('report', { source });
  }

  /** A valid, canonical starter model for a system with this name. */
  newModel(name: string): Promise<EditResult> {
    return this.call('new', { source: '', name });
  }

  /** allowAccept must only be true from the explicit human "Accept risk" form. */
  setStatus(source: string, status: StatusRequest, allowAccept = false): Promise<EditResult> {
    return this.call('set_status', { source, status, allow_accept: allowAccept });
  }

  suggest(source: string, target?: string): Promise<SuggestResult> {
    return this.call('suggest', target ? { source, target } : { source });
  }

  acceptSuggestion(source: string, from: string, target: string, fields?: Fields): Promise<EditResult> {
    return this.call('accept_suggestion', { source, from, target, ...(fields ? { fields } : {}) });
  }

  dismissSuggestion(source: string, from: string, target: string, reason: string): Promise<EditResult> {
    return this.call('dismiss_suggestion', { source, from, target, reason });
  }

  /** start: an access level ("anyone", "any-user", ...) or "controls:<component>". */
  paths(source: string, start: string, targets?: string[]): Promise<PathsResult> {
    return this.call('paths', { source, start, ...(targets?.length ? { targets } : {}) });
  }

  blastRadius(source: string, id: string): Promise<BlastResult> {
    return this.call('blast_radius', { source, id });
  }
}

export const core = new Core();
