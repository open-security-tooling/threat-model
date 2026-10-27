// `threat serve`: the file stays on disk and the server is the source of
// truth. The per-run token arrives in the URL fragment, which browsers never
// send to servers; it's kept in memory only and stripped from the address bar.
import { checkSize, ConflictError, type Backend, type Opened, type WatchStatus } from './backend';

/** Reads `#token=...` and removes it from the visible URL. */
export function takeServeToken(): string | null {
  const hash = window.location.hash.replace(/^#/, '');
  if (!hash) return null;
  const params = new URLSearchParams(hash);
  const token = params.get('token');
  if (!token) return null;
  try {
    history.replaceState(null, '', window.location.pathname + window.location.search);
  } catch {
    window.location.hash = '';
  }
  return token;
}

interface FileResponse {
  source: string;
  name?: string;
  /** Identifies a version of the file's content. */
  revision?: string;
}

function isFileResponse(v: unknown): v is FileResponse {
  return typeof v === 'object' && v !== null && typeof (v as FileResponse).source === 'string';
}

async function errorText(res: Response): Promise<string> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object' && 'error' in body) {
      const e = (body as { error: unknown }).error;
      if (typeof e === 'string') return e;
      if (e && typeof e === 'object' && typeof (e as { message?: unknown }).message === 'string') return (e as { message: string }).message;
    }
  } catch {
    // Not JSON.
  }
  return `The local server answered ${res.status} ${res.statusText}.`;
}

export class ServerBackend implements Backend {
  readonly kind = 'server';
  readonly savesInPlace = true;
  readonly writesThrough = true;
  name = 'threatmodel.yaml';
  /** The version of the file the app's source is based on. */
  private revision = '';

  constructor(private readonly token: string) {}

  private headers(extra: Record<string, string> = {}) {
    return { Authorization: `Bearer ${this.token}`, ...extra };
  }

  async open(): Promise<Opened> {
    const res = await fetch('api/file', { headers: this.headers(), cache: 'no-store' });
    if (!res.ok) throw new Error(await errorText(res));
    const body: unknown = await res.json();
    if (!isFileResponse(body)) throw new Error('The local server sent an unexpected response.');
    checkSize(body.source.length);
    if (body.name) this.name = body.name;
    this.revision = body.revision ?? '';
    return { source: body.source, backend: this };
  }

  async save(source: string): Promise<string | void> {
    const res = await fetch('api/file', {
      method: 'PUT',
      headers: this.headers({ 'Content-Type': 'application/json' }),
      // base_revision lets the server refuse the write if the file changed
      // on disk since this source was based on it.
      body: JSON.stringify(this.revision ? { source, base_revision: this.revision } : { source }),
      cache: 'no-store',
    });
    if (res.status === 409) {
      const body: unknown = await res.clone().json().catch(() => null);
      const message = await errorText(res);
      if (!isFileResponse(body)) throw new Error(message);
      this.revision = body.revision ?? '';
      throw new ConflictError(message, body.source);
    }
    if (!res.ok) throw new Error(await errorText(res));
    const body: unknown = await res.json();
    if (!isFileResponse(body)) return;
    if (body.revision) this.revision = body.revision;
    if (body.source !== source) return body.source;
  }

  watch(onChange: (source: string) => boolean, onStatus: (status: WatchStatus) => void): () => void {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry = 500;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      onStatus('connecting');
      const url = new URL(`api/watch?token=${encodeURIComponent(this.token)}`, document.baseURI);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      try {
        ws = new WebSocket(url);
      } catch {
        schedule();
        return;
      }
      ws.addEventListener('open', () => {
        retry = 500;
        onStatus('live');
      });
      ws.addEventListener('message', (e) => {
        if (typeof e.data !== 'string') return;
        try {
          const msg: unknown = JSON.parse(e.data);
          if (!isFileResponse(msg)) return;
          // The server pushes the current file on connect and after our own
          // writes; a revision we already have is nothing new.
          if (msg.revision && msg.revision === this.revision) return;
          if (onChange(msg.source) && msg.revision) this.revision = msg.revision;
        } catch {
          // Ignore anything that isn't a file update.
        }
      });
      ws.addEventListener('close', () => {
        ws = null;
        if (!closed) schedule();
      });
    };
    const schedule = () => {
      onStatus('offline');
      timer = setTimeout(connect, retry);
      retry = Math.min(retry * 2, 10_000);
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      ws?.close();
    };
  }
}
