// Browser storage. Everything here can fail (private windows, blocked site
// data, quota), so every call is wrapped and the app works without it.

const DB_NAME = 'threat-model';
const STORE = 'autosave';
const KEY = 'current';
const PREFIX = 'threat-model:';

export interface Draft {
  source: string;
  name: string;
  savedAt: number;
  /** Kept so Save can write back to the same file after a reload (Chromium). */
  handle?: FileSystemFileHandle;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB unavailable'));
    req.onblocked = () => reject(new Error('IndexedDB blocked'));
  });
}

async function withStore<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB error'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB aborted'));
    });
  } finally {
    db.close();
  }
}

function isDraft(v: unknown): v is Draft {
  return typeof v === 'object' && v !== null && typeof (v as Draft).source === 'string' && typeof (v as Draft).name === 'string';
}

export async function loadDraft(): Promise<Draft | null> {
  try {
    const v = await withStore<unknown>('readonly', (s) => s.get(KEY));
    return isDraft(v) ? v : null;
  } catch {
    return null;
  }
}

/** Returns false if the browser refused to store it. */
export async function saveDraft(draft: Draft): Promise<boolean> {
  try {
    await withStore('readwrite', (s) => s.put(draft, KEY));
    return true;
  } catch {
    if (draft.handle) {
      // Some browsers can't store file handles; keep the text at least.
      try {
        await withStore('readwrite', (s) => s.put({ ...draft, handle: undefined }, KEY));
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }
}

/** Deletes everything the app has stored in this browser. */
export async function clearAll(): Promise<boolean> {
  let ok = true;
  try {
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error ?? new Error('delete failed'));
      // Another tab holds the database open; it's deleted once that closes.
      req.onblocked = () => resolve();
    });
  } catch {
    ok = false;
  }
  return ok;
}

export function getPref(key: string): string | null {
  try {
    return localStorage.getItem(PREFIX + key);
  } catch {
    return null;
  }
}

export function setPref(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(PREFIX + key);
    else localStorage.setItem(PREFIX + key, value);
  } catch {
    // Preferences are a convenience; ignore.
  }
}
