// Local files: the File System Access API where the browser has it (so Save
// writes back in place), a plain download otherwise.
import { checkSize, type Backend, type Opened } from './backend';

// Parts of the File System Access API that aren't in TypeScript's DOM lib.
interface PickerOptions {
  types?: { description: string; accept: Record<string, string[]> }[];
  excludeAcceptAllOption?: boolean;
  suggestedName?: string;
  multiple?: boolean;
}
interface PermissionHandle {
  queryPermission?(opts: { mode: 'readwrite' }): Promise<PermissionState>;
  requestPermission?(opts: { mode: 'readwrite' }): Promise<PermissionState>;
}
interface PickerWindow {
  showOpenFilePicker?(opts?: PickerOptions): Promise<FileSystemFileHandle[]>;
  showSaveFilePicker?(opts?: PickerOptions): Promise<FileSystemFileHandle>;
}
interface HandleItem {
  getAsFileSystemHandle?(): Promise<FileSystemHandle | null>;
}

const pickerTypes = [{ description: 'Threat model (YAML)', accept: { 'text/yaml': ['.yaml', '.yml'] } }];

const picker = () => window as unknown as PickerWindow;

export const canPickFiles = () => typeof picker().showOpenFilePicker === 'function';
export const canSaveAs = () => typeof picker().showSaveFilePicker === 'function';

export class FileHandleBackend implements Backend {
  readonly kind = 'file';
  readonly savesInPlace = true;
  readonly writesThrough = false;
  constructor(readonly handle: FileSystemFileHandle) {}

  get name() {
    return this.handle.name;
  }

  async save(source: string) {
    const h = this.handle as FileSystemFileHandle & PermissionHandle;
    if (h.queryPermission && (await h.queryPermission({ mode: 'readwrite' })) !== 'granted') {
      if (h.requestPermission && (await h.requestPermission({ mode: 'readwrite' })) !== 'granted') {
        throw new Error('The browser did not allow writing to the file. Use Export → YAML to download a copy instead.');
      }
    }
    const w = await this.handle.createWritable();
    await w.write(source);
    await w.close();
  }
}

export class DownloadBackend implements Backend {
  readonly kind = 'download';
  readonly savesInPlace = false;
  readonly writesThrough = false;
  constructor(readonly name = 'threatmodel.yaml') {}

  async save(source: string) {
    download(this.name, source, 'text/yaml');
  }
}

export function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function readHandle(handle: FileSystemFileHandle): Promise<Opened> {
  const file = await handle.getFile();
  checkSize(file.size);
  return { source: await file.text(), backend: new FileHandleBackend(handle) };
}

/** Shows the native picker. Resolves null if the user cancels. */
export async function pickFile(): Promise<Opened | null> {
  const show = picker().showOpenFilePicker;
  if (!show) return null;
  let handles: FileSystemFileHandle[];
  try {
    handles = await show.call(window, { types: pickerTypes, multiple: false });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') return null;
    throw err;
  }
  const [handle] = handles;
  return handle ? readHandle(handle) : null;
}

/** Asks where to save a model that has no file yet. Resolves null if cancelled. */
export async function pickSaveTarget(suggestedName: string): Promise<FileSystemFileHandle | null> {
  const show = picker().showSaveFilePicker;
  if (!show) return null;
  try {
    return await show.call(window, { types: pickerTypes, suggestedName });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') return null;
    throw err;
  }
}

export async function openFile(file: File): Promise<Opened> {
  checkSize(file.size);
  return { source: await file.text(), backend: new DownloadBackend(file.name) };
}

/** Opens a dropped file, with a writable handle when the browser offers one. */
export async function openDropped(dt: DataTransfer): Promise<Opened | null> {
  // The DataTransfer is emptied once the drop handler returns, so take
  // everything from it before the first await.
  const file = dt.files[0];
  const item = dt.items[0];
  const getHandle = item?.kind === 'file' ? (item as DataTransferItem & HandleItem).getAsFileSystemHandle : undefined;
  const handlePromise = getHandle && item ? getHandle.call(item).catch(() => null) : null;
  if (handlePromise) {
    const handle = await handlePromise;
    if (handle && handle.kind === 'file') return readHandle(handle as FileSystemFileHandle);
  }
  return file ? openFile(file) : null;
}
