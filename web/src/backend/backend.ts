// Where the model file lives. The UI only talks to this interface, so a
// local file and a `threat serve` session share every screen.

export interface Backend {
  readonly kind: 'file' | 'download' | 'server';
  /** File name shown in the UI. */
  readonly name: string;
  /** True when save() writes back to the file the model came from. */
  readonly savesInPlace: boolean;
  /** True when every change should be written straight away (live sync). */
  readonly writesThrough: boolean;
  /** Writes the source. Returns the backend's copy if it differs. */
  save(source: string): Promise<string | void>;
  /**
   * Subscribes to changes made outside the app. onChange returns whether the
   * app took the change; a change it skipped stays unacknowledged, so a
   * later save is checked against it. Returns an unsubscribe.
   */
  watch?(onChange: (source: string) => boolean, onStatus: (status: WatchStatus) => void): () => void;
}

/** The file changed elsewhere since the version an edit was based on. */
export class ConflictError extends Error {
  constructor(
    message: string,
    /** The file as it is now. */
    readonly source: string,
  ) {
    super(message);
    this.name = 'ConflictError';
  }
}

export type WatchStatus = 'connecting' | 'live' | 'offline';

export interface Opened {
  source: string;
  backend: Backend;
}

/** Files bigger than this are refused before reading; the core's limit is 5 MiB. */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

export class FileTooLargeError extends Error {
  constructor(size: number) {
    super(`That file is ${(size / 1024 / 1024).toFixed(1)} MB. Threat model files can be at most 5 MB.`);
  }
}

export function checkSize(size: number) {
  if (size > MAX_FILE_BYTES) throw new FileTooLargeError(size);
}
