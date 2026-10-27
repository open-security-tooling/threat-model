// Messages between the page and the core worker.

export type ToWorker =
  | { type: 'init'; wasmUrl: string; execUrl: string }
  | { type: 'call'; id: number; op: string; request: string };

export type FromWorker =
  | { type: 'ready'; version: string }
  | { type: 'fatal'; message: string }
  | { type: 'response'; id: number; response: string };
