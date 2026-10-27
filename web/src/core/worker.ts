// Runs the Go core (compiled to WebAssembly) off the main thread, so a
// hostile or huge model can't freeze the page and the UI can kill it.
import type { FromWorker, ToWorker } from './protocol';

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

interface ThreatCore {
  call(op: string, request: string): string;
  version: string;
}

interface WorkerScope {
  postMessage(message: FromWorker): void;
  addEventListener(type: 'message', listener: (e: MessageEvent<ToWorker>) => void): void;
  Go?: new () => GoRuntime;
  threatCore?: ThreatCore;
}

const scope = globalThis as unknown as WorkerScope;

async function instantiate(wasmUrl: string, go: GoRuntime): Promise<WebAssembly.Instance> {
  try {
    const { instance } = await WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject);
    return instance;
  } catch {
    // instantiateStreaming needs the application/wasm MIME type; some static
    // hosts don't send it.
    const bytes = await (await fetch(wasmUrl)).arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
    return instance;
  }
}

async function init(wasmUrl: string, execUrl: string): Promise<void> {
  // wasm_exec.js is Go's classic-script loader; importing it as a module
  // still runs it and defines globalThis.Go.
  await import(/* @vite-ignore */ execUrl);
  if (!scope.Go) throw new Error('wasm_exec.js did not define Go');
  const go = new scope.Go();
  const instance = await instantiate(wasmUrl, go);
  void go.run(instance);
  if (!scope.threatCore) throw new Error('core.wasm did not register threatCore');
  scope.postMessage({ type: 'ready', version: scope.threatCore.version });
}

scope.addEventListener('message', (e) => {
  const msg = e.data;
  if (msg.type === 'init') {
    init(msg.wasmUrl, msg.execUrl).catch((err: unknown) => {
      scope.postMessage({ type: 'fatal', message: err instanceof Error ? err.message : String(err) });
    });
    return;
  }
  let response: string;
  try {
    if (!scope.threatCore) throw new Error('The core is not loaded yet.');
    response = scope.threatCore.call(msg.op, msg.request);
  } catch (err) {
    response = JSON.stringify({ error: { message: `The core failed: ${err instanceof Error ? err.message : String(err)}` } });
  }
  scope.postMessage({ type: 'response', id: msg.id, response });
});
