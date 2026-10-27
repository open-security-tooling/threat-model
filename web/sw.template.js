// Service worker for offline use. It only ever serves the app's own files
// (listed at build time) and never stores anything else: model files are
// opened locally and never fetched, and `threat serve`'s api/ is never
// touched, so no model content or API response can end up in a cache.
const VERSION = '__VERSION__';
const CACHE = `threat-model-${VERSION}`;
const FILES = __FILES__;

const scope = new URL(self.registration.scope);
const apiPrefix = new URL('api/', scope).pathname;
const shell = new Set(FILES.map((f) => new URL(f, scope).href));
const indexUrl = new URL('index.html', scope).href;

self.addEventListener('install', (event) => {
  // cache: 'reload' skips the HTTP cache so a new version gets fresh files.
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES.map((f) => new Request(new URL(f, scope), { cache: 'reload' })))));
  // No skipWaiting() here: open tabs keep the version (and lazy chunks) they
  // started with until the person chooses to reload (see the message below).
});

self.addEventListener('message', (event) => {
  // Sent by the page's "Reload" button in the "new version ready" prompt.
  if (event.data && event.data.type === 'skip-waiting') self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('threat-model-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== scope.origin) return;
  if (url.pathname.startsWith(apiPrefix)) return;
  if (req.mode === 'navigate') {
    // Network first, so a new deploy is picked up; the cached shell when offline.
    event.respondWith(fetch(req).catch(() => caches.match(indexUrl).then((r) => r ?? Response.error())));
    return;
  }
  const key = url.origin + url.pathname;
  // Anything that isn't part of the app goes straight to the network, uncached.
  if (!shell.has(key)) return;
  event.respondWith(caches.match(key).then((hit) => hit ?? fetch(req)));
});
