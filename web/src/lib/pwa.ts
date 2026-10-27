// Offline install, and the "new version ready" prompt. Not used under
// `threat serve`: that's a local server on a random port per run, so a
// worker there would only leave caches behind.
import { Store } from './store';

class Pwa extends Store {
  /** A new version is installed and waiting for open tabs to let go. */
  updateReady = false;
  private registration: ServiceWorkerRegistration | null = null;

  register() {
    if (!import.meta.env.PROD || !('serviceWorker' in navigator)) return;
    navigator.serviceWorker
      .register(new URL('sw.js', document.baseURI), { scope: './' })
      .then((reg) => {
        this.registration = reg;
        // Only an update if a worker already controls this page; the first install isn't one.
        const check = () => {
          if (reg.waiting && navigator.serviceWorker.controller) this.setReady();
        };
        check();
        reg.addEventListener('updatefound', () => {
          const w = reg.installing;
          w?.addEventListener('statechange', () => w.state === 'installed' && check());
        });
        // Look for a new version when the tab comes back into view.
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible') reg.update().catch(() => undefined);
        });
      })
      .catch(() => {
        // Offline use is a convenience; the app works without it.
      });
  }

  private setReady() {
    if (this.updateReady) return;
    this.updateReady = true;
    this.emit();
  }

  /** Activates the waiting version and reloads once it has taken over. */
  reload() {
    const waiting = this.registration?.waiting;
    if (!waiting) {
      location.reload();
      return;
    }
    navigator.serviceWorker.addEventListener('controllerchange', () => location.reload(), { once: true });
    waiting.postMessage({ type: 'skip-waiting' });
  }

  dismiss() {
    this.updateReady = false;
    this.emit();
  }
}

export const pwa = new Pwa();
