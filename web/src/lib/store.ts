import { useSyncExternalStore } from 'react';

/** A minimal observable: subclasses call emit() after changing their fields. */
export class Store {
  private listeners = new Set<() => void>();
  private version = 0;

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => void this.listeners.delete(fn);
  };

  getVersion = () => this.version;

  protected emit() {
    this.version++;
    for (const fn of this.listeners) fn();
  }
}

/** Re-renders the calling component whenever the store changes. */
export function useStore<S extends Store>(store: S): S {
  useSyncExternalStore(store.subscribe, store.getVersion);
  return store;
}
