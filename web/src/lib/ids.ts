import type { Model } from '../core/types';

/** Turns a name into an ID the format accepts: lowercase words joined by dashes. */
export function slugify(name: string, fallback = 'item'): string {
  const slug = name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48)
    .replace(/-+$/, '');
  return slug || fallback;
}

/** All IDs in the model; they must be unique across every section. */
export function takenIds(m: Model | undefined): Set<string> {
  const ids = new Set<string>();
  if (!m) return ids;
  for (const list of [m.data, m.zones, m.actors, m.identities, m.components, m.flows, m.threats, m.mitigations]) {
    for (const item of list ?? []) ids.add(item.id);
  }
  return ids;
}

export function uniqueId(base: string, taken: Set<string>): string {
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) {
    const id = `${base}-${i}`;
    if (!taken.has(id)) return id;
  }
}

export const ID_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;
