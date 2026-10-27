// Builds a first model from the guided start's answers, entirely through
// core ops (starting from `new`), so the app writes no YAML of its own.
import { core } from '../core/client';
import type { Fields, Section } from '../core/types';
import { slugify, uniqueId } from './ids';

export interface PieceTile {
  key: string;
  name: string;
  kind: string;
  /** Pieces in your own infrastructure can be internet-facing. */
  canExpose: boolean;
}

export const pieceTiles: PieceTile[] = [
  { key: 'web', name: 'Web app', kind: 'client', canExpose: false },
  { key: 'mobile', name: 'Mobile app', kind: 'client', canExpose: false },
  { key: 'gateway', name: 'WAF / load balancer', kind: 'gateway', canExpose: true },
  { key: 'api', name: 'API', kind: 'service', canExpose: true },
  { key: 'worker', name: 'Background worker', kind: 'service', canExpose: false },
  { key: 'db', name: 'Database', kind: 'database', canExpose: true },
  { key: 'storage', name: 'File storage', kind: 'storage', canExpose: true },
  { key: 'queue', name: 'Queue', kind: 'queue', canExpose: false },
  { key: 'cache', name: 'Cache', kind: 'cache', canExpose: false },
  { key: 'idp', name: 'Login provider', kind: 'identity', canExpose: false },
  { key: 'third', name: 'Third-party API', kind: 'third-party', canExpose: false },
  { key: 'llm', name: 'LLM', kind: 'ai', canExpose: false },
  { key: 'ci', name: 'CI/CD', kind: 'pipeline', canExpose: false },
];

export interface ActorTile {
  key: string;
  name: string;
  access: string;
}

export const actorTiles: ActorTile[] = [
  { key: 'customers', name: 'Customers', access: 'any-user' },
  { key: 'admins', name: 'Admins', access: 'privileged' },
  { key: 'support', name: 'Support staff', access: 'insider' },
  { key: 'partners', name: 'Partners', access: 'insider' },
];

export interface DataTile {
  key: string;
  name: string;
  sensitivity: string;
}

export const dataTiles: DataTile[] = [
  { key: 'passwords', name: 'Passwords', sensitivity: 'secret' },
  { key: 'personal', name: 'Personal data', sensitivity: 'confidential' },
  { key: 'payment', name: 'Payment data', sensitivity: 'confidential' },
  { key: 'api-keys', name: 'API keys', sensitivity: 'secret' },
  { key: 'sessions', name: 'Session tokens', sensitivity: 'secret' },
];

export interface Answers {
  name: string;
  description: string;
  actors: string[];
  pieces: string[];
  internet: string[];
  data: string[];
}

type Op = { section: Section; id: string; fields: Fields };

const zoneFor = (p: PieceTile) =>
  p.kind === 'client' ? 'internet' : p.kind === 'pipeline' ? 'ci' : ['third-party', 'ai', 'identity'].includes(p.kind) ? 'vendors' : 'infra';

const zones: Record<string, Fields> = {
  internet: { name: 'Public internet', trust: 'untrusted' },
  infra: { name: 'Your infrastructure', trust: 'trusted' },
  vendors: { name: 'Third-party services', trust: 'partial' },
  ci: { name: 'CI/CD', trust: 'partial' },
};

function plan(a: Answers): Op[] {
  const ops: Op[] = [];
  const taken = new Set<string>();
  const id = (name: string) => {
    const v = uniqueId(slugify(name), taken);
    taken.add(v);
    return v;
  };

  const dataIds = new Map<string, string>();
  for (const t of dataTiles.filter((t) => a.data.includes(t.key))) {
    const did = id(t.name);
    dataIds.set(t.key, did);
    ops.push({ section: 'data', id: did, fields: { name: t.name, sensitivity: t.sensitivity } });
  }

  const pieces = pieceTiles.filter((p) => a.pieces.includes(p.key));
  const usedZones: string[] = [...new Set(pieces.map(zoneFor))];
  for (const z of Object.keys(zones).filter((z) => usedZones.includes(z))) {
    taken.add(z);
    ops.push({ section: 'zones', id: z, fields: zones[z]! });
  }

  for (const t of actorTiles.filter((t) => a.actors.includes(t.key))) {
    ops.push({ section: 'actors', id: id(t.name), fields: { name: t.name, access: t.access } });
  }

  const compIds = new Map<string, string>();
  for (const p of pieces) {
    const cid = id(p.name);
    compIds.set(p.key, cid);
  }
  const has = (k: string) => compIds.has(k);
  const d = (...keys: string[]) => keys.map((k) => dataIds.get(k)).filter((x): x is string => !!x);
  const stores: Record<string, string[]> = {
    db: d('personal', 'passwords', 'payment'),
    storage: d('personal'),
    api: has('db') ? [] : d('personal', 'passwords'),
    idp: has('idp') ? d('passwords') : [],
    ci: d('api-keys'),
  };
  if (has('idp')) stores.db = d('personal', 'payment');
  for (const p of pieces) {
    const z = zoneFor(p);
    const fields: Fields = { name: p.name, kind: p.kind, zone: z };
    if (z === 'infra') fields.exposure = a.internet.includes(p.key) ? 'internet' : 'internal';
    const s = stores[p.key];
    if (s?.length) fields.stores = s;
    ops.push({ section: 'components', id: compIds.get(p.key)!, fields });
  }

  // A plausible first set of arrows; easy to change on the diagram.
  const hub = ['api', 'worker'].find(has);
  const flows: [string, string, string, string[]][] = [];
  // Clients come in through the gateway when there is one.
  const entry = has('gateway') ? 'gateway' : hub;
  const fromClients = d('sessions', 'personal', ...(has('idp') ? [] : ['passwords']));
  if (entry) for (const c of ['web', 'mobile']) if (has(c)) flows.push([c, entry, 'HTTPS', fromClients]);
  if (hub && has('gateway')) flows.push(['gateway', hub, 'HTTPS', fromClients]);
  if (hub) {
    for (const c of ['db', 'cache', 'storage', 'queue']) if (has(c)) flows.push([hub, c, '', c === 'db' ? d('personal', 'payment') : []]);
    if (has('third')) flows.push([hub, 'third', 'HTTPS', d('api-keys', 'payment')]);
    if (has('llm')) flows.push([hub, 'llm', 'HTTPS', d('personal')]);
    if (has('idp')) flows.push([hub, 'idp', 'HTTPS', d('sessions')]);
    if (has('ci')) flows.push(['ci', hub, 'Deploy', []]);
    if (hub === 'api' && has('worker') && has('queue')) flows.push(['queue', 'worker', '', []]);
  }
  for (const [from, to, over, carries] of flows) {
    const f = compIds.get(from)!;
    const t = compIds.get(to)!;
    const fields: Fields = { from: f, to: t };
    if (over) fields.over = over;
    if (carries.length) fields.carries = [...new Set(carries)];
    ops.push({ section: 'flows', id: id(`${f}-to-${t}`), fields });
  }
  return ops;
}

export async function buildModel(a: Answers): Promise<string> {
  let source = (await core.newModel(a.name.trim() || 'My system')).source;
  if (a.description.trim()) source = (await core.setSystem(source, { description: a.description.trim() })).source;
  const ops = plan(a);
  if (!ops.some((op) => op.section === 'components')) {
    // Nothing picked: keep the starter's example pieces as a first diagram.
    for (const op of ops) source = (await core.upsert(source, op.section, op.id, op.fields)).source;
    return source;
  }
  // Swap the starter's example pieces for the ones picked. Additions come
  // first (a picked ID that matches a starter item, like `api`, just patches
  // it): appending to a section the deletes have emptied fails in the core.
  const starter = (await core.show(source)).model;
  for (const op of ops) source = (await core.upsert(source, op.section, op.id, op.fields)).source;
  const kept = new Set(ops.map((op) => op.id));
  // Referrers go first, since the core won't delete anything still referenced.
  const sections: [Section, { id: string }[] | undefined][] = [
    ['flows', starter.flows],
    ['components', starter.components],
    ['data', starter.data],
    ['zones', starter.zones],
    ['actors', starter.actors],
  ];
  for (const [section, items] of sections) {
    for (const item of items ?? []) if (!kept.has(item.id)) source = (await core.delete(source, section, item.id)).source;
  }
  return source;
}
