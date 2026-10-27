// TypeScript mirrors of the JSON the Go core returns. Field names follow the
// Go struct tags in internal/model, internal/risk and internal/ops.

export type Severity = 'error' | 'warning';

export interface Diagnostic {
  severity: Severity;
  code: string;
  path?: string;
  line?: number;
  column?: number;
  message: string;
  hint?: string;
}

export interface System {
  name: string;
  description?: string;
  owners?: string[];
  links?: string[];
}

export interface DataItem {
  id: string;
  name: string;
  sensitivity: string;
  description?: string;
}

export interface Zone {
  id: string;
  name: string;
  trust: string;
  /** open (the default: a flat network) or segmented (only declared flows). */
  network?: string;
  /** open (the default) or restricted outbound internet access. */
  egress?: string;
}

export interface Permission {
  /** read | write | admin | invoke */
  do: string;
  /** A component or data ID. */
  on: string;
}

/** Something a component runs as: a service account, role, group or key. */
export interface Identity {
  id: string;
  name: string;
  kind: string;
  can?: Permission[];
  notes?: string;
}

export interface Actor {
  id: string;
  name: string;
  access?: string;
}

export interface Component {
  id: string;
  name: string;
  kind: string;
  zone?: string;
  exposure?: string;
  tech?: string[];
  stores?: string[];
  code?: string[];
  reviewed?: string;
  notes?: string;
  /** ID of the identity it runs as. */
  identity?: string;
  /** Unset means the model doesn't say. */
  encrypted_at_rest?: boolean;
  monitored?: boolean;
  /** automated | scheduled | manual */
  patching?: string;
  /** A managed service the provider runs and patches. */
  managed?: boolean;
  /** Who last reviewed it, when the file says (`reviewed: {on, by}`). */
  reviewed_by?: string;
  /** Threat kinds checked and found not to apply, with why. */
  considered?: Record<string, string>;
}

/** A person's statement that they reviewed the whole model. */
export interface Signoff {
  by: string;
  on: string;
  note?: string;
}

export interface Flow {
  id: string;
  from: string;
  to: string;
  over?: string;
  carries?: string[];
  auth?: string;
  notes?: string;
  /** Encrypted in transit; unset means the model doesn't say. */
  encrypted?: boolean;
}

export interface Gives {
  reads?: string[];
  changes?: string[];
  controls?: string[];
  access?: string;
}

export interface Acceptance {
  by: string;
  reason: string;
  until: string;
}

export interface RiskOverride {
  override: string;
  reason: string;
}

export type Refs = Record<string, string[]>;

export interface Threat {
  id: string;
  title: string;
  kind?: string;
  affects?: string[];
  attack?: string[];
  who?: string;
  effort?: string;
  impact?: string;
  impact_note?: string;
  gives?: Gives;
  status: string;
  mitigations?: string[];
  accepted?: Acceptance;
  reason?: string;
  risk?: RiskOverride;
  from?: string;
  refs?: Refs;
}

/** In JSON an effect is "eliminates", "detects", or a map of overrides. */
export type Effect = 'eliminates' | 'detects' | { who?: string; effort?: string; impact?: string };

export interface Evidence {
  type: string;
  target: string;
}

export interface Mitigation {
  id: string;
  title: string;
  status: string;
  owner?: string;
  /** When it should be done by (YYYY-MM-DD). */
  due?: string;
  effect?: Effect;
  evidence?: Evidence[];
  notes?: string;
}

export interface CatalogRef {
  builtin?: string;
  path?: string;
}

export interface Layout {
  x: number;
  y: number;
  w?: number;
  h?: number;
}

export interface Model {
  version: number;
  system: System;
  data?: DataItem[];
  zones?: Zone[];
  actors?: Actor[];
  identities?: Identity[];
  components?: Component[];
  flows?: Flow[];
  threats?: Threat[];
  mitigations?: Mitigation[];
  catalogs?: CatalogRef[];
  signoff?: Signoff;
  layout?: Record<string, Layout>;
}

export interface RiskInputs {
  who: string;
  effort: string;
  impact: string;
}

export interface RiskChange {
  mitigation: string;
  title: string;
  status: string;
  from: string;
  to: string;
  effect: string;
}

export interface Assessment {
  threat: string;
  assessed: boolean;
  inherent: RiskInputs;
  inherent_level?: string;
  /** Residual risk: after the mitigations that are done. */
  level?: string;
  /** Risk once every linked mitigation is done. */
  planned?: string;
  likelihood?: string;
  residual: RiskInputs;
  eliminated?: boolean;
  detected?: boolean;
  override?: boolean;
  why: string;
  changes?: RiskChange[];
}

export interface Summary {
  components: number;
  flows: number;
  threats: number;
  open: number;
  by_risk: Record<string, number>;
  mitigations: Record<string, number>;
  not_assessed: number;
}

export interface View {
  model: Model;
  diagnostics: Diagnostic[];
  risks: Record<string, Assessment>;
  crossings: string[];
  summary: Summary;
  lines: Record<string, number>;
  /** componentId -> threat kind -> threat IDs */
  coverage: Record<string, Record<string, string[]>>;
  /** Each flow's encryption in transit, inferred from HTTPS/TLS when the file doesn't say. */
  transit: Record<string, 'encrypted' | 'unencrypted' | 'unknown'>;
}

export interface ValidateResult {
  ok: boolean;
  errors: number;
  warnings: number;
  diagnostics: Diagnostic[];
  canonical: boolean;
}

export interface FormatResult {
  source: string;
  changed: boolean;
}

export interface ExplainResult {
  threat: Threat;
  risk: Assessment;
  mitigations: Mitigation[];
  affects: string[];
}

export interface EditResult {
  source: string;
  changed: boolean;
  created?: boolean;
  diagnostics: Diagnostic[];
}

export type Section = 'data' | 'zones' | 'actors' | 'identities' | 'components' | 'flows' | 'threats' | 'mitigations';

export interface Position {
  x: number;
  y: number;
  w?: number;
  h?: number;
}

export interface StatusRequest {
  id: string;
  status: string;
  reason?: string;
  accepted?: Acceptance;
}

/** Fields for upsert/set_system: patch semantics, null removes a field. */
export type Fields = Record<string, unknown>;

export interface Suggestion {
  /** catalog:<catalog>/<entry> */
  from: string;
  target: string;
  target_name: string;
  threat: Threat;
  mitigations: Mitigation[];
  advice?: Record<string, string>;
  why_it_matters: string;
  /** The risk the threat would have with its default answers. */
  level: string;
}

export interface SuggestResult {
  suggestions: Suggestion[];
}

export interface PathStep {
  threat?: string;
  title: string;
  effort?: string;
  gains: string[];
  /** Set for steps that follow from the model's structure, not a threat. */
  rule?: string;
}

export interface AttackPath {
  target: string;
  target_name: string;
  steps: PathStep[];
  weakest: string;
  /** How the data gets out. */
  exit: string;
  /** Nothing lets the data out, so the attacker can read it but not take it. */
  contained?: boolean;
}

export interface FixImpact {
  mitigation: string;
  title: string;
  status: string;
  /** Data the attacker could no longer reach at all. */
  breaks: string[];
  /** Data still reachable, but only through harder steps. */
  harder: string[];
}

export interface PathsResult {
  from: string;
  paths: AttackPath[];
  unreachable: string[];
  fixes: FixImpact[];
}

export interface BlastResult {
  component: string;
  reads: string[];
  changes: string[];
  controls: string[];
  /** Parts anyone on the internet could reach anyway. */
  already_reachable: string[];
  /** Display names for every ID above. */
  names: Record<string, string>;
  paths: AttackPath[];
}

export interface Request {
  source: string;
  section?: Section;
  id?: string;
  fields?: Fields;
  position?: Position | null;
  status?: StatusRequest;
  allow_accept?: boolean;
  from?: string;
  target?: string;
  reason?: string;
  start?: string;
  targets?: string[];
  /** set_layouts: positions by ID; null removes one. */
  positions?: Record<string, Position | null>;
  /** new: the system's name. */
  name?: string;
  /** set_signoff: null removes it. */
  signoff?: Signoff | null;
}

export interface OpResults {
  validate: ValidateResult;
  format: FormatResult;
  show: View;
  explain: ExplainResult;
  upsert: EditResult;
  delete: EditResult;
  set_system: EditResult;
  set_layout: EditResult;
  set_status: EditResult;
  suggest: SuggestResult;
  accept_suggestion: EditResult;
  dismiss_suggestion: EditResult;
  paths: PathsResult;
  blast_radius: BlastResult;
  set_layouts: EditResult;
  new: EditResult;
  report: ReportResult;
  set_signoff: EditResult;
}

export interface ReportResult {
  markdown: string;
}

export type Op = keyof OpResults;

/** An error from the core. The message is written to be shown as is. */
export class CoreError extends Error {
  readonly diagnostics: Diagnostic[];
  constructor(message: string, diagnostics: Diagnostic[] = []) {
    super(message);
    this.name = 'CoreError';
    this.diagnostics = diagnostics;
  }
}
