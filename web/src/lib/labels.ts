// Plain-language labels for the format's enumerations (see docs/concepts.md
// and docs/risk.md). The file keeps the short IDs; the UI says what they mean.

export interface Option {
  value: string;
  label: string;
  hint?: string;
}

const opts = (entries: [string, string, string?][]): Option[] =>
  entries.map(([value, label, hint]) => (hint ? { value, label, hint } : { value, label }));

export const threatKinds = opts([
  ['impersonate', 'Pretend to be someone', 'Pretending to be someone or something else'],
  ['tamper', 'Change things', "Changing data or code they shouldn't"],
  ['cover-tracks', 'Leave no trace', 'Doing something and leaving no trace, or denying it later'],
  ['leak', 'See data', "Seeing data they shouldn't"],
  ['disrupt', 'Break it', 'Breaking it or slowing it down'],
  ['escalate', 'Get more access', 'Getting more access than they should have'],
  ['abuse', 'Misuse a feature', 'Using a feature exactly as built, but for harm'],
  ['manipulate-ai', 'Trick the AI', "Tricking an AI component into doing something it shouldn't"],
]);

export const componentKinds = opts([
  ['client', 'Client', 'A browser, mobile or desktop app'],
  ['service', 'Service', 'An API, backend or worker you run'],
  ['gateway', 'Gateway', 'A WAF, load balancer, API gateway, CDN or reverse proxy'],
  ['database', 'Database'],
  ['storage', 'File storage', 'A bucket or file share'],
  ['queue', 'Queue', 'A message queue or event bus'],
  ['cache', 'Cache'],
  ['identity', 'Login provider', 'Identity, SSO or auth service'],
  ['third-party', 'Third-party service', 'An API or SaaS someone else runs'],
  ['pipeline', 'CI/CD pipeline'],
  ['ai', 'AI / LLM'],
  ['other', 'Other'],
]);

export const who = opts([
  ['anyone', 'Anyone on the internet', 'No account needed'],
  ['any-user', 'Anyone with an account', 'Including free sign-ups'],
  ['insider', 'Someone on the inside', 'Employees, contractors, partners with access'],
  ['privileged', 'An admin', 'Admins, ops, people with production access'],
  ['physical', 'Someone holding the device', 'A stolen phone or laptop'],
]);

export const efforts = opts([
  ['trivial', 'Trivial', 'Copy-paste or point-and-click. Minutes.'],
  ['moderate', 'Moderate', 'Needs some skill, time or luck. Hours to days.'],
  ['hard', 'Hard', 'Needs rare access, deep expertise or many things to line up.'],
]);

export const impacts = opts([
  ['low', 'Low', 'Annoying, no real harm'],
  ['medium', 'Medium', 'Limited harm to some users, or a recoverable outage'],
  ['high', 'High', 'Serious harm to many users or the business'],
  ['critical', 'Critical', 'Everything is at stake'],
]);

export const threatStatuses = opts([
  ['open', 'Open', 'Not dealt with yet'],
  ['mitigated', 'Mitigated', 'Its fixes are in place'],
  ['accepted', 'Risk accepted', 'A conscious decision to live with it, until a date'],
  ['not-applicable', "Doesn't apply", 'Dismissed, with a reason'],
]);

export const mitigationStatuses = opts([
  ['planned', 'Planned'],
  ['in-progress', 'In progress'],
  ['done', 'Done'],
]);

export const sensitivities = opts([
  ['public', 'Public', 'Fine for anyone to see'],
  ['internal', 'Internal', 'Not secret, but not for the public'],
  ['confidential', 'Confidential', 'Customer or business data'],
  ['secret', 'Secret', 'Passwords, keys, tokens'],
]);

export const trusts = opts([
  ['untrusted', 'Untrusted', 'Like the public internet'],
  ['partial', 'Partly trusted', 'Like a vendor or CI system'],
  ['trusted', 'Trusted', 'Your own infrastructure'],
]);

export const networks = opts([
  ['open', 'Flat network', 'Anything in the zone can reach anything else'],
  ['segmented', 'Segmented', 'Only the flows in the model are allowed'],
]);

export const egress = opts([
  ['open', 'Open', 'Components can connect anywhere on the internet'],
  ['restricted', 'Restricted', 'Outbound traffic only to allowed destinations'],
]);

export const patching = opts([
  ['automated', 'Automated', 'Updates are applied automatically'],
  ['scheduled', 'Scheduled', 'Updates are applied on a regular schedule'],
  ['manual', 'Manual', 'Someone has to remember to update it'],
]);

export const identityKinds = opts([
  ['service-account', 'Service account'],
  ['role', 'Role', 'A cloud IAM role or similar'],
  ['user-group', 'User group'],
  ['api-key', 'API key'],
  ['other', 'Other'],
]);

export const permissions = opts([
  ['read', 'Read'],
  ['write', 'Write'],
  ['admin', 'Admin'],
  ['invoke', 'Invoke', 'Call or run it'],
]);

/** A yes/no that the model may not answer: unset means "don't know". */
export function yesNo(v: boolean | undefined): string {
  return v === true ? 'Yes' : v === false ? 'No' : 'Not said';
}

export const exposures = opts([
  ['internet', 'Reachable from the internet'],
  ['internal', 'Internal only'],
  ['local', 'Local only'],
]);

export const flowAuths = opts([
  ['none', 'None'],
  ['session-cookie', 'Session cookie'],
  ['bearer-token', 'Bearer token'],
  ['api-key', 'API key'],
  ['mtls', 'Mutual TLS'],
  ['iam', 'Cloud IAM role'],
  ['other', 'Other'],
]);

export const riskLevels = ['low', 'medium', 'high', 'critical'] as const;

export function riskRank(level: string | undefined): number {
  return level ? riskLevels.indexOf(level as (typeof riskLevels)[number]) : -1;
}

export function label(options: Option[], value: string | undefined): string {
  if (!value) return '';
  return options.find((o) => o.value === value)?.label ?? value;
}

export function hint(options: Option[], value: string | undefined): string {
  if (!value) return '';
  return options.find((o) => o.value === value)?.hint ?? '';
}

export function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

export function riskLabel(level: string | undefined): string {
  return level ? capitalize(level) : 'Not assessed';
}
