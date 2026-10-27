# Model file format (v1 draft)

A threat model is one YAML file, `threatmodel.yaml` by default, kept in the repo it describes. See [examples/invoice-service.threatmodel.yaml](examples/invoice-service.threatmodel.yaml) for a full model.

## Design goals

- **Readable without tools.** A developer reviewing a PR should understand a change to the model just by reading the diff.
- **Easy for agents to edit correctly.** IDs are short, stable slugs. A JSON Schema is published. Every reference between items is checked.
- **Clean diffs.** Formatting is deterministic. The diagram's x/y positions live in a separate `layout:` section at the end, so dragging a box doesn't touch the threats.
- **Comment-preserving.** `threat fmt`, the web app and the MCP server all edit the YAML in place. They keep your comments and the order you wrote things in.

### Why YAML?

Developers already use it every day, it allows comments, and agents write it reliably. JSON has no comments and is noisy to diff. HCL and CUE add a language most devs don't know. TOML gets awkward with deeply nested lists. To avoid YAML's sharp edges, we use a **strict subset**:

- No anchors or aliases (`&`, `*`, `<<`), no custom tags, and one document per file. This rules out tricks like the "billion laughs" memory bomb.
- Values that YAML would otherwise silently turn into booleans or numbers, like `no`, `on` or `1.10`, must be quoted. `threat fmt` adds the quotes for you.
- Limits on file size, nesting depth and the number of items. See [security](security.md).

## Top-level structure

```yaml
# yaml-language-server: $schema=https://open-security-tooling.github.io/threat-model/schema/v1.json
version: 1          # format version (required)
system: {}          # what this model describes
data: []            # kinds of information worth protecting
zones: []           # areas with the same level of trust
actors: []          # kinds of people who use the system
identities: []      # service accounts, roles and keys components run as
components: []      # things you run, use or depend on
flows: []           # data moving between components
threats: []         # things someone could do that you don't want
mitigations: []     # concrete changes that reduce threats
catalogs: []        # extra threat libraries to suggest from (optional)
signoff: {}         # a security review of the whole model (optional)
layout: {}          # diagram positions, for tools only (optional)
```

Every item in a list has an `id`: lowercase letters, digits and dashes, unique across the whole file, such as `invoice-api` or `read-others-invoices`. All references use these IDs.

## `system`

```yaml
system:
  name: Invoice service
  description: Lets small businesses create, send and get paid for invoices.
  tenancy: multi                     # single | multi: customers share the system
  owners: ["@acme/billing-team"]     # who maintains this model
  links:
    - https://github.com/acme/invoices/blob/main/docs/architecture.md
```

## `data`

```yaml
data:
  - id: invoices
    name: Customer invoices
    sensitivity: confidential
    description: Names, addresses, line items and amounts.
```

| `sensitivity` | Meaning | Examples |
|---|---|---|
| `public` | Fine if anyone sees it | Marketing pages, published docs |
| `internal` | Not secret, but not for outsiders | Internal dashboards, feature flags |
| `confidential` | Would harm users or the business if leaked | Personal data, invoices, private repos |
| `secret` | Gives access to other things if leaked | Passwords, API keys, session tokens, signing keys |

Sensitivity feeds the *impact* suggestions. See [risk](risk.md).

## `zones`

```yaml
zones:
  - id: internet
    name: Public internet
    trust: untrusted       # untrusted | partial | trusted
  - id: aws-prod
    name: Production AWS account
    trust: trusted
    network: segmented     # open (default) | segmented
    egress: restricted     # open (default) | restricted
```

| Field | Means |
|---|---|
| `network: open` | A flat network: anything in the zone can reach anything else. This is the default, because it's the safe assumption. |
| `network: segmented` | Only the flows in the model are allowed, enforced by security groups, firewall rules or network policies. |
| `egress: open` | Components can connect anywhere on the internet. This is the default. |
| `egress: restricted` | Outbound traffic only goes to allowed destinations, through an egress firewall or proxy. |

The [simulation](simulation.md) uses these to work out how far one break-in spreads and whether stolen data can get out.

## `actors`

```yaml
actors:
  - id: customer
    name: Customer
    access: any-user       # see "who" in risk.md
  - id: support
    name: Support agent
    access: insider
```

## `identities`

What components run as: service accounts, cloud roles, groups and API keys, with what each is allowed to do.

```yaml
identities:
  - id: api-role
    name: Invoice API task role
    kind: role               # service-account | role | user-group | api-key | other
    can:
      - {do: read, on: db}
      - {do: write, on: db}
      - {do: invoke, on: pdf-renderer}
```

| `do` | On data, or a component's stored data | On a component |
|---|---|---|
| `read` | can read it | can read what it stores |
| `write` | can change it | can change what it stores |
| `admin` | can read and change it | full control, as if running code in it |
| `invoke` | | can call it |

A component links to its identity with `identity: api-role`. If that component is compromised, the attacker gets exactly these permissions, so be specific. The library flags identities with `admin` rights, identities shared by several components, and long-lived API keys.

## `components`

```yaml
components:
  - id: api
    name: Invoice API
    kind: service
    zone: aws-prod
    exposure: internet       # internet | internal | local
    tech: [go, postgres, aws-ecs]
    features: [login, password-reset, export]   # what it does, in plain words
    stores: [invoices]       # data this component keeps
    identity: api-role       # what it runs as
    encrypted_at_rest: true  # data it stores is encrypted on disk
    monitored: true          # security events are logged and alerted on
    patching: automated      # automated | scheduled | manual
    managed: true            # a managed service the provider runs and patches
    code:                    # where it lives, used to detect changes
      - "cmd/api/**"
      - "internal/invoice/**"
    reviewed: 2026-10-27     # when someone last checked its threats, or {on: 2026-10-27, by: "@alice"}
    considered:              # threat kinds checked and found not to apply, with why
      disrupt: Stateless, autoscaled behind the load balancer
    notes: Runs as 3 tasks behind an ALB.
```

| `kind` | Use for |
|---|---|
| `client` | Browsers, mobile apps, CLIs your users run |
| `service` | APIs, web servers, workers, functions |
| `gateway` | WAFs, load balancers, API gateways, CDNs, reverse proxies |
| `database` | SQL/NoSQL databases, search indexes |
| `storage` | Object or file storage (S3, GCS, disks) |
| `queue` | Message queues, event buses, streams |
| `cache` | Redis, Memcached, CDN caches |
| `identity` | Login providers, SSO, auth services |
| `third-party` | External APIs and SaaS you depend on |
| `pipeline` | CI/CD, build systems, deploy tooling |
| `ai` | LLMs, agents, model endpoints, vector stores |
| `other` | Anything else; describe it in `notes` |

`features` say what a component does, in plain words, so the library can suggest the threats that come with it: `login`, `signup`, `password-reset`, `mfa`, `oauth-login`, `sso`, `admin-panel`, `file-upload`, `inbound-webhooks`, `outbound-webhooks`, `search`, `export`, `payments`.

`tech` tags are free-form, but the threat library recognises common ones (`go`, `node`, `postgres`, `s3`, `github-actions`, `openai`, …) and uses them to suggest threats and fixes for your stack.

## `flows`

```yaml
flows:
  - id: browser-to-api
    from: browser
    to: api
    over: HTTPS            # protocol or transport, free-form
    carries: [invoices, session-token]
    auth: session-cookie   # none | session-cookie | bearer-token | api-key | mtls | iam | other
    encrypted: true        # encrypted in transit (TLS)
    notes: All endpoints under /api/v1.
```

Controls that are true or false (`encrypted`, `encrypted_at_rest`, `monitored`) can be left out, which means the model doesn't say. Unknown is treated differently from `false`: the library phrases its suggestions as "if it isn't encrypted" rather than claiming it isn't. If `encrypted` is left out, a flow `over` HTTPS, TLS, mTLS or SSH counts as encrypted.

When a client talks to a `gateway` that forwards to one service, library suggestions about that flow look through the gateway: the threat is to the service behind it.

A flow points the way the request goes, and responses are implied. If both sides start conversations, model two flows. The tool works out which flows **cross zones** from the components' zones.

## `threats`

```yaml
threats:
  - id: read-others-invoices
    title: A logged-in customer could read other customers' invoices by changing the invoice ID in the URL
    kind: leak                       # see concepts.md
    affects: [api]                   # component and/or flow IDs
    attack:
      - Sign up for a free account and create an invoice.
      - Open it and note the URL, e.g. /invoices/1042.
      - Change it to /invoices/1041 and load the page.
    who: any-user
    effort: trivial
    impact: high
    impact_note: Exposes names, addresses and amounts for every customer.
    gives:                           # what the attacker ends up with (optional, used by simulation)
      reads: [invoices]
    status: open                     # open | mitigated | accepted | not-applicable
    mitigations: [check-invoice-owner]
    from: catalog:web/object-level-access   # set when accepted from the library
    refs:                            # for security folks; never required
      stride: [information-disclosure]
      cwe: [CWE-639]
      owasp: ["API1:2023"]
```

- `title` is required and must read as a sentence in the form *who could do what by how*.
- `attack`, `who`, `effort` and `impact` are needed to calculate risk. If one is missing, the risk shows as "not assessed".
- `gives` is optional. It describes what a successful attack hands the attacker, which [simulation](simulation.md) uses to chain threats together:
  - `reads: [data…]`
  - `changes: [data…]`
  - `controls: [component…]`, meaning the attacker can run code or act as that component.
  - `access: <who-level>`, meaning the attacker now has, for example, `insider` access.
- `status: accepted` requires `accepted: {by, reason, until}`. After `until`, `threat check` fails.
- `status: not-applicable` requires a `reason`.

## `mitigations`

```yaml
mitigations:
  - id: check-invoice-owner
    title: Check the invoice belongs to the caller's account before returning it
    status: in-progress              # planned | in-progress | done
    owner: "@rahlenjakob"
    due: 2026-11-30                  # when it should be done by
    effect: eliminates               # or an object, see below
    evidence:
      - code: internal/invoice/handler.go#GetInvoice
      - test: internal/invoice/handler_test.go#TestGetInvoice_OtherAccount
      - link: https://github.com/acme/invoices/pull/231
```

`effect` says what the mitigation changes about each threat it's linked to:

```yaml
effect: eliminates                   # the threat is no longer possible
effect: {who: insider}             # now only someone with this access could do it
effect: {effort: hard}             # now much harder
effect: {impact: low}              # still possible, but less damaging
effect: detects                      # doesn't prevent it, but you'd find out (alerting, audit log)
```

The risk shown for a threat is the **residual** risk: its own values, overridden by the effects of linked mitigations that are `done`. The web app and `threat explain` show both, for example *"High → Low once 'Require login' is done"*.

`evidence` entries take the form `path` or `path#symbol`. `threat check` verifies the path exists and, if a symbol is given, that the file contains it. This is a plain text search for now, so it works in any language.

## `catalogs`

```yaml
catalogs:
  - builtin:web
  - builtin:ai
  - path: security/acme-threats.yaml   # your org's own library, see threat-library.md
```

If `catalogs` is omitted, all built-in catalogs are used.

## `signoff`

```yaml
signoff:
  by: "@alice"
  on: 2026-10-27
  note: Reviewed with the billing team before launch
```

A person's statement that the whole model was reviewed. `threat check --base` flags it as stale when the model changes after it. See [policy](policy.md).

## `layout`

```yaml
layout:
  internet: {x: 0, y: 0, w: 320, h: 400}   # zones get a size
  browser: {x: 40, y: 80}
  api: {x: 480, y: 80}
```

Only tools write this section, and agents should leave it alone. Components that aren't in `layout` get placed automatically by the web app.

## Computed values are never stored

Risk levels, zone crossings and "needs review" flags are **calculated**, never written to the file. Storing them would create a second source of truth that goes stale. To see them, use `threat show`, `threat explain`, the web app or MCP.

## Versioning

`version` is an integer. Additions that old tools can ignore keep the same version. Anything that breaks compatibility bumps it, and `threat migrate` rewrites old files.

## Large systems (later)

One file per system is the default. For big systems we plan `include:` to split a model across files, such as one per service, sharing `data` and `zones`. It's left out of v1 on purpose.
