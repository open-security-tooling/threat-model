# Threat library

A blank page is the hardest part of threat modeling. The library suggests threats based on what's in your model, written in the same plain language as everything else.

## How suggestions work

1. Library entries say **when they apply**, for example "a `service` with `exposure: internet` that `stores` `confidential` data".
2. As you build the model, the tool matches entries against your components, flows and zones.
3. Matching entries appear as **suggestions**: in the web app, in `threat suggest` and through MCP. Each one is already filled in with your component names.
4. You **accept** a suggestion, which adds it as a threat with `from: catalog:<id>` that you can then edit, or **dismiss** it with a reason. Dismissals are stored as `status: not-applicable` threats, so the same suggestion doesn't come back and a reviewer can see what was considered.

Suggestions never land in the model on their own.

## A library entry

```yaml
# catalogs/web.yaml
- id: object-level-access
  title: A logged-in user could read or change other users' {data} by changing an ID in a request to {component}
  kind: leak
  applies:
    component:
      kind: [service]
      exposure: [internet]
      stores: [confidential, secret]
  attack:
    - Sign up and create something of your own, such as one of the {data}.
    - Note the ID it has in the URL or request.
    - Repeat the request with a different ID and see whether someone else's record comes back.
  defaults: {who: any-user, effort: trivial, impact: high}
  gives:
    reads: ["{data}"]
  mitigations:
    - id: check-object-owner
      title: Check that each record belongs to the caller before returning or changing it
      effect: eliminates
      by_tech:
        go: Load records scoped to the caller, e.g. `WHERE id = $1 AND account_id = $2`, never by ID alone.
    - id: unguessable-ids
      title: Use random IDs (UUIDv4) instead of sequential numbers
      effect: {effort: hard}
  why_it_matters: >
    This is the most common way APIs leak data. It's easy to miss in code
    review because the endpoint works perfectly for the honest user.
  refs: {stride: [information-disclosure], cwe: [CWE-639], owasp: ["API1:2023"]}
```

### `applies`

An entry applies to exactly one of components, flows or identities:

```yaml
applies:
  component:
    kind: [service]                   # component kinds
    exposure: [internet]              # internet | internal | local
    tech: [postgres, mysql]           # the component's tech tags include any of these
    stores: [confidential, secret]    # it stores data with any of these sensitivities
    zone_trust: [trusted]             # trust of its zone
    zone_network: [open]              # open | segmented
    zone_egress: [open]               # open | restricted
    at_rest: [unencrypted, unknown]   # encrypted | unencrypted | unknown
    monitoring: [off, unknown]        # on | off | unknown
    patching: [manual, unknown]       # automated | scheduled | manual | unknown
    handles: [confidential]           # it stores, sends or receives data with any of these sensitivities
    features: [login, password-reset] # what it does, from the component's `features` list
    not_managed: true                 # skip managed services the provider patches
    identity_rights: [none, admin]    # its identity: none in the model, or has admin rights
    tenancy: [multi]                  # the system's tenancy: single | multi | unknown
```

`exposure` and `to_exposure` also accept `unknown`, for components that don't say.

When one set of conditions isn't enough, `applies` can be a list of alternatives, and the entry matches if any of them does:

```yaml
applies:
  - component: {kind: [identity]}
  - component: {kind: [service], features: [login]}
```

```yaml
applies:
  flow:
    crosses_zones: true               # source and destination are in different zones
    from_zone_trust: [untrusted]      # trust of the source's zone
    from_kind: [client]               # kind of the source component
    to_kind: [service]                # kind of the destination component
    auth: [none]                      # the flow's auth
    carries: [secret]                 # it carries data with any of these sensitivities
    to_exposure: [internet]           # exposure of the destination
    in_transit: [unencrypted, unknown] # encrypted | unencrypted | unknown
```

```yaml
applies:
  identity:
    kind: [api-key]                   # identity kinds
    can: [admin]                      # has any of these permissions
    shared: true                      # used by more than one component
```

For flows into a `gateway` that forwards to a single service, the destination's kind, exposure, tech and name are taken from the service behind the gateway.

Control states include `unknown` so an entry can apply when the model doesn't say. Phrase those titles conditionally, for example "…if the traffic isn't encrypted".

Every condition you write must hold. Within one condition, any of the listed values matches. Leave a condition out to match anything.

`stores` and `carries` take **sensitivity levels**, not data IDs, because a library can't know your model's IDs.

### Placeholders

Titles, attack steps and mitigation titles can use these, filled in from the model when the entry is suggested:

| Placeholder | Becomes |
|---|---|
| `{component}` | The component's name. For flow entries, the destination's name. |
| `{from}`, `{to}` | A flow's source and destination names |
| `{flow}` | A flow's ID |
| `{data}` | The name of the most sensitive data the component stores or the flow carries, or "data" if there is none |
| `{zone}` | The name of the component's zone |
| `{identity}` | The identity's name (identity entries) |

In `gives`, `"{data}"` becomes the target's data IDs, and `"{component}"` becomes the target component.

A YAML value can't start with `{`, because YAML would read it as a map. Rephrase the step instead, for example "Because {to} trusts the network, ..." rather than "{to} trusts the network".

## Built-in catalogs (initial set)

| Catalog | Covers |
|---|---|
| `builtin:web` | Access control, login and sessions, injection, file uploads, SSRF, CORS, open redirects. Roughly OWASP Top 10 and API Top 10 territory, in plain words. |
| `builtin:data` | Databases, backups, object storage, encryption, logging sensitive data. |
| `builtin:cloud` | Over-broad IAM, public buckets, metadata endpoints, leaked credentials. |
| `builtin:supply-chain` | Dependencies, CI/CD, build secrets, unpinned actions, release signing. |
| `builtin:ai` | Prompt injection, tool and agent over-reach, data exfiltration through model output, training-data leaks, cost exhaustion. |
| `builtin:network` | Going around a WAF or gateway, flat networks, unrestricted outbound traffic, exposed admin ports, gateway configuration, unencrypted traffic. |
| `builtin:identity` | Password reset and recovery, OAuth redirects and `state`, JWT checks, session fixation, MFA fallbacks, SAML validation, user enumeration, admin session length. |
| `builtin:saas` | Multi-tenant isolation: tenant IDs from requests, shared caches and indexes, background jobs, cross-tenant support tools, noisy neighbours, tenant deletion. Only applies with `system.tenancy: multi`. |
| `builtin:integrations` | Webhooks in and out, vendor API keys, trusting vendor responses, vendor outages. |
| `builtin:kubernetes` | Service account tokens, privileged containers, public cluster APIs, secrets in ConfigMaps, network policies, image pinning. |
| `builtin:mobile` | Secrets in app bundles, deep links, local storage, client-side authorization, certificate checks. |

Later: a privacy pack (LINDDUN territory, written in plain words) and regulated domains such as payments and health.

## Org and community catalogs

Teams can keep their own catalogs, for example *"every service handling card data must…"*, as YAML files in a repo and reference them from `catalogs:`. The format is the same as the built-ins, and so are the [writing rules](#writing-rules).

Built-in catalogs are embedded in the binary and versioned with it. When a library entry you accepted gets improved, `threat check` can point out that the wording changed upstream (`from:` links it). It never rewrites your threat.

## Writing rules

These apply to library entries and to any threat written by hand or by an agent. `threat lint` checks the mechanical ones.

1. **The title is a sentence: who could do what by how.** Use "A logged-in user could…", not "Broken access control".
2. **No unexplained acronyms.** If you need a term like SSRF, explain it in the same sentence: *"…make our server fetch internal URLs for them (SSRF)…"*.
3. **Attack steps are concrete and number six or fewer.** A junior developer should be able to follow them in a test environment.
4. **Impact is about people and the business**, not the CIA triad: *"Customers' home addresses are exposed"*, not *"Loss of confidentiality"*.
5. **Mitigations are actions in code or config**, scoped to the stack where possible. "Implement proper validation" is not a mitigation.
6. **Say why it matters,** in one or two sentences on why this is easy to get wrong.
7. **Security references go in `refs`,** never in the title or steps.

## Borrowed ideas

- **Gram** (Klarna) suggests threats and controls from a system's tech stack. That's the idea behind `tech` tags and `by_tech` advice here. Gram's suggestions come from server-side plugins. Ours are declarative YAML, so anyone can read and contribute them without writing code.
- **Threagile** runs risk rules over a YAML model. We keep the rules declarative and the output in plain language.
