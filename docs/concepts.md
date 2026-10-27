# Concepts and language

This is the vocabulary of the tool. Each concept is something developers already know, under a name they'd use themselves.

## The system

| Concept | What it is | Classic term |
|---|---|---|
| **Component** | Something you run, use or depend on: a service, a database, a queue, a browser, a third-party API, your CI pipeline, an LLM. | process, data store, external entity |
| **Flow** | Data moving from one component to another, such as "the browser calls the API over HTTPS with a session cookie". | data flow |
| **Zone** | A group of components that trust each other the same way, such as "the public internet", "our AWS account" or "the customer's phone". A flow that **crosses zones** is where most attacks happen. | trust boundary |
| **Data** | The kinds of information worth protecting, with a sensitivity level: invoices, passwords, API keys, health records. | asset |
| **Actor** | A kind of person who uses the system: a customer, an admin, a support agent. Attackers are described by *what access they have*, not by a separate cast of villains. | external entity, threat actor |

## Controls already in place

Some protections aren't fixes for a single threat. They're facts about how the system is built, and they change which threats apply and how far an attack can go. The model records them where they live:

| Control | Where | Example |
|---|---|---|
| WAF, load balancer, API gateway, CDN | a component with `kind: gateway` | `edge`, in front of the API |
| Network segmentation | zone `network: segmented` | only the API can reach the database |
| Outbound traffic limits | zone `egress: restricted` | services can't connect to arbitrary internet hosts |
| Encryption in transit | flow `encrypted: true` | TLS between services |
| Encryption at rest | component `encrypted_at_rest: true` | encrypted database storage |
| Service accounts and roles | `identities:` plus component `identity:` | the API's role can read and write the database, nothing else |
| Logging and alerting | component `monitored: true` | sign-ins and bulk reads alert someone |
| Patching | component `patching: automated` | Dependabot merges security updates |

Leave a control out if you don't know, and the tool will treat it as unknown, not as missing. The threat library suggests threats where controls are missing or unknown, and the [simulation](simulation.md) uses segmentation, egress and identities to show how far a break-in spreads.

## Threats

A **threat** is something someone could do that you don't want them to do. It's always written from the attacker's side, as a sentence:

> **Who** could **do what** by **how**.
>
> *"A logged-in customer could read other customers' invoices by changing the invoice ID in the URL."*

Each threat has:

- **Attack:** the attack as a few concrete steps. If you can't write the steps, the threat probably isn't real yet.
- **Who:** the access someone needs. See [risk](risk.md).
- **Effort:** how hard it is.
- **Impact:** what breaks, and for whom, in user or business terms.
- **Status:** `open`, `mitigated`, `accepted` (a conscious decision, with a reason and an expiry date) or `not-applicable` (dismissed, with a reason).

### Kinds of threat

Every threat has a `kind`. The six core kinds are what security people call STRIDE, renamed after what actually happens:

| `kind` | In plain words | Example | STRIDE |
|---|---|---|---|
| `impersonate` | Pretending to be someone or something else | Logging in with a stolen session cookie | Spoofing |
| `tamper` | Changing data or code they shouldn't | Editing the price in a checkout request | Tampering |
| `cover-tracks` | Doing something and leaving no trace, or denying it later | Deleting records with no audit log | Repudiation |
| `leak` | Seeing data they shouldn't | Reading other customers' invoices | Information disclosure |
| `disrupt` | Breaking it or slowing it down | Uploading a 10 GB file to exhaust disk | Denial of service |
| `escalate` | Getting more access than they should have | A regular user calling an admin-only endpoint | Elevation of privilege |

There are also two kinds that STRIDE doesn't name well but devs run into constantly:

| `kind` | In plain words | Example |
|---|---|---|
| `abuse` | Using a feature exactly as built, but for harm | Using "invite a teammate" to send spam |
| `manipulate-ai` | Tricking an AI component into doing something it shouldn't | A README that tells your coding agent to leak secrets (prompt injection) |

The **coverage view** asks, for each component: *have we thought about each of these?* That's the core discipline of threat modeling, without the jargon.

## Mitigations

A **mitigation** is a concrete change that reduces a threat, written as something a developer can do:

- Good: *"Check the invoice belongs to the caller's account before returning it."*
- Too vague: *"Implement proper access control."*

Each mitigation has:

- **Status:** `planned`, `in-progress` or `done`.
- **Effect:** what it changes about the threat. It can make the threat impossible (`eliminates`), or change who can do it, how hard it is, or how bad it is. The tool recalculates the risk so you can see the difference. See [risk](risk.md).
- **Evidence:** where it lives in code or tests, so the tool can check it still exists.

One mitigation can address many threats, and one threat can need several mitigations.

## Keeping it honest

- **Code links.** Components list the code paths that implement them. When that code changes, the related threats are flagged for review.
- **Reviews.** Components carry a `reviewed` date. A threat model is a snapshot of what someone checked, and the date says when.
- **Accepted risks expire.** "We'll live with this" needs a who, a why and an until.
