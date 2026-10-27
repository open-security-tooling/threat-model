# threat-model

> **Status: early development.** The core, CLI, threat library and simulation work; the web app and MCP server are being built. The docs in [`docs/`](docs/) describe the full design. Expect the format to change before v1.

A threat modeling tool for developers. Describe your system in a plain file that lives in your repo. See it as a diagram in your browser. Get threats explained the way a senior engineer would explain them to you. Your coding agent can keep it all up to date.

## Why another threat modeling tool?

Most open-source threat modeling tools fall short in the same four ways:

| Problem | What we do instead |
|---|---|
| **They speak security, not dev.** STRIDE, CAPEC, MITRE ATT&CK and CWE come first. | Plain language by default: *"A logged-in customer could read other customers' invoices by changing the ID in the URL."* The security mappings are still there, one click away, for the people who need them. |
| **They don't explain the risk.** You get a label like "Information Disclosure, Severity 7.2" and no idea what it means for you. | Every threat comes with the attack, step by step, along with who could do it, how hard it is and what breaks. The risk level comes with a one-sentence reason: *"Critical, because anyone who signs up could do it in minutes, with no special skill; the impact is high: it exposes every customer's invoices."* |
| **They're hard to use.** Desktop-only apps, clunky editors, models locked in a database. | A zero-install web app (think Excalidraw, but for threat models) that runs entirely in your browser, plus a CLI. The file is the source of truth, and it's readable without either. |
| **They go stale.** You make a model once for a review, and it never matches the code again. | Built for agents and CI. The model links to code paths, and `threat check` flags threats that need another look when that code changes. An MCP server lets agents read and update the model safely. |

## How it works

```
                 threatmodel.yaml   ← lives in your repo, reviewed in PRs
                 ▲      ▲      ▲
       ┌─────────┘      │      └──────────┐
       │                │                 │
   Web app           threat CLI          threat mcp
 (browser, WASM)   (you, CI)       (your agents)
       │                │                 │
       └────────────────┴─────────────────┘
               one Go core: parse, validate,
             explain risk, suggest threats, check
```

- **One file.** `threatmodel.yaml` describes your components, how data flows between them, the threats and the fixes. It's designed to be pleasant to read and diff, and hard to get wrong. Editors autocomplete it through a published JSON Schema.
- **One core, three front ends.** The Go core does all the real work. It's compiled into the `threat` CLI and into WebAssembly for the web app, and it's exposed to agents through `threat mcp`. A model behaves the same everywhere.
- **Serverless web app.** It's hosted on GitHub Pages, and your model never leaves your machine. Open a file, edit the diagram, save it back. `threat serve` runs the same app locally with live reload, so you can watch the diagram change as your agent edits the file.

## A taste of the file

```yaml
# yaml-language-server: $schema=https://open-security-tooling.github.io/threat-model/schema/v1.json
version: 1
system:
  name: Invoice service

components:
  - id: api
    name: Invoice API
    kind: service
    exposure: internet
    code: ["internal/invoice/**"]

threats:
  - id: read-others-invoices
    title: A logged-in customer could read other customers' invoices by changing the invoice ID in the URL
    affects: [api]
    kind: leak
    attack:
      - Sign up for a free account and create an invoice.
      - Open it and note the URL, e.g. /invoices/1042.
      - Change it to /invoices/1041.
    who: any-user
    effort: trivial
    impact: high
    mitigations: [check-invoice-owner]

mitigations:
  - id: check-invoice-owner
    title: Check the invoice belongs to the caller's account before returning it
    status: in-progress
    effect: eliminates
    evidence:
      - test: internal/invoice/handler_test.go#TestGetInvoice_OtherAccount
```

```console
$ threat explain read-others-invoices
CRITICAL  A logged-in customer could read other customers' invoices by changing the invoice ID in the URL
   read-others-invoices · open · affects Invoice API

How it works
  1. Sign up for a free account and create an invoice.
  2. Open it and note the URL, e.g. /invoices/1042.
  3. Change it to /invoices/1041 and load the page.

Who could do it: anyone with an account, including free sign-ups
How hard: trivial (minutes, tools exist)
How bad: high. Exposes names, addresses and amounts for every customer.

Why this risk: Critical, because anyone who signs up could do it in minutes, with no special skill; the impact is high: Exposes names, addresses and amounts for every customer. Drops to low once the planned mitigations are done.

Fixes
  [~] Check the invoice belongs to the caller's account before returning or changing it (in-progress; critical → low once done: makes this impossible)
  [ ] Use random UUIDs for invoice IDs instead of sequential numbers (planned; critical → medium once done: it becomes much harder)
```

See the [full example](docs/examples/invoice-service.threatmodel.yaml).

## Design docs

| Doc | What's in it |
|---|---|
| [Principles](docs/principles.md) | The rules we use to make design decisions |
| [Concepts and language](docs/concepts.md) | The vocabulary: components, flows, zones, threats, risk, in dev terms |
| [Model file format](docs/model-format.md) | The `threatmodel.yaml` spec |
| [Risk](docs/risk.md) | How risk is scored and explained, without CVSS math |
| [Threat library](docs/threat-library.md) | Built-in threat suggestions and how to write them |
| [Simulation](docs/simulation.md) | Attack paths, blast radius, "which fix breaks the most paths", threats as tests |
| [Web app](docs/web-app.md) | UX design for the browser app |
| [Agents and staying up to date](docs/agents.md) | CLI, MCP server, CI checks, agent workflows |
| [Policy for security teams](docs/policy.md) | `.threat.yaml`: enforcement, approvers, sign-off, what `check` reports about model changes |
| [Architecture](docs/architecture.md) | Go core, WASM, CLI, repo layout, build and release |
| [Security](docs/security.md) | The tool's own threat model. Yes, we dogfood. |
| [Roadmap](docs/roadmap.md) | Milestones and open questions |

## Prior art

We're learning from these tools. Each gets parts of this right, but none of them puts developer language, explained risk and agent-maintained models together in one tool.

| Tool | What we borrow | Where we differ |
|---|---|---|
| [Gram](https://github.com/klarna-incubator/gram) (Klarna) | Suggestions from your tech stack, a review workflow for security champions, a diagram-first UX | Gram is a server app with a database, SSO and websockets, and models live in its database. We're serverless and file-based, and review happens in PRs. |
| [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) | A free, open, diagram-based tool | STRIDE- and LINDDUN-first vocabulary, and it doesn't explain risk |
| [Threagile](https://github.com/Threagile/threagile) | YAML models and risk rules, in Go | Very large models in security vocabulary, built for generating reports rather than everyday editing |
| [pytm](https://github.com/OWASP/pytm), [threatcl](https://github.com/threatcl/threatcl) | Models as code | No visual editing, and you need to know Python or HCL |
| Microsoft Threat Modeling Tool | The classic DFD and STRIDE workflow | Windows-only desktop app with its own file format |

## License

[Apache-2.0](LICENSE)
