# Principles

Use these to settle design arguments. When two principles conflict, the one higher on the list wins.

## 1. Secure by default, including the tool itself

A threat model is a map of your weak spots. Treat it as sensitive data.

- The model never leaves your machine unless you move it. No server, no accounts, no telemetry, and no third-party scripts in the web app.
- Treat every model file as untrusted input, because models arrive in pull requests from strangers. Parsing, rendering and the MCP server all assume a file could be malicious.
- See [security.md](security.md).

## 2. Plain language first, security jargon on request

Write for a developer who has never heard of STRIDE.

- Threats are sentences about what *someone could do*: *"A logged-in customer could read other customers' invoices…"*. Don't use labels like *"IDOR"* or *"Information Disclosure"*.
- Every term we introduce gets explained where it's used. If a dev needs a glossary to read a threat, rewrite the threat.
- STRIDE, CWE, CAPEC, OWASP and ATT&CK mappings are first-class *metadata*. Security teams and auditors can see them and filter on them, but they never stand in for an explanation.

## 3. Explain, don't just score

A number without a reason is noise.

- Every risk level comes with a one-sentence *why*, generated from the inputs: who could do it, how hard it is, what's at stake.
- Every threat says *how* the attack works in a few concrete steps.
- Every mitigation says *what changes* when it's done, for example "only logged-in users could do this now", and the risk is recalculated to show it.

## 4. The file is the product

The web app, CLI and MCP server are all views of one file.

- `threatmodel.yaml` must be readable and editable with no tool installed.
- It must diff cleanly in a PR: stable IDs, deterministic formatting, and diagram layout kept separate from meaning.
- Tools must preserve the comments and ordering you wrote. A tool rewriting your file in its own style breaks trust.

## 5. Built to be kept up to date

A stale threat model is worse than none, because it gives false confidence.

- The model links to code, so the tool can tell when reality moved.
- CI can check the model: broken references, missing evidence, expired risk acceptances, threats affected by a change.
- Agents are first-class users, so every operation a human can do, an agent can do through the CLI (`--json`) or MCP.

## 6. Suggest, never decide

The tool proposes threats from a library. A human or agent accepts them, adapts them or dismisses them with a reason. The model only contains things someone chose to put there, so nothing in it is auto-generated noise.

## 7. Small and boring underneath

- One Go core shared by every front end, so behavior can't drift between them.
- Few dependencies, all pinned. Every dependency is a supply-chain risk in a security tool.
- Formats and APIs are versioned from day one.
