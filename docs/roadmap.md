# Roadmap

Each milestone ends with something usable. The tool's own `threatmodel.yaml` is the first real user from M1 on.

## M0: Design (now)

These docs. Settle the [open questions](#open-questions) that block M1.

## M1: The file and the CLI

- Format v1 spec, JSON Schema published.
- `threat validate`, `threat fmt`, `threat show`, `threat explain`, `threat report` (Markdown).
- Comment-preserving edit engine, with golden tests and fuzzing.
- Risk tables, residual risk and explanation sentences.
- Basic `threat check`: references, evidence, expired acceptances, formatting.

*Done when* the tool's own threat model lives in `threatmodel.yaml` and CI runs `threat check` on it.

## M2: Agents and staying current

- `threat mcp` with the tools, resources and prompts in [agents.md](agents.md).
- `threat check --base` (code-change detection with git) and the GitHub Action with a PR comment.
- Threat library v0: `builtin:web`, `builtin:ai`, `builtin:supply-chain`, plus `threat suggest`.
- `threat init` with the agent instructions snippet.

*Done when* an agent can draft a model for a real repo from scratch, and keeps it current across PRs with no human editing the YAML.

## M3: Web app

- WASM core in a Worker, plus the JSON bridge.
- Diagram, threat cards, threats view, coverage view, YAML view, suggestions.
- Open and save with the File System Access API, download fallback, local autosave.
- Deployed to GitHub Pages. `threat serve` with live reload.

*Done when* someone new can go from an empty page to a useful model in about 10 minutes.

## M4: Simulation

- `threat paths`, blast radius, "which fix breaks the most paths", what-if toggles in the web app.
- `test:` evidence warnings for high and critical threats, plus the `write-attack-test` prompt.

## Later

- More catalogs: `mobile`, privacy (LINDDUN territory), payments, health.
- `red-team` agent prompt (experimental).
- Multi-file models (`include:`).
- Imports from OWASP Threat Dragon, Threagile and Gram.
- SARIF export, so open threats can show up in GitHub code scanning.
- Translations.

## Open questions

| # | Question | Leaning |
|---|---|---|
| 1 | **YAML library for comment-preserving edits.** | Decided (2026-10-27): `goccy/go-yaml` (zero dependencies). Proven by golden tests and fuzzing; see `internal/edit`. |
| 3 | **Automatic diagram layout.** ELK gives great results but is large. Dagre is smaller. | Start with dagre and revisit |
| 4 | **WASM size.** | Measured (2026-10-27): about 6.5 MB raw, 1.4 MB gzipped, starts in ~20 ms. Standard Go is fine; TinyGo not needed. |
| 5 | **Should the threat library live in its own repo** so the community can contribute without touching the tool? | Same repo until the format is stable, then split |
| 6 | **Are the risk tables right?** | Approved for the v1 draft (2026-10-27). Revisit with real models before v1 is frozen |
