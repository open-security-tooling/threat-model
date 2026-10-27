# threat-model

A developer-friendly threat modeling tool: Go core + `threat` CLI, MCP server, and a React web app running the core as WASM. Design docs in `docs/`; the file format is `docs/model-format.md`.

## Layout

- `internal/model`: types, strict-YAML parsing, validation, JSON Schema. The schema table in `schema.go` is the single source of truth for the format.
- `internal/edit`: comment-preserving edits and canonical formatting (`threat fmt`).
- `internal/ops`: the contract every front end calls (including the Markdown report). New features go here first, then into the CLI, MCP and the WASM bridge (`ops.Call`).
- `internal/risk`, `internal/catalog` (+ `catalogs/*.yaml`), `internal/sim`, `internal/check`, `internal/mcp`, `internal/serve`.
- `web/`: React + TypeScript + Vite. It never parses or edits YAML itself; it calls the WASM core.
- `threatmodel.yaml`: this tool's own threat model. Keep it current; CI runs `threat check` on it.

## Commands

- `make test` (vet + tests), `make fuzz`, `make build`, `make wasm`, `make web`
- `make release-preview` shows the next version and notes; `make release` tags it (signed) from an up-to-date `main`
- After changing the schema table: `go run ./cmd/threat schema > schema/v1.json` (a test enforces it)

## Rules

- Security-first: model files are untrusted input (they arrive in PRs). Never follow paths outside the repo, never render model text as HTML, keep parse limits.
- Dependencies: stdlib first. Any new module or npm package needs a reason; pin exact versions.
- User-facing text is plain developer language: "who could do what by how", no unexplained acronyms. Errors say what's wrong and how to fix it.
- Tests that create git repos must isolate git config (see `isolatedGit` in `internal/check/check_test.go`). The maintainer's global config signs every commit with their hardware key, which tests must never use.
- Use React (TS) for UI work, not Svelte.
