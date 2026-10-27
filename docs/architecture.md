# Architecture

## One core, many front ends

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐
│ threat (CLI) │  │ threat mcp   │  │ threat serve │  │ Web app (TS) │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘
     │             │             │               │ postMessage (JSON)
     │             │             │        ┌──────┴───────┐
     │             │             │        │ Web Worker   │
     │             │             │        │ core.wasm    │
     │             │             │        └──────┬───────┘
     └─────────────┴──────┬──────┴───────────────┘
                          ▼
                 internal/ops   ← one function per operation
                          │
   ┌────────┬────────┬────┴───┬─────────┬────────┬────────┐
   model    edit     risk     catalog   sim      check    report
```

**`internal/ops` is the contract.** Every operation, such as `validate`, `upsert_threat`, `explain_risk`, `suggest`, `find_paths` or `check`, is one Go function with JSON-serialisable inputs and outputs. The CLI, the MCP tools and the WASM bridge are thin adapters over the same functions. If an operation exists in one front end, it exists in all of them and behaves the same way.

## Go packages

| Package | Responsibility |
|---|---|
| `internal/model` | Types, strict-YAML parsing with limits, validation, reference checks, JSON Schema generation |
| `internal/edit` | Comment- and order-preserving edits on the YAML tree, plus canonical formatting (`threat fmt`) |
| `internal/risk` | Likelihood and risk tables, residual risk from mitigation effects, explanation sentences |
| `internal/catalog` | Loading built-in and custom catalogs, matching `applies` rules, filling in templates |
| `internal/sim` | Attack-path search and blast radius ([simulation](simulation.md)) |
| `internal/check` | CI checks, git integration for "what changed since `reviewed`", evidence checks |
| `internal/report` | Markdown and self-contained HTML reports, diagram SVG |
| `internal/ops` | The operation layer above |
| `internal/mcp` | MCP server (stdio) |
| `internal/serve` | Local HTTP server for `threat serve`, file watching, live updates |
| `cmd/threat` | CLI |
| `wasm/` | `GOOS=js GOARCH=wasm` entry point exposing `ops` over one JSON call bridge |

Packages that need the OS (`check`'s git calls, `serve`, `mcp`) are excluded from the WASM build. Everything else compiles to both targets.

## The hard part: editing YAML without wrecking it

Agents and the web app edit the file constantly, and every edit must:

1. keep the comments and the item order the user wrote
2. touch only the lines that changed, so diffs stay small
3. produce exactly what `threat fmt` would

So `internal/edit` works on the YAML **syntax tree**, not on decoded structs. It finds the item by `id`, changes the node and re-emits the result. This is the riskiest piece technically, so we prototype it before anything else, with golden-file tests for a wide range of edits. Candidate libraries: the maintained go-yaml v3 fork's node API, and `goccy/go-yaml`'s AST. See [roadmap](roadmap.md).

## WebAssembly

- Built with the standard Go toolchain (`GOOS=js GOARCH=wasm`), loaded with Go's `wasm_exec.js`.
- **Runs in a Web Worker**, so parsing, checks and simulation never block the UI.
- The bridge is a single entry point, `call(op, argsJSON) → resultJSON`, mirroring `internal/ops`. A narrow surface is easy to secure and test.
- Expected size is a few MB raw, around 1–2 MB compressed. It's loaded once and cached by the service worker. If size becomes a problem we'll evaluate TinyGo, but its weaker reflection support can break YAML and JSON libraries.

## Web app

- TypeScript and Vite, with React and React Flow (@xyflow/react) for the diagram.
- CodeMirror 6 for the YAML view.
- **All model logic lives in the WASM core.** The UI only renders what the core returns and sends operations back. It never edits YAML itself.
- The build is **fully static and self-contained**: no CDNs, no web fonts from third parties, no analytics. Everything is served from the same origin.

## `threat serve`

- Serves the same static build, embedded in the binary with `go:embed`.
- Binds `127.0.0.1` on a random port and opens `http://127.0.0.1:<port>/#token=<random>`.
- Every API and WebSocket request needs the token and a matching `Host`/`Origin`, which blocks other websites and DNS-rebinding attacks.
- It watches the model file and pushes changes over a WebSocket. Saves from the app go through `ops`, and it only writes to the one file it was started with.

## MCP

- Speaks stdio only. No network listener.
- One model file per server instance, set at startup. Tools take no file paths.
- Built on the official MCP Go SDK, if it fits our dependency bar. Otherwise we implement the small protocol subset we need ourselves.

## Git

`threat check --base <ref>` shells out to the user's `git` instead of embedding a git library. That means fewer dependencies, and it respects the user's git config. Refs are validated and passed after `--end-of-options`.

## Build, test, release

- **Tests:**
  - golden files for parsing, formatting and editing
  - table tests for the risk tables
  - **fuzzing** (`go test -fuzz`) for the parser and editor
  - Playwright end-to-end tests for the web app
- **CI:** GitHub Actions, following org policy: GitHub-owned or verified actions only, SHA-pinned, `permissions: {}` by default.
- **Releases:**
  - built with `-trimpath` for linux, macOS and windows on amd64 and arm64
  - checksums plus GitHub artifact attestations (build provenance)
  - available through `go install`, with a Homebrew tap later
- **Web app:** built and deployed to GitHub Pages from tagged releases, through a protected `github-pages` environment, with provenance for the built bundle.

## Repo layout

```
threat-model/
├── cmd/threat/                 CLI
├── internal/…              packages above
├── wasm/                   WASM entry point
├── web/                    web app (TypeScript)
├── catalogs/               built-in threat library (YAML, embedded)
├── schema/                 generated JSON Schema (published to Pages)
├── docs/                   these docs
└── threatmodel.yaml        the tool's own threat model (dogfooding)
```
