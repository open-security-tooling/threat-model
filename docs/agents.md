# Agents and staying up to date

Threat models rot because updating them is a separate chore from changing code. The fix is to make updating the model part of the same loop: the PR, the agent's task, the CI run.

Agents are first-class users. Anything a human can do in the web app, an agent can do through the CLI (`--json` everywhere) or the MCP server, with the same validation.

## CLI

| Command | What it does |
|---|---|
| `threat init` | Creates a starter `threatmodel.yaml` (interactive, or `--from-agent` to emit a drafting prompt) |
| `threat lint` | `validate` plus the writing rules: unexplained acronyms, security IDs in titles, vague mitigations, threats without a `kind` |
| `threat validate` | Checks schema, references and the strict-YAML rules. Errors are in plain language with fix hints. |
| `threat fmt` | Canonical formatting, comment-preserving. `--check` for CI. |
| `threat show` | A summary of components, threats by risk, and open mitigations |
| `threat explain <id>` | The plain-language card for a threat or mitigation, including *why this risk* |
| `threat status <id> <status>` | Change a threat's or mitigation's status. Accepting a risk needs `--by`, `--reason` and `--until`. |
| `threat suggest [--component <id>]` | Matching library threats not yet in the model |
| `threat paths --from anyone --to <data>` | [Attack paths](simulation.md) |
| `threat check` | Everything CI cares about. See below. |
| `threat report` | Markdown or HTML report, for PRs, wikis and audits |
| `threat serve` | The web app on localhost with live reload |
| `threat mcp` | The MCP server over stdio |

Every command accepts `--json` and has stable exit codes: `0` ok, `1` findings, `2` usage or parse error.

## `threat check`: keeping the model honest in CI

```console
$ threat check --base origin/main
✗ This change touches code for "Invoice API" (internal/invoice/**), reviewed 2026-03-02.
    3 threats relate to it. Confirm they're still accurate, then bump `reviewed`:
    HIGH  read-others-invoices — A logged-in customer could read other customers' invoices…
    MED   invoice-pdf-ssrf — Anyone could make our PDF renderer fetch internal URLs…
    LOW   …
✗ Mitigation "check-invoice-owner" is done, but its evidence is gone:
    internal/invoice/handler.go no longer contains "GetInvoice"
✗ Accepted risk "no-mfa-for-support" expired on 2026-09-30 (accepted by @alice: "MFA rollout in Q3")
! New flow "api-to-stripe" crosses zones and has no threats yet. Run `threat suggest --flow api-to-stripe`
✓ 41 references valid, format ok
```

What it checks:

| Check | Default |
|---|---|
| Schema, references, strict YAML | error |
| `fmt --check` | error |
| Code changed under a component's `code:` paths since its `reviewed` date (uses `git`) | warning (error with `--strict`) |
| `evidence` path or symbol missing | error |
| Accepted risk past `until` | error |
| High or critical threat open with no mitigation planned | warning |
| `done` mitigation for a high or critical threat without `test:` evidence | warning |
| New flow that crosses zones with no threats (with `--base`) | warning |
| Internet-facing component with no threats and nothing `considered` | warning |
| Mitigation done without evidence, or past its `due` date | warning |
| A risk set by hand (`risk.override`) | warning |
| `reviewed` or `signoff` dated in the future | error |
| **Changes that lower risk** compared with `--base`: threats removed, dismissed, accepted or downgraded, overrides, fixes done without evidence, a stale sign-off | warning (error with `--strict` or policy) |

A security team can turn these into enforcement with a policy file, `.threat.yaml`: fail on open critical risks, require approvers for risk-lowering changes, require evidence, due dates and sign-off. See [policy](policy.md).

### GitHub Action

A thin wrapper around `threat check --base` that:

- writes a job summary
- posts or updates one PR comment: *"This PR changes the threat model: +2 threats, 1 mitigation done (High → Low)"*, plus a rendered diagram of what changed
- is published under the org, pinned by SHA like everything else

Combine it with `CODEOWNERS` on `threatmodel.yaml` so a security champion reviews model changes. That's the review workflow Gram builds into its server, done with the PR flow you already have.

## MCP server

`threat mcp --file threatmodel.yaml` speaks MCP over **stdio only**, scoped to **one model file**.

Changes that make the model look safer, or that record a person's judgement, are refused unless the server is started with a flag:

| Refused by default | Allowed with |
|---|---|
| Deleting a threat; marking a high or critical threat not applicable (including dismissing such a suggestion); lowering a threat's who/effort/impact; setting or removing a risk override; setting `reviewed` | `--allow-risk-lowering` |
| Accepting a risk | `--allow-accept` |
| Any write at all | not available with `--read-only` |

The agent gets a plain explanation and is told to propose the change to the user instead.

### Tools

| Tool | Purpose |
|---|---|
| `get_model` | Summary: components, flows, zones, threat counts by risk |
| `list_threats` | Filter by component, status, kind, minimum risk |
| `get_threat` / `get_mitigation` | Full item, plus computed risk and explanation |
| `upsert_component` / `upsert_flow` / `upsert_data` / `upsert_zone` / `upsert_actor` / `upsert_identity` | Add or update items (validated) |
| `set_system` | Name, description, tenancy, owners, links |
| `upsert_threat` / `upsert_mitigation` | Add or update threats and fixes (validated, writing rules linted) |
| `set_status` | Change the status of a threat or mitigation. Accepting a risk requires `by`, `reason` and `until`. |
| `suggest_threats` | Library matches for a component or flow |
| `check` | Same as `threat check`, optionally with a list of changed files |
| `explain_risk` | The *why this risk* sentence |
| `find_paths` | Attack paths between a start and a target |

Every write goes through the Go core: validate, then a comment-preserving edit, then canonical formatting. **An invalid write is rejected with a plain-language error, and the file is left untouched.** Agents can't corrupt the model.

### Resources

- `threatmodel://model`: the file as written
- `threatmodel://report`: the Markdown report
- `threatmodel://writing-rules`: the [writing rules](threat-library.md#writing-rules), so agents write threats in the house style

### Prompts

| Prompt | What the agent does |
|---|---|
| `draft-model` | Reads the repo (entry points, infra code, dependencies), then proposes components, flows, data and zones, with `code:` paths filled in |
| `review-change` | Given a diff, finds which components it touches and whether threats or mitigations need updating, then proposes the edits |
| `red-team` | Plays attacker against the model and proposes missing threats and chains as suggestions ([simulation](simulation.md)) |
| `write-attack-test` | Turns a threat's attack steps into a test that proves its mitigation works |

## Agent instructions snippet

`threat init` offers to add this to `AGENTS.md` or `CLAUDE.md`:

```markdown
## Threat model

This repo has a threat model in `threatmodel.yaml` (spec: https://open-security-tooling.github.io/threat-model/).

- When you change code, run `threat check --base origin/main --json`. If it reports
  components needing review, check whether their threats are still accurate and update
  the model in the same PR. Bump `reviewed` only after actually checking.
- When you add an internet-facing endpoint, a new data store, a new third-party
  integration or anything that crosses a zone, add it to the model and run `threat suggest`.
- When you fix a threat, set the mitigation to `done` and add `evidence` (prefer a `test:`).
- Write threats as "who could do what by how". No unexplained acronyms. See `threat explain` output for the style.
- Never set a threat to `accepted` yourself. Accepting risk is a human decision.
```

The last rule is enforced, not just suggested: `set_status` to `accepted` through MCP requires the `--allow-accept` flag on `threat mcp`, which is off by default.
