# Policy: making threat check enforce what your security team needs

Out of the box, `threat check` gives advice. Most findings about the model's own changes are warnings, because the tool can't know whether a change was right. A security team that wants enforcement adds a **policy file**, `.threat.yaml`, at the repository root.

- **No policy file:** developers get the friendly defaults, so nothing is blocked that a person should decide.
- **With a policy file:** `threat check` fails on what the policy says. Developers see plain-language findings like *"This lowers a high risk to low. Someone in @acme/appsec needs to agree."* They never have to learn the policy's settings.

Own the policy through `CODEOWNERS`, so changes to it need your review:

```text
# .github/CODEOWNERS
/.threat.yaml        @acme/appsec
/threatmodel.yaml    @acme/appsec
```

## Example

```yaml
# .threat.yaml
version: 1
extends: security/org-policy.yaml   # optional: a shared policy vendored into the repo

fail_on:
  open_risk: critical               # nothing open at critical

changes:
  risk_lowering: error              # removing, dismissing, accepting or downgrading threats fails…
  approvers: ["@acme/appsec"]       # …and the GitHub Action names who must approve

acceptance:
  max_days: 180                     # risk acceptances expire within six months

require:
  evidence_for_done: true           # "done" needs evidence
  test_evidence_for: high           # high and critical fixes need a test
  due_for: high                     # unfinished fixes for high risks need a due date
  signoff: true                     # the model needs a security sign-off

review:
  max_age_days: 180                 # components with code are reviewed twice a year

catalogs:
  required: ["builtin:web", "builtin:cloud"]
```

All fields are optional. A child file's settings override those of the file it `extends`, and required catalogs add up. `extends` must point to a file inside the repository. Fetching remote policies is deliberately not supported, because `threat check` never touches the network.

## What `threat check --base` reports about the model itself

Comparing with the base branch, `threat check` lists every change that lowers risk:

| Finding | When |
|---|---|
| `threat-removed` | A threat that applied is gone |
| `threat-dismissed` | A threat was marked `not-applicable` |
| `risk-accepted` | A threat was accepted as a risk |
| `risk-lowered` | A threat's own `who`, `effort` or `impact` answers changed so its risk dropped. Finishing a mitigation doesn't count. |
| `risk-override` | A threat's risk was set by hand |
| `done-without-evidence` | A mitigation was marked done without any evidence |
| `signoff-stale` | The model changed but its `signoff` didn't |

Without a policy these are warnings (or errors with `--strict`). With `changes.risk_lowering: error` they fail the check, and `approvers` are named in the hint and in the pull request summary.

The check can't tell who approved a pull request; that's what branch protection is for. Require a review from code owners on `threatmodel.yaml` (above), and the approvers named in the summary are the people GitHub asks.

## Sign-off

A security review of the whole model is recorded in the file:

```yaml
signoff:
  by: "@alice"
  on: 2026-10-27
  note: Reviewed with the billing team before launch
```

Individual components can record who reviewed them: `reviewed: {on: 2026-10-27, by: "@alice"}`.

Agents can't write either through MCP, because both are statements by a person.

## Defaults without a policy

These always run, as warnings:
- mitigations marked done without evidence
- mitigations past their `due` date
- risks set by hand
- internet-facing components with no threats and nothing `considered`

Dates in the future for `reviewed` or `signoff` are always errors, because they would silence review checks.
