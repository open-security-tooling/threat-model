# Running threat check in CI

A threat model is only useful while it matches the code. `threat check` catches the moments it stops matching: code that changed since its threats were reviewed, a mitigation marked done whose code is gone, an accepted risk past its date, or a change that quietly lowers a risk. Running it on every pull request means those moments show up in review, where someone can do something about them.

This page covers GitHub. Other CI systems are at the end.

## Set it up

1. Commit your model (`threatmodel.yaml` at the repository root is the default).
2. Add the workflow from [action/README.md](../action/README.md#usage). It checks out the repository with full history, so the check can compare with the pull request's base. Then it runs the Action.
3. Open a pull request. You'll get:
   - annotations on the model file, one per problem, on the "Files changed" tab
   - a job summary listing what changed, what needs a person to agree, errors, warnings and the top open risks
   - one comment on the pull request with the same summary, updated on every push rather than added again
4. Make the check required (below), so a failing check blocks the merge.

The job needs `contents: read`, plus `pull-requests: write` if it comments. It needs no secrets. Run it on `pull_request`, never `pull_request_target` (see [pull requests from forks](#pull-requests-from-forks)).

Pin both versions: the Action by its full commit SHA, and the `threat` binary with `version:`. Then an upgrade arrives as a pull request you can review, not as a surprise in CI. The Action checks the binary with `gh attestation verify` before running it, and stops if the check fails.

### What fails the check

`threat check` exits `0` when there are no errors, `1` when there are, and `2` when it can't run at all (a missing file, or a bad `--base`). Warnings never fail the job unless you make them errors with `strict: true` or the policy.

Out of the box, the errors are: the file doesn't parse or validate, it isn't formatted (`threat fmt`), a done mitigation's evidence is gone, and an accepted risk has expired. Everything else is a warning until a policy says otherwise.

## Policy, approvers and branch protection

Three pieces work together. Each does one job:

| Piece | Lives in | Does |
|---|---|---|
| Policy | `.threat.yaml` | Decides what counts as an error: open critical risks, missing due dates, risk acceptances longer than 90 days, changes that lower risk. Names the `approvers` for risk-lowering changes. See [policy.md](policy.md). |
| The Action | your workflow | Runs the check, fails the job on errors, and lists the risk-lowering changes under **Needs a person to agree**, naming the approvers. |
| CODEOWNERS and branch protection | `.github/CODEOWNERS`, repository settings | Make GitHub *require* an approval from those people before the merge. |

The check can't enforce approval itself. It runs when code is pushed, and it can't see a review that comes later. GitHub's branch protection can. So:

1. **Give the model and the policy owners.** In `.github/CODEOWNERS`:

   ```text
   # A security champion reviews every change to the threat model.
   /threatmodel.yaml   @acme/security-champions
   # The security team owns the rules and the CI that applies them.
   /.threat.yaml       @acme/appsec
   /.github/workflows/ @acme/appsec
   ```

   The policy needs an owner too. The check reads `.threat.yaml` from the pull request itself, so without an owner, a pull request could relax the policy and pass its own check. The same goes for the workflow files.

2. **Use the same people in the policy.** Set `changes.approvers` in `.threat.yaml` to the team that owns `threatmodel.yaml` in CODEOWNERS. Then the people the summary names are the people GitHub asks for a review.

3. **Protect the default branch** (Settings → Rules → Rulesets, or Branches → Branch protection):
   - Require a pull request before merging, with **Require review from Code Owners**.
   - **Dismiss stale approvals when new commits are pushed**, and require approval of the most recent push. Otherwise someone could get the model approved and then change it.
   - **Require status checks to pass**, and add the Action's job (e.g. `check`).

What this gets you: anyone can propose a change to the model. A change that removes a threat, marks it not applicable, accepts a risk or lowers its answers gets flagged in the summary. With `changes.risk_lowering: error` it fails the check. It can't be merged until a code owner of the model approves it.

## Code scanning (SARIF)

With `sarif: true` (and `security-events: write`), the Action uploads results to GitHub code scanning under the category `threat-model`:

- **Each finding** is an alert, with the finding code as its rule (`needs-review`, `evidence-missing`…), at the line in the model it's about.
- **Each open threat** is an alert too, under a rule per kind of threat (`open-threat/leak`, `open-threat/impersonate`…). Its message says why it has its risk level. Critical and high risks are errors, medium ones warnings and low ones notes.

That puts your open threats in the Security tab next to your other scanners, with history, filters and the API. It's handy when a security team tracks risk across many repositories.

Fix alerts in the model, not in the Security tab. Dismissing an alert there doesn't change the threat. When you finish a mitigation or accept a risk in `threatmodel.yaml`, the alert closes on the next run. Run the upload on pushes to the default branch as well as pull requests, so the Security tab reflects what's merged.

Code scanning is free for public repositories. Private repositories need GitHub Code Security, and the job also needs `actions: read`.

## Pull requests from forks

When a pull request comes from a fork, GitHub runs `pull_request` workflows with a **read-only token**, whatever the workflow asks for. That's deliberate, since it keeps a stranger's code from writing to your repository. It also means:

- annotations, the job summary and pass or fail all still work
- the Action can't post its comment, so it says so and skips it
- the Action skips the SARIF upload

**Don't switch to `pull_request_target` to get around this.** It runs with a write token and your secrets, in the context of your repository. Combined with a checkout of the PR's code, that's the most common way GitHub Actions get compromised. The Action warns if it sees it.

If you want comments on fork PRs, add a second workflow that runs on `workflow_run` after the check and **only posts the comment**. It's in [action/README.md](../action/README.md#pull-requests-from-forks). It's safe because:

- it runs from your default branch's copy of the workflow, which the fork can't change
- it never checks out or runs the pull request's code
- it treats the artifact from the fork's run as untrusted data: it checks the PR number against GitHub, caps the size, and marks the comment as coming from the fork's run, because the fork could have changed its own check workflow to write anything

The pass or fail of the check is what protects your branch. The comment is for convenience, so a fork's comment should never be what anyone relies on.

## Other CI systems

The Action is a thin wrapper. Anywhere else, check out with history and run:

```console
$ threat check --base origin/main            # human-readable, exit 1 on errors
$ threat check --base origin/main --json     # for scripts
$ threat check --base origin/main --format summary > summary.md   # Markdown for a merge request comment
$ threat check --base origin/main --format sarif > threat.sarif   # SARIF 2.1.0 for any SARIF viewer
```

Verify the binary first with `gh attestation verify threat_linux_amd64 --repo open-security-tooling/threat-model`. The same CODEOWNERS idea works with GitLab's code owners and merge request approval rules.

## Exporting a risk register

Auditors and security teams often want a spreadsheet. `threat report --register csv` (or `json`) writes one row per threat: its risk before and after mitigations and why, status, mitigations with owners and due dates, risk acceptances, mappings like CWE and OWASP, whether there's evidence, and when the affected components were last reviewed. Each row also carries the model name, file, commit and time, so registers from many repositories can be combined.

The CSV is safe to open in Excel. Model text comes from pull requests, so any cell that would start with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, and the spreadsheet treats it as text instead of running it as a formula. That's why an owner like `@alice` shows as `'@alice` in the raw file.
