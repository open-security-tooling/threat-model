#!/usr/bin/env bash
# Cut a release: work out the next version from the commits since the last
# tag, then create a signed, annotated tag with the release notes and push it.
# The release workflow takes it from there.
#
# Versions follow conventional commits:
#   feat: ...              → minor
#   fix: / perf: ...       → patch
#   type!: or BREAKING CHANGE in the body → major (minor while below 1.0)
#   anything else          → patch, listed under "Other changes"
#
# Usage: scripts/release.sh [--dry-run] [vX.Y.Z]
#   Give a version to override the computed one.
set -euo pipefail

dry_run=false
override=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    v[0-9]*) override=$arg ;;
    *) echo "usage: $0 [--dry-run] [vX.Y.Z]" >&2; exit 2 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

# Release from an up-to-date, clean main, so the tag points at reviewed code.
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || { echo "Switch to main first (you're on $branch)." >&2; exit 1; }
git diff --quiet && git diff --cached --quiet || { echo "Commit or stash your changes first." >&2; exit 1; }
git fetch -q --tags origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "main isn't the same as origin/main; pull first." >&2; exit 1; }

last=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)
range=${last:+$last..}HEAD
subjects=$(git log --no-merges --format='%s' "$range")
bodies=$(git log --no-merges --format='%B' "$range")
[ -n "$subjects" ] || { echo "No commits since $last; nothing to release." >&2; exit 1; }

if [ -z "$last" ]; then
  major=0 minor=0 patch=0
else
  IFS=. read -r major minor patch <<< "${last#v}"
  patch=${patch%%-*}
fi

breaking=false feat=false
grep -qE '^[a-z]+(\([^)]*\))?!:' <<< "$subjects" && breaking=true
grep -q 'BREAKING CHANGE' <<< "$bodies" && breaking=true
grep -qE '^feat(\([^)]*\))?:' <<< "$subjects" && feat=true

if [ -n "$override" ]; then
  next=$override
elif [ -z "$last" ]; then
  next=v0.1.0
elif $breaking && [ "$major" -gt 0 ]; then
  next="v$((major + 1)).0.0"
elif $breaking || $feat; then
  # Before 1.0, breaking changes bump the minor version.
  next="v$major.$((minor + 1)).0"
else
  next="v$major.$minor.$((patch + 1))"
fi
[[ "$next" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "$next isn't a valid version." >&2; exit 1; }
git rev-parse -q --verify "refs/tags/$next" > /dev/null && { echo "$next already exists." >&2; exit 1; }

section() {
  local title=$1 pattern=$2 lines
  lines=$(grep -E "$pattern" <<< "$subjects" | sed -E 's/^[a-z]+(\([^)]*\))?!?: */- /' || true)
  if [ -n "$lines" ]; then
    printf '\n\n%s\n\n%s' "$title" "$lines"
  fi
}
notes="$next"
# Breaking changes: "type!:" in the subject, or BREAKING CHANGE in the body.
breaking_subjects=$( { grep -E '^[a-z]+(\([^)]*\))?!:' <<< "$subjects" || true; git log --no-merges --format='%s' --grep='BREAKING CHANGE' "$range"; } | awk 'NF && !seen[$0]++')
breaking_lines=$(sed -E 's/^[a-z]+(\([^)]*\))?!?: */- /' <<< "$breaking_subjects")
if [ -n "$breaking_lines" ]; then
  notes+=$(printf '\n\nBreaking changes\n\n%s' "$breaking_lines")
fi
notes+=$(section "Features" '^feat(\([^)]*\))?:')
notes+=$(section "Fixes" '^(fix|perf)(\([^)]*\))?:')
# Everything that isn't a feature, fix or breaking change.
other=$(grep -vE '^(feat|fix|perf)(\([^)]*\))?!?:|^[a-z]+(\([^)]*\))?!:' <<< "$subjects" | grep -vxF -e "${breaking_subjects:-//none//}" | sed -E 's/^[a-z]+(\([^)]*\))?: *//' | sed 's/^/- /' || true)
if [ -n "$other" ]; then
  notes+=$(printf '\n\nOther changes\n\n%s' "$other")
fi

echo "Releasing $next (previous: ${last:-none})"
echo
echo "$notes"
echo
if $dry_run; then
  echo "(dry run: no tag created)"
  exit 0
fi
read -r -p "Create and push the signed tag $next? [y/N] " answer
[ "$answer" = y ] || [ "$answer" = Y ] || { echo "Cancelled."; exit 1; }

git tag -s "$next" -m "$notes"
git tag -v "$next" > /dev/null 2>&1 || { echo "The new tag's signature didn't verify; not pushing." >&2; git tag -d "$next"; exit 1; }
git push origin "$next"
echo "Pushed $next. Approve the release in GitHub when it asks: https://github.com/open-security-tooling/threat-model/actions"
