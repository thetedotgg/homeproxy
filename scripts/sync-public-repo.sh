#!/usr/bin/env bash
# Commit the scanned public export of a private revision onto a clone of the
# public repository, as one ordinary commit on top of its main. Never pushes.
#
# Usage: scripts/sync-public-repo.sh --deny-patterns FILE [--ref REV] [--message TEXT] PUBLIC_CLONE
#
# PUBLIC_CLONE must be a clean checkout of the public repository's main that is
# up to date with its origin. All scans of scripts/export-public-repo.sh apply.
set -euo pipefail

usage() {
  sed -n '5p' "${BASH_SOURCE[0]}" | sed 's/^# //' >&2
  exit 2
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ref=HEAD
deny_file=""
clone=""
message=""
while (($#)); do
  case "$1" in
    --ref) ref="${2:?}"; shift 2 ;;
    --deny-patterns) deny_file="${2:?}"; shift 2 ;;
    --message) message="${2:?}"; shift 2 ;;
    -h|--help|-*) usage ;;
    *) [[ -z "$clone" ]] || usage; clone="$1"; shift ;;
  esac
done
[[ -n "$deny_file" && -n "$clone" ]] || usage

clone="$(realpath -- "$clone")"
[[ "$(git -C "$clone" rev-parse --show-toplevel)" == "$clone" ]] || { echo "Not a Git checkout: $clone" >&2; exit 1; }
[[ "$(git -C "$clone" symbolic-ref --short HEAD)" == main ]] || { echo "Public clone must be on main." >&2; exit 1; }
[[ -z "$(git -C "$clone" status --porcelain)" ]] || { echo "Public clone has local changes." >&2; exit 1; }
git -C "$clone" fetch -q origin main
[[ "$(git -C "$clone" rev-parse HEAD)" == "$(git -C "$clone" rev-parse origin/main)" ]] \
  || { echo "Public clone main differs from origin/main; update it first." >&2; exit 1; }

commit="$(git -C "$repo_root" rev-parse --verify "${ref}^{commit}")"
work="$(mktemp -d)"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

# The maintainer identity of this repository (export enforces a noreply e-mail),
# never the author of the last public commit, which may be a contributor.
author="$(git -C "$repo_root" config user.name || true) <$(git -C "$repo_root" config user.email || true)>"
bash "$repo_root/scripts/export-public-repo.sh" --ref "$commit" --deny-patterns "$deny_file" \
  --author "$author" "$work/export"

version="$(node -e 'console.log(require(process.argv[1]).version)' "$work/export/package.json")"
# Private subjects can name branches, PRs or people: default to a fixed one.
subject="${message:-HomeProxy $version}"
rc=0
grep -qaiE -f "$deny_file" <<<"$subject" || rc=$?
case "$rc" in
  1) ;;
  0) echo "The commit message matches a deny pattern; choose another --message." >&2; exit 1 ;;
  *) echo "Could not scan the commit message (grep $rc)." >&2; exit 1 ;;
esac

# Replace the tracked tree with the export; .git of the clone stays untouched.
git -C "$clone" ls-files -z | (cd "$clone" && xargs -0 -r rm -f --)
tar -C "$work/export" --exclude=./.git -cf - . | tar -C "$clone" -xf -
git -C "$clone" add -A
if git -C "$clone" diff --cached --quiet; then
  echo "Public repository already matches ${commit:0:12}; nothing to commit."
  exit 0
fi
git -C "$clone" -c user.name="${author% <*}" -c user.email="$(sed -E 's/.*<(.*)>/\1/' <<<"$author")" \
  commit -q -m "$subject" -m "Synced from private revision ${commit:0:12}."
echo "Committed $(git -C "$clone" rev-parse --short HEAD) in $clone; review it and push when ready."
