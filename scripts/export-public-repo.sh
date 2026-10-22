#!/usr/bin/env bash
# Build a fresh single-commit Git repository with the public HomeProxy source.
#
# The private history keeps QA evidence, local paths and names that must not be
# published. This script exports one committed revision, drops the paths in
# scripts/public-export-exclude.txt, scans the result and commits it into a new
# repository. It never pushes; publishing stays a separate, explicit step.
# Every check fails closed: a scanner error blocks the export like a finding.
#
# Usage: scripts/export-public-repo.sh (--deny-patterns FILE | --no-deny-patterns)
#          [--ref REV] [--author "Name <id+user@users.noreply.github.com>"] [--no-gitleaks] OUTPUT_DIR
#
# FILE holds private extended regexes (names, e-mails), one per line, and must
# live outside the repository. They are matched case-insensitively in every
# file, binary files included, so image metadata is covered too.
set -euo pipefail

GITLEAKS_IMAGE="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
# Binary files are only expected in these places (icons, fonts, screenshots).
BINARY_ALLOW='^(assets|public|src-tauri/icons|website/src/(screens|generated|og|fonts|icons|donate))/'

usage() {
  sed -n '10,11p' "${BASH_SOURCE[0]}" | sed 's/^# //' >&2
  exit 2
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ref=HEAD
deny_file=""
deny_mode=""
run_gitleaks=1
author=""
output=""
while (($#)); do
  case "$1" in
    --ref) ref="${2:?}"; shift 2 ;;
    --deny-patterns) deny_file="${2:?}"; deny_mode="file"; shift 2 ;;
    --no-deny-patterns) deny_mode="none"; shift ;;
    --author) author="${2:?}"; shift 2 ;;
    --no-gitleaks) run_gitleaks=0; shift ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) [[ -z "$output" ]] || usage; output="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$deny_mode" ]] || usage

if [[ -z "$author" ]]; then
  author="$(git -C "$repo_root" config user.name || true) <$(git -C "$repo_root" config user.email || true)>"
fi
if [[ ! "$author" =~ ^[^\<\>]+\ \<[^@\<\>]+@users\.noreply\.github\.com\>$ ]]; then
  echo "Refusing author '$author': use a GitHub noreply address so no personal e-mail is published." >&2
  exit 1
fi

commit="$(git -C "$repo_root" rev-parse --verify "${ref}^{commit}")"
if [[ -e "$output" ]]; then
  echo "Refusing to reuse existing output: $output" >&2
  exit 1
fi
mkdir -p -- "$(dirname -- "$output")"
output_parent="$(realpath -- "$(dirname -- "$output")")"
output="$output_parent/$(basename -- "$output")"
case "$output/" in
  "$repo_root"/*) echo "Output must be outside the repository: $output" >&2; exit 1 ;;
esac
if [[ "$deny_mode" == file ]]; then
  deny_file="$(realpath -- "$deny_file")"
  case "$deny_file" in
    "$repo_root"/*) echo "Keep the deny pattern file outside the repository." >&2; exit 1 ;;
  esac
  [[ -f "$deny_file" && -s "$deny_file" ]] || { echo "Deny pattern file is missing or empty: $deny_file" >&2; exit 1; }
fi

mkdir -- "$output"
git -C "$repo_root" archive --format=tar "$commit" | tar -x -C "$output"

exclude_list="$output/scripts/public-export-exclude.txt"
[[ -f "$exclude_list" ]] || { echo "Missing exclude list in $commit" >&2; exit 1; }
while IFS= read -r entry || [[ -n "$entry" ]]; do
  [[ -z "$entry" || "$entry" == \#* ]] && continue
  if [[ "$entry" == /* || "$entry" == *..* ]]; then
    echo "Invalid exclude entry: $entry" >&2
    exit 1
  fi
  target="$output/${entry%/}"
  if [[ ! -e "$target" && ! -L "$target" ]]; then
    # A renamed internal file would otherwise slip into the public tree.
    echo "Stale exclude entry (path not found in $commit): $entry" >&2
    exit 1
  fi
  rm -rf -- "$target"
done < "$exclude_list"

failures=0
report() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

# grep: 0 = match, 1 = no match, anything else (bad regex, unreadable file) is
# an error and must block the export instead of reading as "clean".
grep_matches() {
  local rc=0
  "$@" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) report "scanner error ($rc): $*"; return 1 ;;
  esac
}

mapfile -d '' files < <(find "$output" -type f -print0)
while IFS= read -r -d '' link; do
  report "symbolic link in export: ${link#"$output"/}"
done < <(find "$output" -type l -print0)

# Generic leaks: personal home directories, private keys and common tokens.
# Placeholder accounts used by tests and VM fixtures are not personal paths.
# Each match is checked on its own (-o), so a placeholder on the same line
# cannot hide a key or a real home directory.
generic='(/home/[a-z][a-z0-9_-]*/|/mnt/c/Users/|C:\\Users\\|BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})'
placeholder_home='^/home/(qa|test|user|runner|example)/$'
for file in "${files[@]}"; do
  relative="${file#"$output"/}"
  [[ "$relative" == scripts/export-public-repo.sh ]] && continue
  if grep_matches grep -qI . "$file"; then
    matches="$(grep -IoE "$generic" "$file" || [[ $? == 1 ]])" || { report "scanner error: $relative"; continue; }
    if [[ -n "$matches" ]] && grep_matches grep -qvE "$placeholder_home" <<<"$matches"; then
      report "generic sensitive pattern in $relative"
    fi
  elif [[ -s "$file" && ! "$relative" =~ $BINARY_ALLOW ]]; then
    report "unexpected binary file: $relative"
  fi
  if [[ "$deny_mode" == file ]] && grep_matches grep -qaiE -f "$deny_file" "$file"; then
    report "private deny pattern in $relative"
  fi
done

# Markdown links must not point at excluded or missing files.
while IFS= read -r -d '' doc; do
  dir="$(dirname -- "$doc")"
  while IFS= read -r link; do
    link="${link%%#*}"
    [[ -z "$link" || "$link" == *://* || "$link" == mailto:* ]] && continue
    [[ -e "$dir/$link" ]] || report "broken link ${doc#"$output"/} -> $link"
  done < <(grep -oE '\]\([^)]+\)' "$doc" | sed -E 's/^\]\((.*)\)$/\1/' || true)
done < <(find "$output" -name '*.md' -print0)

if ((run_gitleaks)); then
  docker run --rm -v "$output:/scan:ro" "$GITLEAKS_IMAGE" dir /scan --config /scan/.gitleaks.toml --redact --no-banner \
    || report "gitleaks reported findings or could not run"
fi

if ((failures)); then
  echo "Public export blocked by $failures finding(s); nothing was committed in $output." >&2
  exit 1
fi

author_name="${author% <*}"
author_email="${author##*<}"
author_email="${author_email%>}"
git -C "$output" init -q -b main
git -C "$output" add -A
git -C "$output" -c user.name="$author_name" -c user.email="$author_email" commit -q \
  -m "HomeProxy $(node -e 'console.log(require(process.argv[1]).version)' "$output/package.json")" \
  -m "Public source export of private revision ${commit:0:12}."
echo "Public repository prepared: $output ($(git -C "$output" rev-parse --short HEAD), $(git -C "$output" ls-files | wc -l) files)"
echo "Nothing was pushed."
