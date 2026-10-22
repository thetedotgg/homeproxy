#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/windows-interop.sh"

release_version="$(node -e 'const fs=require("fs"); console.log(JSON.parse(fs.readFileSync("package.json", "utf8")).version)')"
target_root="$repo_root/target/x86_64-pc-windows-msvc/release"
app_path="$target_root/klidna-sit.exe"
installer_path="$target_root/bundle/nsis/HomeProxy_${release_version}_x64-setup.exe"
expected_app_path="$repo_root/target/x86_64-pc-windows-msvc/release/klidna-sit.exe"
expected_installer_path="$repo_root/target/x86_64-pc-windows-msvc/release/bundle/nsis/HomeProxy_${release_version}_x64-setup.exe"
# Default to an ignored staging folder inside the repo; set
# HOMEPROXY_WINDOWS_RELEASE_OUTPUT to export elsewhere (e.g. Windows Downloads).
if [[ -z "${HOMEPROXY_WINDOWS_RELEASE_OUTPUT:-}" ]]; then
  mkdir -p -- "$repo_root/target/release-output"
fi
release_output="${HOMEPROXY_WINDOWS_RELEASE_OUTPUT:-$repo_root/target/release-output/HomeProxy-${release_version}-x64-setup.exe}"

validate_generated_output_path() {
  local path="$1"
  local expected="$2"
  local resolved

  if [[ "$path" != "$expected" ]]; then
    echo "Refusing unexpected Windows release output path: $path" >&2
    exit 1
  fi
  resolved="$(realpath -m -- "$path")"
  if [[ "$resolved" != "$expected" || -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    echo "Refusing unsafe Windows release output: $path" >&2
    exit 1
  fi
}

validate_generated_output_path "$app_path" "$expected_app_path"
validate_generated_output_path "$installer_path" "$expected_installer_path"
if [[ -L "$release_output" || ( -e "$release_output" && ! -f "$release_output" ) ]]; then
  echo "Refusing unsafe Windows release destination: $release_output" >&2
  exit 1
fi

release_temp_dir="$(mktemp -d /tmp/homeproxy-windows-unsigned.XXXXXXXXXX)"
cleanup() {
  find "$release_temp_dir" -depth -delete
}
trap cleanup EXIT
freshness_marker="$release_temp_dir/build-started"
touch -- "$freshness_marker"

for output in "$app_path" "$installer_path"; do
  if [[ -e "$output" ]]; then
    unlink -- "$output"
  fi
done

npm run tauri -- build \
  --runner cargo-xwin \
  --target x86_64-pc-windows-msvc \
  --bundles nsis

for artifact in "$app_path" "$installer_path"; do
  if [[ ! -f "$artifact" || -L "$artifact" || ! "$artifact" -nt "$freshness_marker" ]]; then
    echo "Windows build did not create a fresh regular artifact: $artifact" >&2
    exit 1
  fi
done

verified_app="$release_temp_dir/klidna-sit.exe"
verified_installer="$release_temp_dir/HomeProxy-setup.exe"
install -m 0400 -T -- "$app_path" "$verified_app"
install -m 0400 -T -- "$installer_path" "$verified_installer"

if command -v 7zz >/dev/null 2>&1; then
  seven_zip="$(command -v 7zz)"
elif command -v 7z >/dev/null 2>&1; then
  seven_zip="$(command -v 7z)"
else
  echo "7-Zip CLI is required to verify the NSIS payload." >&2
  exit 1
fi

extract_dir="$release_temp_dir/nsis"
mkdir -- "$extract_dir"
"$seven_zip" x -y "-o$extract_dir" -- "$verified_installer" >/dev/null
mapfile -d '' embedded_apps < <(find "$extract_dir" -name 'klidna-sit.exe' -type f -print0)
if [[ "${#embedded_apps[@]}" -ne 1 || -L "${embedded_apps[0]:-}" ]]; then
  echo "Expected exactly one regular embedded klidna-sit.exe; found ${#embedded_apps[@]}." >&2
  exit 1
fi
embedded_app="${embedded_apps[0]}"

verify_tauri_nsis_payload() {
  local standalone="$1"
  local embedded="$2"
  local standalone_marker="__TAURI_BUNDLE_TYPE_VAR_NSS__TAURI_BUNDLE_TYPE_VAR_UNK"
  local embedded_marker="__TAURI_BUNDLE_TYPE_VAR_NSS__TAURI_BUNDLE_TYPE_VAR_NSS"
  local standalone_offsets=()
  local embedded_offsets=()
  local marker_offset
  local suffix_offset

  if [[ "${#standalone_marker}" -ne "${#embedded_marker}" ]] ||
    [[ "$(stat -c %s -- "$standalone")" -ne "$(stat -c %s -- "$embedded")" ]]; then
    echo "The NSIS application payload has an unexpected size or marker layout." >&2
    return 1
  fi

  mapfile -t standalone_offsets < <(LC_ALL=C grep -aobF -- "$standalone_marker" "$standalone" || true)
  mapfile -t embedded_offsets < <(LC_ALL=C grep -aobF -- "$embedded_marker" "$embedded" || true)
  if [[ "${#standalone_offsets[@]}" -ne 1 || "${#embedded_offsets[@]}" -ne 1 ]]; then
    echo "Expected exactly one Tauri bundle marker in each application payload." >&2
    return 1
  fi

  marker_offset="${standalone_offsets[0]%%:*}"
  if [[ "$marker_offset" != "${embedded_offsets[0]%%:*}" ]]; then
    echo "The Tauri bundle marker moved inside the NSIS application payload." >&2
    return 1
  fi
  suffix_offset=$((marker_offset + ${#standalone_marker}))

  if ! cmp -n "$marker_offset" -- "$standalone" "$embedded" ||
    ! cmp -i "$suffix_offset:$suffix_offset" -- "$standalone" "$embedded"; then
    echo "The NSIS payload differs beyond Tauri's expected UNK-to-NSS bundle marker patch." >&2
    return 1
  fi
}

windows_verifier="$(windows_path "$repo_root/scripts/verify-windows-unsigned-release.ps1")"
windows_app="$(windows_path "$verified_app")"
windows_installer="$(windows_path "$verified_installer")"
windows_embedded_app="$(windows_path "$embedded_app")"
windows_powershell \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -ExecutionPolicy Bypass \
  -File "$windows_verifier" \
  -ExpectedVersion "$release_version" \
  -AppPath "$windows_app" \
  -InstallerPath "$windows_installer" \
  -EmbeddedAppPath "$windows_embedded_app"

verify_tauri_nsis_payload "$verified_app" "$embedded_app"
if ! cmp -- "$verified_app" "$app_path" || ! cmp -- "$verified_installer" "$installer_path"; then
  echo "Windows release outputs changed during verification." >&2
  exit 1
fi

install -m 0644 -T -- "$verified_installer" "$release_output"
if [[ ! -f "$release_output" || -L "$release_output" ]] || ! cmp -- "$verified_installer" "$release_output"; then
  echo "The copied Windows installer failed final verification: $release_output" >&2
  exit 1
fi
sha256sum -- "$app_path" "$installer_path" "$release_output"
