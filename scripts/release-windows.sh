#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/windows-interop.sh"

if [[ -z "${HOMEPROXY_TAURI_SIGNING_CONFIG:-}" ]]; then
  echo "HOMEPROXY_TAURI_SIGNING_CONFIG must point to an authorized Tauri Windows signing config." >&2
  exit 2
fi

signing_config="$(realpath -- "$HOMEPROXY_TAURI_SIGNING_CONFIG")"
if [[ ! -f "$signing_config" ]]; then
  echo "Signing config does not exist: $signing_config" >&2
  exit 2
fi

release_version="$(node -e 'const fs=require("fs"); console.log(JSON.parse(fs.readFileSync("package.json", "utf8")).version)')"
target_root="$repo_root/target/x86_64-pc-windows-msvc/release"
app_path="$target_root/klidna-sit.exe"
installer_path="$target_root/bundle/nsis/HomeProxy_${release_version}_x64-setup.exe"
signing_policy="$repo_root/scripts/windows-signing-policy.json"
expected_app_path="$repo_root/target/x86_64-pc-windows-msvc/release/klidna-sit.exe"
expected_installer_path="$repo_root/target/x86_64-pc-windows-msvc/release/bundle/nsis/HomeProxy_${release_version}_x64-setup.exe"

validate_generated_output_path() {
  local path="$1"
  local expected="$2"
  local resolved

  if [[ "$path" != "$expected" ]]; then
    echo "Refusing unexpected Windows release output path: $path" >&2
    exit 1
  fi
  resolved="$(realpath -m -- "$path")"
  if [[ "$resolved" != "$expected" ]]; then
    echo "Refusing non-canonical Windows release output path: $path resolves to $resolved" >&2
    exit 1
  fi
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    echo "Refusing non-regular pre-existing Windows release output: $path" >&2
    exit 1
  fi
}

remove_generated_output() {
  local path="$1"

  if [[ -e "$path" ]]; then
    unlink -- "$path"
  fi
  if [[ -e "$path" ]]; then
    echo "Could not remove the pre-existing Windows release output: $path" >&2
    exit 1
  fi
}

validate_generated_output_path "$app_path" "$expected_app_path"
validate_generated_output_path "$installer_path" "$expected_installer_path"

release_temp_dir="$(mktemp -d /tmp/homeproxy-windows-release.XXXXXXXXXX)"
cleanup() {
  find "$release_temp_dir" -depth -delete
}
trap cleanup EXIT
freshness_marker="$release_temp_dir/build-started"
touch -- "$freshness_marker"

remove_generated_output "$app_path"
remove_generated_output "$installer_path"

npm run tauri -- build \
  --runner cargo-xwin \
  --target x86_64-pc-windows-msvc \
  --bundles nsis \
  --config "$signing_config"

for artifact in "$app_path" "$installer_path"; do
  if [[ ! -f "$artifact" || -L "$artifact" ]]; then
    echo "Windows build did not create the expected regular output: $artifact" >&2
    exit 1
  fi
  if [[ ! "$artifact" -nt "$freshness_marker" ]]; then
    echo "Windows build output is not fresh: $artifact" >&2
    exit 1
  fi
done

verified_app="$release_temp_dir/verified-standalone.exe"
verified_installer="$release_temp_dir/verified-installer.exe"
install -m 0400 -T -- "$app_path" "$verified_app"
install -m 0400 -T -- "$installer_path" "$verified_installer"

windows_verifier="$(windows_path "$repo_root/scripts/verify-windows-release.ps1")"
windows_app="$(windows_path "$verified_app")"
windows_installer="$(windows_path "$verified_installer")"
windows_signing_policy="$(windows_path "$signing_policy")"

verify_windows_artifacts() {
  local windows_application="$1"

  windows_powershell \
    -NoLogo \
    -NoProfile \
    -NonInteractive \
    -ExecutionPolicy Bypass \
    -File "$windows_verifier" \
    -ExpectedVersion "$release_version" \
    -AppPath "$windows_application" \
    -InstallerPath "$windows_installer" \
    -PolicyPath "$windows_signing_policy"
}

verify_windows_artifacts "$windows_app"

if command -v 7zz >/dev/null 2>&1; then
  seven_zip="$(command -v 7zz)"
elif command -v 7z >/dev/null 2>&1; then
  seven_zip="$(command -v 7z)"
else
  echo "7-Zip CLI is required to verify the signed NSIS payload (tried 7zz and 7z)." >&2
  exit 1
fi

extract_dir="$release_temp_dir/nsis"
mkdir -- "$extract_dir"
"$seven_zip" x -y "-o$extract_dir" -- "$verified_installer" >/dev/null

embedded_app_list="$release_temp_dir/embedded-apps.list"
if ! find "$extract_dir" -name 'klidna-sit.exe' -print0 >"$embedded_app_list"; then
  echo "Could not enumerate the signed NSIS application payload." >&2
  exit 1
fi
mapfile -d '' embedded_apps <"$embedded_app_list"
if [[ "${#embedded_apps[@]}" -ne 1 ]]; then
  echo "Expected exactly one embedded klidna-sit.exe in the signed NSIS installer; found ${#embedded_apps[@]}." >&2
  exit 1
fi
embedded_app="${embedded_apps[0]}"
if [[ ! -f "$embedded_app" || -L "$embedded_app" ]]; then
  echo "Refusing non-regular NSIS application payload: $embedded_app" >&2
  exit 1
fi

windows_embedded_app="$(windows_path "$embedded_app")"
verify_windows_artifacts "$windows_embedded_app"

normalized_app="$release_temp_dir/standalone.normalized.exe"
normalized_embedded_app="$release_temp_dir/nsis-payload.normalized.exe"
node "$repo_root/scripts/normalize-windows-release-payload.mjs" \
  "$verified_app" \
  "$embedded_app" \
  "$normalized_app" \
  "$normalized_embedded_app"
if ! cmp -- "$normalized_app" "$normalized_embedded_app"; then
  echo "Signed NSIS application payload does not match the just-built standalone application." >&2
  exit 1
fi

if ! cmp -- "$verified_app" "$app_path" || ! cmp -- "$verified_installer" "$installer_path"; then
  echo "Windows release outputs changed after their private verification snapshots were created." >&2
  exit 1
fi

# Default to an ignored staging folder inside the repo; set
# HOMEPROXY_WINDOWS_RELEASE_OUTPUT to export elsewhere (e.g. Windows Downloads).
if [[ -z "${HOMEPROXY_WINDOWS_RELEASE_OUTPUT:-}" ]]; then
  mkdir -p -- "$repo_root/target/release-output"
fi
release_output="${HOMEPROXY_WINDOWS_RELEASE_OUTPUT:-$repo_root/target/release-output/HomeProxy-${release_version}-x64-setup.exe}"
if [[ -L "$release_output" || ( -e "$release_output" && ! -f "$release_output" ) ]]; then
  echo "Refusing non-regular Windows release destination: $release_output" >&2
  exit 1
fi
install -m 0644 -T -- "$verified_installer" "$release_output"
if [[ ! -f "$release_output" || -L "$release_output" ]]; then
  echo "Windows release destination is not a regular file: $release_output" >&2
  exit 1
fi
if ! cmp -- "$verified_installer" "$release_output"; then
  echo "Copied Windows release does not match the verified installer snapshot." >&2
  exit 1
fi
sha256sum -- "$app_path" "$installer_path" "$release_output"
