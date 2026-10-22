#!/usr/bin/env bash
# Exercises packaging/linux/install-bundle.sh with fake system tools; it never
# calls the real sudo, apt or usermod. Optional argument: an extracted release
# bundle directory whose real install.sh and packages are checked the same way.
set -euo pipefail

if (($# > 1)); then
  echo "Usage: $0 [extracted-bundle-dir]" >&2
  exit 2
fi
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
installer="$repo_root/packaging/linux/install-bundle.sh"
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/bin"
export HP_TEST_LOG="$test_root/calls"
export HP_TEST_ARCH=amd64
export HP_TEST_USER=alice
export PATH="$test_root/bin:$PATH"
unset SUDO_USER

cat >"$test_root/bin/sudo" <<'EOF'
#!/bin/sh
printf 'sudo %s\n' "$*" >>"$HP_TEST_LOG"
EOF
for tool in apt apt-get dpkg-deb usermod; do
  cat >"$test_root/bin/$tool" <<'EOF'
#!/bin/sh
echo "unexpected direct call: $0 $*" >&2
exit 99
EOF
done
cat >"$test_root/bin/dpkg" <<'EOF'
#!/bin/sh
test "$1" = --print-architecture || exit 99
echo "$HP_TEST_ARCH"
EOF
cat >"$test_root/bin/id" <<'EOF'
#!/bin/sh
test "$1" = -un || exit 99
echo "$HP_TEST_USER"
EOF
chmod +x "$test_root/bin/"*

case_number=0
new_bundle() {
  case_number=$((case_number + 1))
  bundle="$test_root/bundle-$case_number"
  mkdir -p "$bundle"
  install -m755 "$installer" "$bundle/install.sh"
  local package
  for package in "$@"; do
    printf 'fake %s\n' "$package" >"$bundle/$package"
  done
  (cd "$bundle" && if (($#)); then sha256sum -- "$@" >SHA256SUMS; else : >SHA256SUMS; fi)
}

expect_success() {
  local description=$1 expected
  : >"$HP_TEST_LOG"
  expected=$(cat)
  if ! (cd "$test_root" && bash "$bundle/install.sh" >"$test_root/out" 2>&1); then
    cat "$test_root/out" >&2
    echo "FAIL $description: installer failed" >&2
    exit 1
  fi
  diff -u <(printf '%s\n' "$expected") "$HP_TEST_LOG"
  echo "PASS $description"
}

expect_failure() {
  local description=$1 message=$2
  : >"$HP_TEST_LOG"
  if (cd "$test_root" && bash "$bundle/install.sh" >"$test_root/out" 2>&1); then
    echo "FAIL $description: installer unexpectedly succeeded" >&2
    exit 1
  fi
  if [[ -s $HP_TEST_LOG ]]; then
    cat "$HP_TEST_LOG" >&2
    echo "FAIL $description: privileged commands ran before refusal" >&2
    exit 1
  fi
  if ! grep -qF -- "$message" "$test_root/out"; then
    cat "$test_root/out" >&2
    echo "FAIL $description: missing message '$message'" >&2
    exit 1
  fi
  echo "PASS $description"
}

new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.7_amd64.deb
expect_success 'installs exactly the bundled pair and grants the admin group' <<'EOF'
sudo apt install -- ./homeproxy_9.8.7_amd64.deb ./homeproxy-desktop_9.8.7_amd64.deb
sudo usermod -aG homeproxy-admin alice
EOF
grep -qF 'HomeProxy 9.8.7 packages are installed.' "$test_root/out"
grep -qF 'Balíčky HomeProxy 9.8.7 jsou nainstalované.' "$test_root/out"
echo 'PASS reports the installed version in Czech and English'

SUDO_USER=bob HP_TEST_USER=root expect_success 'sudo invocation grants the group to the invoking user' <<'EOF'
sudo apt install -- ./homeproxy_9.8.7_amd64.deb ./homeproxy-desktop_9.8.7_amd64.deb
sudo usermod -aG homeproxy-admin bob
EOF

HP_TEST_USER=root expect_failure 'refuses a root session' 'Run this installer as a regular user on Ubuntu amd64.'
SUDO_USER=root expect_failure 'refuses sudo from root' 'běžný uživatel na Ubuntu amd64'
HP_TEST_ARCH=arm64 expect_failure 'refuses a non-amd64 system' 'Run this installer as a regular user on Ubuntu amd64.'

new_bundle homeproxy_9.8.7_amd64.deb
expect_failure 'refuses a missing desktop package' 'exactly one homeproxy and one homeproxy-desktop'
new_bundle homeproxy-desktop_9.8.7_amd64.deb
expect_failure 'refuses a missing server package' 'exactly one homeproxy and one homeproxy-desktop'
new_bundle homeproxy_9.8.7_amd64.deb homeproxy_9.8.6_amd64.deb homeproxy-desktop_9.8.7_amd64.deb
expect_failure 'refuses multiple server packages' 'exactly one homeproxy and one homeproxy-desktop'
new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.7_amd64.deb homeproxy-desktop_9.8.6_amd64.deb
expect_failure 'refuses multiple desktop packages' 'exactly one homeproxy and one homeproxy-desktop'
new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.6_amd64.deb
expect_failure 'refuses mismatched package versions' 'invalid or different versions'

new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.7_amd64.deb
rm -- "$bundle/SHA256SUMS"
expect_failure 'refuses a bundle without SHA256SUMS' 'SHA256SUMS is missing'

new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.7_amd64.deb
(cd "$bundle" && sha256sum -- homeproxy_9.8.7_amd64.deb >SHA256SUMS)
expect_failure 'refuses a package that SHA256SUMS does not cover' 'homeproxy-desktop_9.8.7_amd64.deb is not listed in SHA256SUMS'

new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.7_amd64.deb
printf 'tampered\n' >>"$bundle/homeproxy-desktop_9.8.7_amd64.deb"
expect_failure 'refuses a tampered package' 'Checksums do not match'

new_bundle homeproxy_9.8.7_amd64.deb homeproxy-desktop_9.8.7_amd64.deb
printf 'not-a-checksum  homeproxy-desktop_9.8.7_amd64.deb\n' >>"$bundle/SHA256SUMS"
expect_failure 'refuses a malformed SHA256SUMS line' 'Checksums do not match'

if (($# == 1)); then
  real_bundle=$(cd -- "$1" && pwd)
  : >"$HP_TEST_LOG"
  (cd "$test_root" && bash "$real_bundle/install.sh" >"$test_root/out" 2>&1) || {
    cat "$test_root/out" >&2
    echo "FAIL real bundle installer failed with fake system tools" >&2
    exit 1
  }
  mapfile -t calls <"$HP_TEST_LOG"
  if ((${#calls[@]} != 2)) ||
    [[ ! ${calls[0]} =~ ^sudo\ apt\ install\ --\ \./homeproxy_[^\ ]+_amd64\.deb\ \./homeproxy-desktop_[^\ ]+_amd64\.deb$ ]] ||
    [[ ${calls[1]} != "sudo usermod -aG homeproxy-admin alice" ]]; then
    printf '%s\n' "${calls[@]}" >&2
    echo 'FAIL real bundle produced unexpected privileged commands' >&2
    exit 1
  fi
  echo "PASS real bundle $real_bundle verifies and selects its packages"
fi
