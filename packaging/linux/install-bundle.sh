#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n%s\n' "$1" "$2" >&2
  exit 1
}

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
install_user="${SUDO_USER:-$(id -un)}"
if [[ "$install_user" == root || "$(dpkg --print-architecture)" != amd64 ]]; then
  fail 'Spusťte tento instalátor jako běžný uživatel na Ubuntu amd64.' \
    'Run this installer as a regular user on Ubuntu amd64.'
fi

# The bundle is version independent: it must contain exactly one server and one
# desktop package of the same version, and both must be covered by SHA256SUMS.
shopt -s nullglob
server_packages=(homeproxy_*_amd64.deb)
desktop_packages=(homeproxy-desktop_*_amd64.deb)
shopt -u nullglob
if ((${#server_packages[@]} != 1 || ${#desktop_packages[@]} != 1)); then
  fail 'Složka musí obsahovat právě jeden balíček homeproxy a jeden homeproxy-desktop (.deb pro amd64).' \
    'The folder must contain exactly one homeproxy and one homeproxy-desktop package (.deb for amd64).'
fi
server_package=${server_packages[0]}
desktop_package=${desktop_packages[0]}
server_version=${server_package#homeproxy_}
server_version=${server_version%_amd64.deb}
desktop_version=${desktop_package#homeproxy-desktop_}
desktop_version=${desktop_version%_amd64.deb}
if [[ ! $server_version =~ ^[0-9][0-9A-Za-z.+~-]*$ || $server_version != "$desktop_version" ]]; then
  fail 'Balíčky homeproxy a homeproxy-desktop mají neplatnou nebo rozdílnou verzi.' \
    'The homeproxy and homeproxy-desktop packages have invalid or different versions.'
fi

if [[ ! -f SHA256SUMS ]]; then
  fail 'Chybí soubor SHA256SUMS; stáhněte balíček znovu.' \
    'SHA256SUMS is missing; download the bundle again.'
fi
for package in "$server_package" "$desktop_package"; do
  if ! awk -v name="$package" '$2 == name || $2 == "*" name { found = 1 } END { exit !found }' SHA256SUMS; then
    fail "Soubor $package není uvedený v SHA256SUMS; stáhněte balíček znovu." \
      "$package is not listed in SHA256SUMS; download the bundle again."
  fi
done
if ! sha256sum --check --strict SHA256SUMS; then
  fail 'Kontrolní součty nesouhlasí; stáhněte balíček znovu.' \
    'Checksums do not match; download the bundle again.'
fi

sudo apt install -- "./$server_package" "./$desktop_package"
sudo usermod -aG homeproxy-admin "$install_user"
echo "Balíčky HomeProxy $server_version jsou nainstalované. HomeProxy otevřete z nabídky aplikací."
echo 'Odhlaste se a znovu přihlaste, aby se projevilo oprávnění ke správě HomeProxy.'
echo "HomeProxy $server_version packages are installed. Open HomeProxy from the applications menu."
echo 'Sign out and back in so the permission to manage HomeProxy takes effect.'
