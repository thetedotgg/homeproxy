#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "Usage: $0" >&2
  exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

for tool in cargo dpkg dpkg-deb python3 install; do
  command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done
if [[ ! -x node_modules/.bin/tauri ]]; then
  echo 'Local Tauri CLI is missing; restore the locked Node dependencies before building' >&2
  exit 1
fi

version=$(cargo metadata --locked --offline --no-deps --format-version 1 |
  python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "homeproxy-service"))')
architecture=$(dpkg --print-architecture)
server_package="$repo_root/target/linux-package/homeproxy_${version}_${architecture}.deb"
if [[ ! -f $server_package ]]; then
  echo "Build the matching server package first: scripts/build-linux.sh" >&2
  exit 1
fi
if [[ $(dpkg-deb --field "$server_package" Package) != homeproxy ||
      $(dpkg-deb --field "$server_package" Version) != "$version" ]]; then
  echo 'Existing server package does not match the workspace version' >&2
  exit 1
fi

python3 - "$version" <<'PY'
import json
import sys
from pathlib import Path

base = json.loads(Path('src-tauri/tauri.conf.json').read_text())
linux = json.loads(Path('src-tauri/tauri.linux.conf.json').read_text())
version = sys.argv[1]
if base.get('version') != version:
    raise SystemExit('Desktop version does not match the server workspace version')
if linux.get('productName') != 'Homeproxy Desktop':
    raise SystemExit('Linux productName must yield the separate homeproxy-desktop package')
if linux['bundle']['linux']['deb'].get('depends') != [f'homeproxy (= {version})']:
    raise SystemExit('Desktop must depend on the matching server package version')
if linux.get('app', {}).get('enableGTKAppId') is not True:
    raise SystemExit('Linux must enable the GTK application ID for dock integration')
if not base.get('bundle', {}).get('icon'):
    raise SystemExit('Desktop must configure application icons')
PY

built_package="$repo_root/target/release/bundle/deb/Homeproxy Desktop_${version}_${architecture}.deb"
rm -f -- "$built_package"
# Tauri automatically merges tauri.linux.conf.json. CARGO_NET_OFFLINE prevents
# a build from silently downloading crates; Node uses the checked-in local CLI.
CARGO_NET_OFFLINE=true node_modules/.bin/tauri build --ci --no-sign --bundles deb -- --locked --offline

if [[ ! -f $built_package ]]; then
  echo "Tauri did not produce the expected desktop package: $built_package" >&2
  exit 1
fi
if [[ $(dpkg-deb --field "$built_package" Package) != homeproxy-desktop ||
      $(dpkg-deb --field "$built_package" Version) != "$version" ]]; then
  echo 'Desktop .deb has an unexpected name or version' >&2
  exit 1
fi
desktop_depends=$(dpkg-deb --field "$built_package" Depends)
if [[ $desktop_depends != *"homeproxy (= $version)"* ]]; then
  echo 'Desktop .deb lost its exact server package dependency' >&2
  exit 1
fi

# Tauri 2.12 names the entry after productName even when enableGTKAppId is on.
# GNOME/Wayland resolves the GTK app ID to <identifier>.desktop instead.
# Keep the separate package name and normalize only the launcher filename.
package_stage=$(mktemp -d)
trap 'rm -rf -- "$package_stage"' EXIT
dpkg-deb --raw-extract "$built_package" "$package_stage"
python3 - "$package_stage" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

stage = Path(sys.argv[1])
base = json.loads(Path('src-tauri/tauri.conf.json').read_text())
linux = json.loads(Path('src-tauri/tauri.linux.conf.json').read_text())
entries = stage / 'usr/share/applications'
source = entries / f'{linux["productName"]}.desktop'
destination = entries / f'{base["identifier"]}.desktop'
if destination != source and destination.exists():
    raise SystemExit('Desktop identity collides with another packaged launcher')
source.rename(destination)
# Preserve correct integrity metadata if the bundler starts supplying md5sums.
md5sums = stage / 'DEBIAN/md5sums'
if md5sums.exists():
    md5sums.write_text(''.join(
        f'{hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()}  {path.relative_to(stage)}\n'
        for path in sorted(stage.rglob('*'))
        if path.is_file() and not path.is_symlink() and 'DEBIAN' not in path.relative_to(stage).parts
    ))
PY
dpkg-deb --build --root-owner-group "$package_stage" "$built_package"

# Validate the final archive, not just config/source assets. Missing icons must
# fail the build rather than produce another installable but blank launcher.
python3 - "$built_package" <<'PY'
import configparser
import io
import json
import struct
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

base = json.loads(Path('src-tauri/tauri.conf.json').read_text())
identity = base['identifier']
archive = subprocess.run(['dpkg-deb', '--fsys-tarfile', sys.argv[1]], check=True, stdout=subprocess.PIPE).stdout
with tarfile.open(fileobj=io.BytesIO(archive)) as payload:
    members = {member.name.removeprefix('./'): member for member in payload.getmembers() if member.isfile()}
    launchers = [name for name in members if name.startswith('usr/share/applications/') and name.endswith('.desktop')]
    expected = f'usr/share/applications/{identity}.desktop'
    if launchers != [expected]:
        raise SystemExit('Desktop .deb must contain exactly the GTK-identity launcher')
    entry = configparser.ConfigParser(interpolation=None, strict=True)
    entry.read_string(payload.extractfile(members[expected]).read().decode())
    desktop = entry['Desktop Entry']
    if desktop.get('StartupWMClass') != identity or desktop.get('Name') != 'HomeProxy':
        raise SystemExit('Desktop .deb launcher does not match the native window identity')
    if desktop.get('Type') != 'Application' or desktop.get('Terminal') != 'false':
        raise SystemExit('Desktop .deb launcher is not a graphical application')
    if desktop.get('Exec') != 'klidna-sit' or 'usr/bin/klidna-sit' not in members:
        raise SystemExit('Desktop .deb launcher does not resolve to the packaged executable')
    icon = desktop.get('Icon', '')
    if not icon or PurePosixPath(icon).name != icon or '.' in icon:
        raise SystemExit('Desktop .deb launcher must use an icon theme name')
    for size in (32, 64, 128, 512):
        name = f'usr/share/icons/hicolor/{size}x{size}/apps/{icon}.png'
        if name not in members:
            raise SystemExit(f'Desktop .deb is missing its {size}px launcher icon')
        data = payload.extractfile(members[name]).read()
        if len(data) < 24 or data[:8] != b'\x89PNG\r\n\x1a\n' or struct.unpack('>II', data[16:24]) != (size, size):
            raise SystemExit(f'Desktop .deb has an invalid {size}px launcher icon')
        if data != Path(f'src-tauri/icons/{"icon" if size == 512 else f"{size}x{size}"}.png').read_bytes():
            raise SystemExit(f'Desktop .deb does not contain the current {size}px artwork')
PY

output="$repo_root/target/linux-package/homeproxy-desktop_${version}_${architecture}.deb"
install -m644 "$built_package" "$output"
echo "$output"
