#!/usr/bin/env bash
# Turns existing build outputs into the public GitHub Release assets with
# stable names, so releases/latest/download/<name> links keep working.
#
#   check-version [TAG]               verify all manifests agree (and TAG == v<version>); prints the version
#   linux [OUT_DIR]                   Ubuntu bundle + versioned .deb files from target/linux-package
#   windows INSTALLER [OUT_DIR]       stable + versioned copies of the NSIS installer
#   finalize ASSET_DIR TAG NOTES_OUT  verify the complete asset set, write SHA256SUMS.txt and release notes
#
# OUT_DIR defaults to target/release-assets. Nothing here installs, uploads or signs.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

bundle_name=HomeProxy-Ubuntu-amd64
stable_tarball="$bundle_name.tar.gz"
stable_installer=HomeProxy-Setup-x64.exe
work=
trap '[[ -z $work ]] || rm -rf -- "$work"' EXIT

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

die() {
  echo "package-release-assets: $*" >&2
  exit 1
}

require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
  done
}

# Prints the single release version after checking every place that carries it.
check_version() {
  local tag=${1-}
  require_tools cargo node
  local script
  script=$(cat <<'JS'
const fs = require('fs');
const tag = process.argv[1] ?? '';
const fail = (message) => { console.error(`package-release-assets: ${message}`); process.exit(1); };
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const members = JSON.parse(input).packages.map((p) => [p.name, p.version]);
  const versions = new Set(members.map(([, v]) => v));
  if (members.length === 0 || versions.size !== 1) fail(`workspace crates disagree on the version: ${JSON.stringify(members)}`);
  const [version] = versions;
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(version)) fail(`unsupported release version: ${version}`);
  const lock = fs.readFileSync('Cargo.lock', 'utf8').replace(/\r\n/g, '\n');
  for (const [name] of members) {
    const entry = lock.match(new RegExp(`\\[\\[package\\]\\]\\nname = "${name}"\\nversion = "([^"]+)"\\n(?!source)`));
    if (!entry || entry[1] !== version) fail(`Cargo.lock has ${name} ${entry?.[1] ?? '(missing)'}, expected ${version}`);
  }
  const read = (path) => JSON.parse(fs.readFileSync(path, 'utf8'));
  const pkg = read('package.json');
  const pkgLock = read('package-lock.json');
  const tauri = read('src-tauri/tauri.conf.json');
  const tauriLinux = read('src-tauri/tauri.linux.conf.json');
  const checks = [
    ['package.json', pkg.version],
    ['package-lock.json', pkgLock.version],
    ['package-lock.json packages[""]', pkgLock.packages?.['']?.version],
    ['src-tauri/tauri.conf.json', tauri.version],
  ];
  for (const [where, found] of checks) {
    if (found !== version) fail(`${where} has version ${found}, expected ${version}`);
  }
  const depends = JSON.stringify(tauriLinux.bundle?.linux?.deb?.depends);
  if (depends !== JSON.stringify([`homeproxy (= ${version})`])) {
    fail(`src-tauri/tauri.linux.conf.json desktop dependency is ${depends}, expected homeproxy (= ${version})`);
  }
  if (tag !== '' && tag !== `v${version}`) fail(`tag ${tag} does not match the source version ${version} (expected v${version})`);
  console.log(version);
});
JS
)
  cargo metadata --locked --offline --no-deps --format-version 1 | node -e "$script" -- "$tag"
}

prepare_output_dir() {
  local dir=$1
  [[ -n $dir && ! -L $dir ]] || die "refusing unsafe output directory: $dir"
  mkdir -p -- "$dir"
  [[ -d $dir && ! -L $dir ]] || die "output is not a directory: $dir"
}

# Assets are copied, never moved, so the original build outputs stay intact.
copy_asset() {
  local source=$1 destination=$2 mode=$3
  [[ -f $source && ! -L $source ]] || die "missing regular build output: $source"
  if [[ -L $destination || (-e $destination && ! -f $destination) ]]; then
    die "refusing unsafe destination: $destination"
  fi
  rm -f -- "$destination"
  cp -- "$source" "$destination"
  chmod "$mode" -- "$destination"
}

source_date_epoch() {
  if [[ -n ${SOURCE_DATE_EPOCH-} ]]; then
    echo "$SOURCE_DATE_EPOCH"
  elif git -C "$repo_root" rev-parse --verify -q HEAD >/dev/null 2>&1; then
    git -C "$repo_root" log -1 --format=%ct
  else
    echo 0
  fi
}

check_deb() {
  local deb=$1 package=$2 version=$3
  [[ $(dpkg-deb --field "$deb" Package) == "$package" &&
     $(dpkg-deb --field "$deb" Version) == "$version" &&
     $(dpkg-deb --field "$deb" Architecture) == amd64 ]] ||
    die "$deb is not $package $version for amd64"
}

package_linux() {
  local out=${1:-target/release-assets}
  require_tools cargo node dpkg dpkg-deb sha256sum tar gzip
  local version server desktop bundle epoch
  version=$(check_version)
  [[ $(dpkg --print-architecture) == amd64 ]] || die 'Ubuntu release assets are built for amd64 only'
  server="target/linux-package/homeproxy_${version}_amd64.deb"
  desktop="target/linux-package/homeproxy-desktop_${version}_amd64.deb"
  check_deb "$server" homeproxy "$version"
  check_deb "$desktop" homeproxy-desktop "$version"
  prepare_output_dir "$out"

  work=$(mktemp -d)
  bundle="$work/$bundle_name"
  mkdir -m755 -- "$bundle"
  copy_asset "$server" "$bundle/${server##*/}" 644
  copy_asset "$desktop" "$bundle/${desktop##*/}" 644
  copy_asset packaging/linux/install-bundle.sh "$bundle/install.sh" 755
  (cd "$bundle" && sha256sum -- "${server##*/}" "${desktop##*/}" >SHA256SUMS && chmod 644 SHA256SUMS)

  # Reproducible archive: fixed order, owner and timestamps.
  epoch=$(source_date_epoch)
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -C "$work" -cf - "$bundle_name" | gzip -n -9 >"$work/$stable_tarball"
  copy_asset "$work/$stable_tarball" "$out/$stable_tarball" 644
  copy_asset "$server" "$out/${server##*/}" 644
  copy_asset "$desktop" "$out/${desktop##*/}" 644
  echo "$out/$stable_tarball"
}

package_windows() {
  (($# >= 1 && $# <= 2)) || usage
  local installer=$1 out=${2:-target/release-assets}
  require_tools cargo node sha256sum head
  local version expected
  version=$(check_version)
  expected="HomeProxy_${version}_x64-setup.exe"
  [[ ${installer##*[/\\]} == "$expected" ]] || die "installer must be the Tauri NSIS output $expected, got $installer"
  [[ -f $installer && ! -L $installer && -s $installer ]] || die "missing regular installer: $installer"
  [[ $(head -c 2 -- "$installer") == MZ ]] || die "installer is not a Windows executable: $installer"
  prepare_output_dir "$out"
  copy_asset "$installer" "$out/$stable_installer" 644
  copy_asset "$installer" "$out/$expected" 644
  [[ $(sha256sum <"$out/$stable_installer") == $(sha256sum <"$installer") ]] || die 'installer copy changed'
  echo "$out/$stable_installer"
}

finalize() {
  (($# == 3)) || usage
  local dir=$1 tag=$2 notes_out=$3
  require_tools sha256sum tar cmp sort
  [[ -d $dir && ! -L $dir ]] || die "asset directory does not exist: $dir"
  [[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)$ ]] || die "invalid release tag: $tag"
  local version=${BASH_REMATCH[1]}
  local server="homeproxy_${version}_amd64.deb"
  local desktop="homeproxy-desktop_${version}_amd64.deb"
  local versioned_installer="HomeProxy_${version}_x64-setup.exe"
  local -a assets
  local expected found name
  mapfile -t assets < <(printf '%s\n' "$stable_installer" "$versioned_installer" "$stable_tarball" "$server" "$desktop" | LC_ALL=C sort)
  expected=$(printf '%s\n' "${assets[@]}")
  found=$(cd "$dir" && find . -mindepth 1 -maxdepth 1 ! -name SHA256SUMS.txt -printf '%P\n' | LC_ALL=C sort)
  [[ $found == "$expected" ]] || die "unexpected release asset set in $dir:"$'\n'"$found"$'\n'"expected:"$'\n'"$expected"
  for name in "${assets[@]}"; do
    [[ -f $dir/$name && ! -L $dir/$name && -s $dir/$name ]] || die "asset is not a non-empty regular file: $name"
  done
  cmp -s -- "$dir/$stable_installer" "$dir/$versioned_installer" || die 'stable and versioned installers differ'

  # The tarball must hold exactly the installer folder, matching the loose .deb assets.
  local listing expected_listing
  work=$(mktemp -d)
  listing=$(tar -tvzf "$dir/$stable_tarball" | awk '{ print substr($1, 1, 1), $NF }' | LC_ALL=C sort)
  expected_listing=$(printf '%s\n' "d $bundle_name/" "- $bundle_name/SHA256SUMS" "- $bundle_name/install.sh" \
    "- $bundle_name/$server" "- $bundle_name/$desktop" | LC_ALL=C sort)
  [[ $listing == "$expected_listing" ]] || die "unexpected $stable_tarball layout:"$'\n'"$listing"
  tar -xzf "$dir/$stable_tarball" -C "$work" --no-same-owner
  (cd "$work/$bundle_name" && sha256sum --check --strict --quiet SHA256SUMS) || die 'bundle SHA256SUMS does not verify'
  cmp -s -- "$work/$bundle_name/$server" "$dir/$server" || die "bundled $server differs from the release asset"
  cmp -s -- "$work/$bundle_name/$desktop" "$dir/$desktop" || die "bundled $desktop differs from the release asset"
  cmp -s -- "$work/$bundle_name/install.sh" packaging/linux/install-bundle.sh || die 'bundled install.sh is not packaging/linux/install-bundle.sh'
  [[ -x $work/$bundle_name/install.sh ]] || die 'bundled install.sh is not executable'

  (cd "$dir" && sha256sum -- "${assets[@]}" >SHA256SUMS.txt)
  (cd "$dir" && sha256sum --check --strict --quiet SHA256SUMS.txt)

  local repository=${GITHUB_REPOSITORY-}
  if [[ -z $repository ]]; then
    repository=$(git -C "$repo_root" remote get-url origin 2>/dev/null |
      sed -nE 's#\.git$##; s#^(https://github\.com/|git@github\.com:)([^/]+/[^/]+)$#\2#p')
  fi
  [[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'set GITHUB_REPOSITORY=owner/repo'
  local notes
  notes=$(<.github/release-notes.md)
  notes=${notes//'{{VERSION}}'/$version}
  notes=${notes//'{{TAG}}'/$tag}
  notes=${notes//'{{REPOSITORY}}'/$repository}
  [[ $notes != *'{{'* ]] || die 'release notes template has an unknown placeholder'
  printf '%s\n' "$notes" >"$notes_out"
  echo "$dir/SHA256SUMS.txt"
}

command=${1-}
(($#)) && shift
case $command in
  check-version) (($# <= 1)) || usage; check_version "${1-}" ;;
  linux) (($# <= 1)) || usage; package_linux "${1-}" ;;
  windows) package_windows "$@" ;;
  finalize) finalize "$@" ;;
  *) usage ;;
esac
