#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--debug]" >&2
  exit 2
}

build_profile=release
case "${1-}" in
  "") ;;
  --debug) build_profile=debug ;;
  *) usage ;;
esac
if (($# > 1)); then usage; fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

for tool in cargo dpkg-deb dpkg readelf ldd python3 install; do
  command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done

version=$(cargo metadata --locked --offline --no-deps --format-version 1 |
  python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "homeproxy-service"))')

cargo_args=(build --locked --offline -p homeproxy-service -p homeproxy-cli)
if [[ $build_profile == release ]]; then cargo_args+=(--release); fi
cargo "${cargo_args[@]}"

binary_dir="$repo_root/target/$build_profile"
for binary in homeproxyd homeproxy; do
  linked_libraries=$(ldd "$binary_dir/$binary")
  if grep -q 'not found' <<<"$linked_libraries"; then
    echo "Unresolved shared library in $binary" >&2
    exit 1
  fi
  if grep -Eq 'lib(gtk|webkit|javascriptcore)' <<<"$linked_libraries"; then
    echo "Server binary unexpectedly depends on desktop libraries: $binary" >&2
    exit 1
  fi
done

glibc_min=$(readelf --version-info "$binary_dir/homeproxyd" "$binary_dir/homeproxy" |
  grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' |
  sed 's/^GLIBC_//' | sort -Vu | tail -1)
if [[ -z $glibc_min ]]; then echo 'Cannot determine required glibc version' >&2; exit 1; fi

depends="adduser, ca-certificates, libc6 (>= $glibc_min), systemd"
if grep -q 'libgcc_s.so' <<<"$(ldd "$binary_dir/homeproxyd" "$binary_dir/homeproxy")"; then
  depends="$depends, libgcc-s1"
fi

architecture=$(dpkg --print-architecture)
stage="$repo_root/target/linux-package/stage"
artifact="$repo_root/target/linux-package/homeproxy_${version}_${architecture}.deb"
rm -rf -- "$stage"
mkdir -p "$stage/DEBIAN"
install -Dm755 "$binary_dir/homeproxyd" "$stage/usr/bin/homeproxyd"
install -Dm755 "$binary_dir/homeproxy" "$stage/usr/bin/homeproxy"
install -Dm644 packaging/linux/homeproxy.service "$stage/usr/lib/systemd/system/homeproxy.service"
install -Dm644 docs/ubuntu-server.md "$stage/usr/share/doc/homeproxy/ubuntu-server.md"
install -Dm644 LICENSE "$stage/usr/share/doc/homeproxy/copyright"
for script in postinst prerm postrm; do
  install -m755 "packaging/linux/$script" "$stage/DEBIAN/$script"
done
cat >"$stage/DEBIAN/control" <<EOF
Package: homeproxy
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Maintainer: HomeProxy project
Homepage: https://homeproxy.thetasigma.io
Depends: $depends
Description: Local HomeProxy daemon and command line client
 Explicit HTTP and SOCKS5 proxy with a local Unix-socket control interface.
 The proxy is disabled until explicitly configured and started.
EOF

dpkg-deb --build --root-owner-group "$stage" "$artifact"
echo "$artifact"
