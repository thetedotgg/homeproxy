#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/bin"
export HP_TEST_LOG="$test_root/calls"
export HP_TEST_WAS_ENABLED=yes
export PATH="$test_root/bin:$PATH"

cat >"$test_root/bin/getent" <<'EOF'
#!/bin/sh
case "$1:$2" in
    group:homeproxy-admin) echo 'homeproxy-admin:x:999:' ;;
    passwd:homeproxy) echo 'homeproxy:x:999:999::/var/lib/homeproxy:/usr/sbin/nologin' ;;
    *) exit 2 ;;
esac
EOF
cat >"$test_root/bin/id" <<'EOF'
#!/bin/sh
test "$1:$2" = '-gn:homeproxy' && echo homeproxy-admin
EOF
cat >"$test_root/bin/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$HP_TEST_LOG"
EOF
cat >"$test_root/bin/deb-systemd-helper" <<'EOF'
#!/bin/sh
printf 'helper %s\n' "$*" >>"$HP_TEST_LOG"
if [ "$1" = --quiet ] && [ "$2" = was-enabled ]; then
    [ "$HP_TEST_WAS_ENABLED" = yes ]
fi
EOF
cat >"$test_root/bin/deb-systemd-invoke" <<'EOF'
#!/bin/sh
printf 'invoke %s\n' "$*" >>"$HP_TEST_LOG"
EOF
chmod +x "$test_root/bin/"*

assert_log() {
    local expected="$test_root/expected"
    cat >"$expected"
    diff -u "$expected" "$HP_TEST_LOG"
    : >"$HP_TEST_LOG"
}

: >"$HP_TEST_LOG"
sh "$repo_root/packaging/linux/postinst" configure ''
assert_log <<'EOF'
systemctl daemon-reload
helper unmask homeproxy.service
helper --quiet was-enabled homeproxy.service
helper enable homeproxy.service
invoke start homeproxy.service
EOF
echo 'PASS fresh install enables and starts the service'

sh "$repo_root/packaging/linux/postinst" configure 1.1.2
assert_log <<'EOF'
systemctl daemon-reload
helper unmask homeproxy.service
helper --quiet was-enabled homeproxy.service
helper enable homeproxy.service
invoke restart homeproxy.service
EOF
echo 'PASS enabled service remains enabled on upgrade'

HP_TEST_WAS_ENABLED=no
export HP_TEST_WAS_ENABLED
sh "$repo_root/packaging/linux/postinst" configure 1.1.2
assert_log <<'EOF'
systemctl daemon-reload
helper unmask homeproxy.service
helper --quiet was-enabled homeproxy.service
helper update-state homeproxy.service
invoke restart homeproxy.service
EOF
echo 'PASS administrator-disabled service remains disabled on upgrade'

sh "$repo_root/packaging/linux/postrm" remove
assert_log <<'EOF'
systemctl daemon-reload
helper mask homeproxy.service
EOF
echo 'PASS removal records a package-owned mask'

sh "$repo_root/packaging/linux/postrm" purge
assert_log <<'EOF'
systemctl daemon-reload
helper purge homeproxy.service
helper unmask homeproxy.service
EOF
echo 'PASS purge clears package state and its mask'
