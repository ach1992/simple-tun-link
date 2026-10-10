#!/usr/bin/env bash
# Nonprivileged, offline acceptance of installer transactional behavior.
set -Eeuo pipefail
umask 077
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
installer="$(cd "$(dirname "$0")" && pwd -P)/install.sh"
prefix="$root/prefix"
mkdir -p "$prefix/bin" "$prefix/lib"

fail() { printf 'install test FAILED: %s\n' "$*" >&2; exit 1; }
expect_failure() { if "$@" >"$root/out" 2>"$root/err"; then fail "unexpected success: $*"; fi; }
sha() { sha256sum -- "$1" | awk '{print $1}'; }
bundle() {
  local version=$1 commit=$2 dir="$root/$1"
  mkdir -p "$dir"
  cat > "$dir/stl_${version}_linux_amd64" <<SCRIPT
#!/bin/sh
if [ "\$1" = version ] && [ "\$2" = --json ]; then
  echo '{"schema_version":1,"version":"$version","commit":"$commit","date":"2026-10-10T00:00:00Z"}'
elif [ "\$1" = link ] && [ "\$2" = list ] && [ "\$3" = --json ]; then
  if [ "\${STL_INSTALL_TEST_LINKS:-0}" = 1 ]; then
    echo '{"schema_version":1,"links":[{"id":"lnk_synthetic"}]}'
  else
    echo '{"schema_version":1,"links":[]}'
  fi
else
  exit 2
fi
SCRIPT
  chmod 0755 "$dir/stl_${version}_linux_amd64"
  printf 'MIT License\n' > "$dir/LICENSE"
  cat > "$dir/BUILD-MANIFEST.txt" <<MANIFEST
project=simple-tun-link
executable=stl
license=MIT
version=$version
commit=$commit
build_date=2026-10-10T00:00:00Z
platforms=linux/amd64 linux/arm64
source=https://github.com/ach1992/simple-tun-link
mode=tag
MANIFEST
  (cd "$dir" && sha256sum "stl_${version}_linux_amd64" LICENSE BUILD-MANIFEST.txt > SHA256SUMS)
}
bundle v0.1.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bundle v0.1.1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
[[ $(uname -m) == x86_64 ]] || { echo 'SKIP: amd64 offline installer test fixture'; exit 0; }

# Unowned binaries and aliases are never taken over.
printf 'foreign\n' > "$prefix/bin/stl"
expect_failure bash "$installer" install --bundle "$root/v0.1.0" --prefix "$prefix"
[[ $(cat "$prefix/bin/stl") == foreign ]] || fail 'foreign binary changed'
rm -- "$prefix/bin/stl"

# Verify before publishing; a corrupt download cannot create an executable.
cp -a "$root/v0.1.0" "$root/corrupt"
printf 'tamper\n' >> "$root/corrupt/stl_v0.1.0_linux_amd64"
expect_failure bash "$installer" install --bundle "$root/corrupt" --prefix "$prefix"
[[ ! -e $prefix/bin/stl ]] || fail 'published unverified binary'

bash "$installer" install --bundle "$root/v0.1.0" --prefix "$prefix"
[[ -f $prefix/bin/stl && -L $prefix/bin/stlink && $(readlink "$prefix/bin/stlink") == stl ]] || fail 'canonical binary/alias not installed'
original=$(sha "$prefix/bin/stl")
[[ $original == "$(sha "$root/v0.1.0/stl_v0.1.0_linux_amd64")" ]] || fail 'wrong installed build'
expect_failure bash "$installer" install --bundle "$root/v0.1.1" --prefix "$prefix"
expect_failure bash "$installer" update --bundle "$root/corrupt" --prefix "$prefix"
[[ $(sha "$prefix/bin/stl") == "$original" ]] || fail 'corrupt update modified binary'

# After the executable rename but before record publication, rollback must
# restore the old executable byte-for-byte, with no alias or metadata drift.
expect_failure env STL_INSTALL_TEST_FAIL_AFTER_SWAP=1 bash "$installer" update --bundle "$root/v0.1.1" --prefix "$prefix"
[[ $(sha "$prefix/bin/stl") == "$original" ]] || fail 'failed update did not restore prior executable'
[[ $(grep '^version=' "$prefix/lib/simple-tun-link/install-record") == version=v0.1.0 ]] || fail 'failed update modified install record'
[[ $(readlink "$prefix/bin/stlink") == stl ]] || fail 'failed update broke alias'

bash "$installer" update --bundle "$root/v0.1.1" --prefix "$prefix"
[[ $(sha "$prefix/bin/stl") == "$(sha "$root/v0.1.1/stl_v0.1.1_linux_amd64")" ]] || fail 'new binary was not published'
[[ $(grep '^version=' "$prefix/lib/simple-tun-link/install-record") == version=v0.1.1 ]] || fail 'record not updated'
bash "$installer" update --bundle "$root/v0.1.1" --prefix "$prefix" # idempotent no-op

# The canonical reader (not a duplicate state parser) guards uninstall.
expect_failure env STL_INSTALL_TEST_LINKS=1 bash "$installer" uninstall --prefix "$prefix"
[[ -f $prefix/bin/stl && -L $prefix/bin/stlink ]] || fail 'Links guard changed installation'

# Local modification makes the ownership record insufficient for deletion.
printf 'tamper\n' >> "$prefix/bin/stl"
expect_failure bash "$installer" uninstall --prefix "$prefix"
[[ -f $prefix/bin/stl ]] || fail 'uninstall removed modified executable'
# Recreate only inside the disposable prefix to finish the lifecycle test.
cp "$root/v0.1.1/stl_v0.1.1_linux_amd64" "$prefix/bin/stl"
chmod 0755 "$prefix/bin/stl"
expect_failure env STL_INSTALL_TEST_FAIL_AFTER_UNINSTALL_REMOVE=1 bash "$installer" uninstall --prefix "$prefix"
[[ -f $prefix/bin/stl && -L $prefix/bin/stlink && -f $prefix/lib/simple-tun-link/install-record ]] || fail 'failed uninstall did not restore all installed identities'
bash "$installer" uninstall --prefix "$prefix"
[[ ! -e $prefix/bin/stl && ! -L $prefix/bin/stlink && ! -e $prefix/lib/simple-tun-link/install-record ]] || fail 'uninstall left installed artifacts'

printf 'Installer offline checks PASS (install, verified update, rollback, ownership, Link guard, uninstall).\n'
