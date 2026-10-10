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
elif [ "\$1" = maintenance ] && [ "\$2" = pre-uninstall ] && [ "\$3" = --json ]; then
  if [ "\${STL_INSTALL_TEST_LINKS:-0}" = 1 ]; then
    echo '{"schema_version":1,"ready":false}'
    exit 1
  else
    echo '{"schema_version":1,"ready":true}'
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
# Uninstall must unlink the canonical executable, not move the live inode
# into the retained journal (which would obscure /proc/self/exe identity).
shopt -s nullglob
retired=("$prefix/bin"/.stl-install.*)
shopt -u nullglob
[[ ${#retired[@]} -eq 1 && -f ${retired[0]}/previous-stl && ! -e ${retired[0]}/removed-stl ]] || fail 'uninstall incorrectly retained a moved live executable inode'
# A fresh install validates and retires the completed-uninstall journal.
bash "$installer" install --bundle "$root/v0.1.0" --prefix "$prefix" > /dev/null
[[ $(sha "$prefix/bin/stl") == "$original" ]] || fail 'reinstall following committed uninstall produced wrong binary'

# An untrustworthy backup must not be silently discarded after publication.
# Retain recovery data, report the partial state, and block blind retries.
quarantine="$root/ambiguous-prefix"
mkdir -p "$quarantine/bin" "$quarantine/lib"
bash "$installer" install --bundle "$root/v0.1.0" --prefix "$quarantine"
expect_failure env STL_INSTALL_TEST_CORRUPT_BACKUP=1 bash "$installer" update --bundle "$root/v0.1.1" --prefix "$quarantine"
grep -q 'partial failure; inspect retained recovery directory:' "$root/err" || fail 'uncertain update failed without recovery warning'
[[ $(sha "$quarantine/bin/stl") == "$(sha "$root/v0.1.1/stl_v0.1.1_linux_amd64")" ]] || fail 'unexpected binary identity after uncertain update'
[[ $(grep '^version=' "$quarantine/lib/simple-tun-link/install-record") == version=v0.1.0 ]] || fail 'unexpected record identity after uncertain update'
shopt -s nullglob
recoveries=("$quarantine/bin"/.stl-install.*)
shopt -u nullglob
[[ ${#recoveries[@]} -eq 1 && -f ${recoveries[0]}/previous-stl ]] || fail 'uncertain recovery material was discarded'
expect_failure bash "$installer" update --bundle "$root/v0.1.1" --prefix "$quarantine"
grep -q 'unreconciled STL installer recovery directory' "$root/err" || fail 'blind retry did not fail closed'

# R1: a failed/incomplete installer fetch must not invoke sudo on a syntactically
# complete prefix. Model the documented private-download-before-sudo boundary.
mkdir -p "$root/fakebin"
cat > "$root/fakebin/curl" <<'CURL'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ $1 == -o ]]; then shift; output=$1; break; fi
  shift
done
printf 'exit 0\n' > "$output"
exit 18 # simulated broken transport after a syntactically valid prefix
CURL
cat > "$root/fakebin/sudo" <<'SUDO'
#!/usr/bin/env bash
echo privileged-installer-executed > "$STL_TEST_SUDO_MARKER"
exit 0
SUDO
chmod 0755 "$root/fakebin/curl" "$root/fakebin/sudo"
export STL_TEST_SUDO_MARKER="$root/sudo-was-executed"
expect_failure env PATH="$root/fakebin:$PATH" bash -c 'set -euo pipefail; umask 077; t=$(mktemp); trap '\''rm -f -- "$t"'\'' EXIT; curl -fLSs -o "$t" https://example.invalid/installer; bash -n "$t"; sudo bash "$t" install --version v0.1.0'
[[ ! -e $STL_TEST_SUDO_MARKER ]] || fail 'partial network delivery executed privileged code'

# R2: explicit pre-publication, post-rename, and record-sync failure seams.
for point in prepublish-sync post-executable-sync record-sync; do
  recovered="$root/recovered-$point"
  mkdir -p "$recovered/bin" "$recovered/lib"
  bash "$installer" install --bundle "$root/v0.1.0" --prefix "$recovered" > /dev/null
  expect_failure env STL_INSTALL_TEST_FAIL_AT="$point" bash "$installer" update --bundle "$root/v0.1.1" --prefix "$recovered"
  [[ $(sha "$recovered/bin/stl") == "$original" ]] || fail "$point failed to restore exact original binary"
  [[ $(grep '^version=' "$recovered/lib/simple-tun-link/install-record") == version=v0.1.0 ]] || fail "$point failed to restore ownership record"
  [[ $(readlink "$recovered/bin/stlink") == stl ]] || fail "$point damaged alias"
done

# Failed compensation durability must keep recovery evidence, even when all
# visible canonical paths appear restored.
compensating="$root/compensation-uncertain"
mkdir -p "$compensating/bin" "$compensating/lib"
bash "$installer" install --bundle "$root/v0.1.0" --prefix "$compensating" > /dev/null
expect_failure env STL_INSTALL_TEST_FAIL_AFTER_SWAP=1 STL_INSTALL_TEST_FAIL_AT=compensation-sync bash "$installer" update --bundle "$root/v0.1.1" --prefix "$compensating"
grep -q 'partial failure; inspect retained recovery directory' "$root/err" || fail 'uncertain compensation discarded evidence'
shopt -s nullglob
uncertain=("$compensating/bin"/.stl-install.*)
shopt -u nullglob
[[ ${#uncertain[@]} -eq 1 && -f ${uncertain[0]}/previous-stl ]] || fail 'missing durable recovery copy after compensation uncertainty'
expect_failure bash "$installer" update --bundle "$root/v0.1.1" --prefix "$compensating"
grep -q 'unreconciled STL installer recovery directory' "$root/err" || fail 'retry crossed incomplete rollback state'

# Committed journal is retained until a later invocation verifies canonical
# identity; a successful idempotent retry durably retires it.
committed="$root/committed"
mkdir -p "$committed/bin" "$committed/lib"
bash "$installer" install --bundle "$root/v0.1.0" --prefix "$committed" > /dev/null
shopt -s nullglob
markers=("$committed/bin"/.stl-install.*)
shopt -u nullglob
[[ ${#markers[@]} -eq 1 && -f ${markers[0]}/COMMITTED ]] || fail 'missing durable committed journal'
# A syntactically complete but corrupt/inconsistent COMMITTED must never
# be retired. This exercises the same strict journal v1 grammar as the Go gate.
marker="${markers[0]}/COMMITTED"
cp -p -- "$marker" "$root/known-good-committed"
for kind in empty status-only unknown extra wrong-hash; do
  case "$kind" in
    empty) : > "$marker" ;;
    status-only) printf 'status=committed\n' > "$marker" ;;
    unknown) printf 'status=committed\noperation=foreign\nsha256=%s\n' "$(sha "$committed/bin/stl")" > "$marker" ;;
    extra) cp "$root/known-good-committed" "$marker"; printf 'extra=1\n' >> "$marker" ;;
    wrong-hash) printf 'status=committed\noperation=install\nsha256=%064d\n' 0 > "$marker" ;;
  esac
  expect_failure bash "$installer" update --bundle "$root/v0.1.0" --prefix "$committed"
  [[ $(sha "$committed/bin/stl") == "$original" ]] || fail "$kind journal corruption mutated canonical binary"
  [[ -f $marker ]] || fail "$kind journal corruption was silently retired"
done
cp -p -- "$root/known-good-committed" "$marker"
bash "$installer" update --bundle "$root/v0.1.0" --prefix "$committed" > /dev/null
shopt -s nullglob
markers=("$committed/bin"/.stl-install.*)
shopt -u nullglob
[[ ${#markers[@]} -eq 0 ]] || fail 'verified committed journal not retired'

# R3: a separately forked shared Engine-like flock must exclude an installer
# transaction until the shared holder exits; normal Link work uses SH locks.
concurrent="$root/maintenance-concurrent"
mkdir -p "$concurrent/bin" "$concurrent/lib"
bash "$installer" install --bundle "$root/v0.1.0" --prefix "$concurrent" > /dev/null
mkfifo "$root/release-gate"
(
  exec 8>>"$concurrent/lib/simple-tun-link/.maintenance.lock"
  flock -s 8
  touch "$root/gate-acquired"
  read -r _ < "$root/release-gate"
) &
holder=$!
for ((i=0;i<100;i++)); do
  [[ -e $root/gate-acquired ]] && break
  sleep 0.01
done
[[ -e $root/gate-acquired ]] || fail 'shared gate helper could not obtain maintenance lock'
bash "$installer" update --bundle "$root/v0.1.1" --prefix "$concurrent" > "$root/concurrent-out" 2> "$root/concurrent-err" &
updater=$!
sleep 0.12
[[ $(sha "$concurrent/bin/stl") == "$original" ]] || fail 'exclusive update crossed active shared mutation'
kill -0 "$updater" 2>/dev/null || fail 'installer exited instead of waiting on shared maintenance lock'
printf 'release\n' > "$root/release-gate"
wait "$holder"
wait "$updater" || fail 'installer failed after shared maintenance gate released'
[[ $(sha "$concurrent/bin/stl") == "$(sha "$root/v0.1.1/stl_v0.1.1_linux_amd64")" ]] || fail 'queued update did not publish after release'

# The full offline suite also covers the distro-aware APT planner.
bash "$(dirname "$0")/test-install-requirements.sh"

# Explicit all-backend selection still never touches the real host's APT
# when the installer targets a disposable offline prefix.
no_host_packages="$root/optional-dependencies"
mkdir -p "$no_host_packages/bin" "$no_host_packages/lib"
bash "$installer" install --bundle "$root/v0.1.0" --prefix "$no_host_packages" --backends all >/dev/null
[[ -x $no_host_packages/bin/stl ]] || fail 'offline all-backend installation did not publish STL'

printf 'Installer offline checks PASS (integrity, concurrency gate, durability failure seams, rollback, and recovery journals).\n'
