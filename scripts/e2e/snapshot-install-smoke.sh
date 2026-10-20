#!/usr/bin/env bash
# Source-bound, native-architecture offline release-snapshot installer smoke.
# This does not tag/publish, mutate host networking, or prove Link recovery.
set -Eeuo pipefail
umask 077

fail() { printf 'SNAPSHOT_INSTALL_SMOKE_FAILED=%s\n' "$1" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail 'run as an unprivileged user'
[[ $(uname -s) == Linux ]] || fail 'Linux required'
for tool in git go sha256sum cmp mktemp; do
  command -v "$tool" >/dev/null || fail "missing $tool"
done

source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$source_root"
[[ -z "$(git status --porcelain)" ]] || fail 'clean committed checkout required'
source_sha="$(git rev-parse --verify HEAD)"
short_sha="$(git rev-parse --short=12 HEAD)"
[[ $source_sha =~ ^[0-9a-f]{40}$ && $short_sha =~ ^[0-9a-f]{12}$ ]] ||
  fail 'invalid Git identity'

case "$(uname -m):$(go env GOARCH)" in
  x86_64:amd64) arch=amd64 ;;
  aarch64:arm64) arch=arm64 ;;
  *) fail 'native amd64/arm64 kernel and Go architecture required' ;;
esac

# Shared /tmp may be a small tmpfs occupied by concurrent CI/tool jobs.
# Prefer the available disk-backed temporary location; do not clean other
# processes' scratch directories to obtain build capacity.
export TMPDIR="${TMPDIR:-/var/tmp}"
[[ -d $TMPDIR && -w $TMPDIR ]] || fail 'writable private scratch parent required'
scratch="$(mktemp -d "$TMPDIR/stl-snapshot-install.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -m 0700 "$scratch/prefix" "$scratch/prefix/bin" "$scratch/prefix/lib"

# Builder already requires a clean exact HEAD, records its commit and creates
# both architecture binaries, manifest and checksums without publishing.
GOTOOLCHAIN=local bash scripts/build-artifacts.sh --snapshot "$scratch/bundle"
(
  cd "$scratch/bundle"
  sha256sum --check SHA256SUMS
  grep -Fx "commit=$source_sha" BUILD-MANIFEST.txt >/dev/null ||
    fail 'manifest commit mismatch'
  grep -Fx "version=dev-$short_sha" BUILD-MANIFEST.txt >/dev/null ||
    fail 'manifest version mismatch'
  grep -Fx 'mode=snapshot' BUILD-MANIFEST.txt >/dev/null ||
    fail 'manifest mode mismatch'
)
native_binary="$scratch/bundle/stl_dev-${short_sha}_linux_${arch}"
[[ -x $native_binary ]] || fail 'native artifact missing'
native_sha="$(sha256sum "$native_binary" | awk '{print $1}')"

# Verify that each transferable package has precisely the allowed leaf files:
# no traversal, links, extra helper downloads, or mixed architecture binaries.
for packaged_arch in amd64 arm64; do
  archive="$scratch/bundle/stl_dev-${short_sha}_linux_${packaged_arch}_local-install.tar.gz"
  [[ -f $archive ]] || fail "missing local installation archive $packaged_arch"
  entries=$(tar -tzf "$archive") || fail 'cannot inspect local package archive'
  expected=$(printf '%s\n' "stl_dev-${short_sha}_linux_${packaged_arch}" install.sh \
    LICENSE BUILD-MANIFEST.txt LOCAL-INSTALL.txt SHA256SUMS)
  [[ $entries == "$expected" ]] || fail 'unexpected path, architecture or member in local archive'
  unpack="$scratch/archive-$packaged_arch"
  mkdir -m 0700 "$unpack"
  tar --extract --gzip --file "$archive" --directory "$unpack" \
    --no-same-owner --no-same-permissions || fail 'local package extraction failed'
  (cd "$unpack" && sha256sum --check SHA256SUMS >/dev/null) || fail 'local package checksum failed'
  cmp -s scripts/install.sh "$unpack/install.sh" || fail 'local installer differs from canonical source'
  bash -n "$unpack/install.sh" || fail 'local installer syntax invalid'
  [[ -x "$unpack/stl_dev-${short_sha}_linux_${packaged_arch}" ]] || fail 'local binary not executable'
done
native_package="$scratch/archive-$arch"

# Offline nondefault prefix: no package installation, /usr/local writes,
# privileged systemd calls, daemon activation, or network operations.
bash "$native_package/install.sh" install --bundle "$native_package" --prefix "$scratch/prefix"
installed="$scratch/prefix/bin/stl"
[[ -f $installed && -x $installed && -L "$scratch/prefix/bin/stlink" ]] ||
  fail 'installed executable or alias missing'
[[ "$(readlink "$scratch/prefix/bin/stlink")" == stl ]] ||
  fail 'alias does not point to the canonical binary'
cmp -s "$native_binary" "$installed" || fail 'installed binary differs from snapshot'
# Same-version local re-install is a safe no-op even through the copied script.
installed_inode=$(stat -c %i "$installed")
record="$scratch/prefix/lib/simple-tun-link/install-record"
record_hash=$(sha256sum "$record" | awk '{print $1}')
bash "$native_package/install.sh" install --bundle "$native_package" --prefix "$scratch/prefix"
[[ $(stat -c %i "$installed") == "$installed_inode" &&
   $(sha256sum "$record" | awk '{print $1}') == "$record_hash" ]] ||
  fail 'same-version local re-install modified the installed identity'
actual_version="$("$installed" version --json)"
alias_version="$("$scratch/prefix/bin/stlink" version --json)"
[[ $actual_version == "$alias_version" ]] || fail 'alias version mismatch'
[[ $actual_version == *"\"schema_version\":1"* &&
   $actual_version == *"\"version\":\"dev-$short_sha\""* &&
   $actual_version == *"\"commit\":\"$source_sha\""* ]] ||
  fail 'executable-reported identity mismatch'

# Canonical uninstall is intentionally NOT invoked here: the real binary
# checks the host's root-owned state and systemd restore-unit identity even
# for a custom offline prefix. CI runners do not guarantee either is safe or
# absent. The trap removes only this test's private temporary prefix.
# Offline uninstall transaction regression is owned by test-install.sh.
[[ -z "$(git status --porcelain)" ]] || fail 'smoke modified source checkout'

printf 'SNAPSHOT_NATIVE_ARCH=%s\n' "$arch"
printf 'SNAPSHOT_SOURCE_SHA=%s\n' "$source_sha"
printf 'SNAPSHOT_NATIVE_BINARY_SHA256=%s\n' "$native_sha"
echo 'SNAPSHOT_NATIVE_INSTALL_ALIAS=PASS'
echo 'SNAPSHOT_TRANSFERABLE_ARCH_BUNDLE=PASS'
echo 'SNAPSHOT_LOCAL_REINSTALL_NOOP=PASS'
