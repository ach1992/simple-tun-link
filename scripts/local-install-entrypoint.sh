#!/usr/bin/env bash
# Generated single-file local entrypoint. The builder replaces the @...@ fields
# and appends the verified architecture-specific local archive after 'exit'.
# This is only a bootstrap: scripts/install.sh owns the installation transaction.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

fail() { printf 'stl local install [FAILED]: %s\n' "$*" >&2; exit 1; }
version='@VERSION@'
commit='@COMMIT@'
architecture='@ARCH@'
archive_name='@ARCHIVE@'
archive_sha256='@DIGEST@'
archive_bytes=@BYTES@

prefix=/usr/local
prefix_set=0
enable_wss=0
# An optional archive alone never consents to Carrier installation.
while (( $# > 0 )); do
  case "$1" in
    --prefix)
      [[ $# -ge 2 && $prefix_set == 0 ]] ||
        fail 'provide --prefix once with an absolute path'
      prefix=$2
      prefix_set=1
      shift 2
      ;;
    --with-wss)
      [[ $enable_wss == 0 ]] || fail 'duplicate --with-wss'
      enable_wss=1
      shift
      ;;
    *) fail 'usage: bash stl_<version>_linux_<arch>_local-install.sh [--prefix /existing/isolated/prefix] [--with-wss]' ;;
  esac
done
[[ $(uname -s) == Linux ]] || fail 'Linux required'
case $(uname -m) in
  x86_64) actual_arch=amd64 ;;
  aarch64) actual_arch=arm64 ;;
  *) fail 'unsupported CPU architecture (requires x86_64 or aarch64)' ;;
esac
[[ $actual_arch == "$architecture" ]] ||
  fail "wrong file for $(uname -m); download the official linux/$actual_arch local installer"
[[ $prefix != /usr/local || $EUID == 0 ]] ||
  fail 'system installation requires root; use sudo bash ...'
[[ $prefix == /* && $prefix != / ]] || fail 'prefix must be an absolute directory'

source=${BASH_SOURCE[0]}
[[ $source == /* && -f $source && ! -L $source &&
   $(realpath -e -- "$source") == "$source" ]] ||
  fail 'run the transferred file by its canonical absolute path (no symlinks)'
source_name=$(basename -- "$source")
[[ $source_name == "stl_${version}_linux_${architecture}_local-install.sh" ]] ||
  fail 'unexpected installer filename; transfer the official file unchanged'
[[ $(stat -c %u -- "$source") == "$EUID" ]] ||
  fail 'transferred file must belong to the executing administrator'
mode=$(stat -c %a -- "$source")
[[ $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) ||
  fail 'transferred file is writable by other users; re-transfer into a private administrator-owned directory'
# Root must not execute a local file through replaceable parent components.
if [[ $EUID == 0 ]]; then
  path=/
  IFS=/ read -ra components <<< "${source%/*}"
  for component in "${components[@]}"; do
    [[ -z $component ]] && continue
    path="${path%/}/$component"
    [[ -d $path && ! -L $path && $(stat -c %u -- "$path") == 0 ]] ||
      fail "untrusted source directory ownership or symlink: $path"
    mode=$(stat -c %a -- "$path")
    [[ $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )) ||
      fail "transferred file is in a writable source directory: $path"
  done
fi
source_bytes=$(stat -c %s -- "$source")
(( source_bytes > archive_bytes && source_bytes <= 134250000 )) ||
  fail 'local installer has an invalid or oversized payload'

# A missing or corrupt selected companion fails BEFORE core installation.
# Canonical installer also verifies archive, executable, record and paths.
companion="${source%/*}/wstunnel_11.0.0_linux_${architecture}.tar.gz"
if [[ $enable_wss == 1 ]]; then
  [[ -f $companion && ! -L $companion ]] ||
    fail "WSS selected but official $(basename -- "$companion") absent; core unchanged"
  case $architecture in
    amd64) expected_companion_sha=9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e ;;
    arm64) expected_companion_sha=b86abf73e340ed0c3ff9a77a5458aa27213784920ec65513132b36def45edc94 ;;
    *) fail 'unsupported optional WSS companion architecture' ;;
  esac
  [[ $(sha256sum -- "$companion" | awk '{print $1}') == "$expected_companion_sha" ]] ||
    fail 'selected optional WSS archive SHA-256 mismatch; core unchanged'
fi

# Take a private immutable-for-this-operation copy of the entire transferred
# file before reading its embedded archive; no GitHub/download step is needed.
if [[ $EUID == 0 ]]; then
  stage=$(mktemp -d /root/.stl-local-install.XXXXXXXX) || fail 'private root staging failed'
else
  stage=$(mktemp -d "${TMPDIR:-/var/tmp}/.stl-local-install.XXXXXXXX") || fail 'private staging failed'
fi
cleanup() { [[ -d $stage && ! -L $stage ]] && rm -rf --one-file-system -- "$stage"; }
trap cleanup EXIT
cp -- "$source" "$stage/entrypoint" || fail 'cannot snapshot local installer'
chmod 0600 -- "$stage/entrypoint"
[[ $(stat -c %s -- "$stage/entrypoint") == "$source_bytes" ]] ||
  fail 'transferred file changed while copying; transfer the official artifact again'
archive="$stage/$archive_name"
tail -c "$archive_bytes" -- "$stage/entrypoint" > "$archive" ||
  fail 'cannot read embedded archive'
[[ $(sha256sum -- "$archive" | awk '{print $1}') == "$archive_sha256" ]] ||
  fail 'embedded archive SHA256 mismatch; re-download from the verified official release'
# Only after the complete embedded archive hash matches the build-bound digest
# may any archive script bytes be executed. Extraction itself is delegated to
# the single canonical installer 'unpack' safety boundary.
tar -xOzf "$archive" install.sh > "$stage/canonical.sh" ||
  fail 'cannot recover the canonical installer from the verified archive'
bash -n "$stage/canonical.sh" || fail 'canonical installer syntax invalid'
bash "$stage/canonical.sh" unpack --archive "$archive" \
  --destination "$stage/bundle" --sha256 "$archive_sha256"
cmp -s -- "$stage/canonical.sh" "$stage/bundle/install.sh" ||
  fail 'extracted canonical installer identity changed'
grep -Fxq -- "version=$version" "$stage/bundle/BUILD-MANIFEST.txt" &&
  grep -Fxq -- "commit=$commit" "$stage/bundle/BUILD-MANIFEST.txt" ||
  fail 'embedded bundle version or source commit mismatch'

# The one-file route uses the canonical installer's restricted automatic
# Stable policy *under the maintenance lock*. Do not inspect the install
# record here: any pre-lock decision would race a concurrent installer.
bash "$stage/bundle/install.sh" install --auto-stable --bundle "$stage/bundle" \
  --prefix "$prefix" --backends native,wireguard
"$prefix/bin/stl" version --json || fail 'installed executable identity check failed'
# Only --with-wss selects optional WSS; file presence is not consent.
if [[ $enable_wss == 1 ]]; then
  if ! bash "$stage/bundle/install.sh" companion-wss --archive "$companion" --prefix "$prefix"; then
    fail 'core installed but selected WSS companion admission failed; no WSS Link created'
  fi
  printf '[OK] Selected pinned WSS helper installed; explicit Link setup is still required.
'
fi
if [[ $prefix == /usr/local ]]; then
  if [[ -t 0 && -t 1 ]]; then
    "$prefix/bin/stl" menu
  else
    printf '[OK] Run sudo stl menu to create or manage tunnels.\n'
  fi
fi
exit 0
# Opaque archive bytes appended by scripts/build-artifacts.sh follow this line.
