#!/usr/bin/env bash
# Source-bound, native-architecture offline release-snapshot installer smoke.
# This does not tag/publish, mutate host networking, or prove Link recovery.
set -Eeuo pipefail
umask 077

fail() { printf 'SNAPSHOT_INSTALL_SMOKE_FAILED=%s\n' "$1" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail 'run as an unprivileged user'
[[ $(uname -s) == Linux ]] || fail 'Linux required'
for tool in git go sha256sum cmp mktemp python3; do
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
  archive_name=$(basename -- "$archive")
  outer_digest=$(awk -v name="$archive_name" '$2 == name {print $1}' "$scratch/bundle/SHA256SUMS")
  [[ $outer_digest =~ ^[0-9a-f]{64}$ ]] || fail 'missing outer archive checksum'
  unpack="$scratch/archive-$packaged_arch"
  # Exercise the canonical pre-extraction guard, including exact member type,
  # size and private destination, on BOTH generated architectures.
  # Consume the complete authenticated installer before executing it.
  # Streaming directly to bash can close early and SIGPIPE tar once the
  # canonical script exceeds the pipe buffer (exit code 141).
  bootstrap="$scratch/bootstrap-$packaged_arch.sh"
  tar -xOzf "$archive" install.sh > "$bootstrap" ||
    fail 'could not extract canonical installer from verified archive'
  cmp -s scripts/install.sh "$bootstrap" || fail 'untrusted archive installer'
  bash -n "$bootstrap" || fail 'archive installer syntax invalid'
  bash "$bootstrap" unpack --archive "$archive" --destination "$unpack" --sha256 "$outer_digest"
  [[ -z $(find "$scratch" -maxdepth 1 -name '.stl-unpack.*' -print -quit) ]] ||
    fail 'successful unpack retained an internal private snapshot'
  (cd "$unpack" && sha256sum --check SHA256SUMS >/dev/null) || fail 'local package checksum failed'
  cmp -s scripts/install.sh "$unpack/install.sh" || fail 'local installer differs from canonical source'
  bash -n "$unpack/install.sh" || fail 'local installer syntax invalid'
  [[ -x "$unpack/stl_dev-${short_sha}_linux_${packaged_arch}" ]] || fail 'local binary not executable'
done

# The single-file entrypoint is source/arch bound and consists of a strict
# one-command bootstrap plus EXACTLY the checked legacy archive bytes.
for packaged_arch in amd64 arm64; do
  archive="$scratch/bundle/stl_dev-${short_sha}_linux_${packaged_arch}_local-install.tar.gz"
  one_file="$scratch/bundle/stl_dev-${short_sha}_linux_${packaged_arch}_local-install.sh"
  [[ -f $one_file ]] || fail "missing one-file installer: $packaged_arch"
  tail -c "$(stat -c %s -- "$archive")" -- "$one_file" | cmp -s - "$archive" ||
    fail "one-file embedded archive is not exact: $packaged_arch"
  one_file_sha=$(awk -v name="$(basename -- "$one_file")" '$2 == name {print $1}' "$scratch/bundle/SHA256SUMS")
  [[ $one_file_sha =~ ^[0-9a-f]{64}$ &&
     $(sha256sum -- "$one_file" | awk '{print $1}') == "$one_file_sha" ]] ||
    fail "missing/wrong release-wide one-file checksum: $packaged_arch"
done
one_file="$scratch/bundle/stl_dev-${short_sha}_linux_${arch}_local-install.sh"
foreign_arch=arm64
[[ $arch == amd64 ]] || foreign_arch=amd64
foreign="$scratch/bundle/stl_dev-${short_sha}_linux_${foreign_arch}_local-install.sh"
if bash "$foreign" --prefix "$scratch/prefix" > "$scratch/wrong-arch.log" 2>&1; then
  fail 'wrong-architecture one-command installer was accepted'
fi
grep -q 'wrong file for' "$scratch/wrong-arch.log" || fail 'missing wrong-arch guidance'

# Transfer corruption must fail before invoking canonical installation. The
# filename is preserved, as the real operator copies official bytes as-is.
mkdir -m 0700 "$scratch/tamper"
tampered="$scratch/tamper/$(basename -- "$one_file")"
cp -- "$one_file" "$tampered"
printf x | dd of="$tampered" bs=1 seek=$(($(stat -c %s -- "$tampered") - 1)) \
  conv=notrunc status=none
if bash "$tampered" --prefix "$scratch/prefix" > "$scratch/tamper.log" 2>&1; then
  fail 'tampered one-file archive unexpectedly installed'
fi
grep -q 'embedded archive SHA256 mismatch' "$scratch/tamper.log" ||
  fail 'tampered file did not fail at the digest gate'
[[ ! -e "$scratch/prefix/bin/stl" ]] || fail 'tampering installed an executable'
chmod 0666 "$tampered"
if bash "$tampered" --prefix "$scratch/prefix" > "$scratch/untrusted.log" 2>&1; then
  fail 'writable one-file transfer unexpectedly installed'
fi
grep -q 'writable by other users' "$scratch/untrusted.log" ||
  fail 'world-writable file did not fail at source-ownership boundary'
# A source with independently changed header+payload could recalculate its own
# hash: the official, independently trusted publisher identity is essential.
echo 'SNAPSHOT_ONE_FILE_ARCH_DIGEST_PERMISSIONS_AND_IDENTITY=PASS'

# Reject adversarial transfer archives before extraction or execution.
# Synthetic local fixtures exercise unchanged member names with unsafe types,
# unbounded payloads, duplicate/traversal members and altered checksums.
python3 - "$scratch/adversarial" "dev-$short_sha" "$arch" <<'PY'
from pathlib import Path
import hashlib
import io
import sys
import tarfile

base, version, arch = sys.argv[1:]
root = Path(base)
binary = f"stl_{version}_linux_{arch}"
names = [binary, "install.sh", "LICENSE", "BUILD-MANIFEST.txt",
         "LOCAL-INSTALL.txt", "SHA256SUMS"]
files = {
    binary: b"#!/bin/sh\nexit 0\n",
    "install.sh": b"#!/bin/bash\nexit 0\n",
    "LICENSE": b"MIT License\n",
    "BUILD-MANIFEST.txt": f"project=simple-tun-link\nversion={version}\n".encode(),
    "LOCAL-INSTALL.txt": b"fixture\n",
}
files["SHA256SUMS"] = "".join(
    hashlib.sha256(files[name]).hexdigest() + "  " + name + "\n"
    for name in names[:-1]
).encode()

for mutation in ("symlink", "hardlink", "device", "setuid", "oversize",
                 "traversal", "duplicate", "bad-checksum"):
    directory = root / mutation
    directory.mkdir(parents=True, mode=0o700)
    archive = directory / f"{binary}_local-install.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        for name in names + (["LICENSE"] if mutation == "duplicate" else []):
            data = files[name]
            info = tarfile.TarInfo(
                "../escape" if mutation == "traversal" and name == "LOCAL-INSTALL.txt"
                else name
            )
            info.uid = info.gid = info.mtime = 0
            info.mode = (0o4755 if mutation == 'setuid' and name == binary
                         else (0o700 if name == binary else 0o600))
            if mutation == "symlink" and name == "install.sh":
                info.type = tarfile.SYMTYPE
                info.linkname = "../../escape"
            elif mutation == "hardlink" and name == "LICENSE":
                info.type = tarfile.LNKTYPE
                info.linkname = "../../escape"
            elif mutation == "device" and name == "LICENSE":
                info.type = tarfile.CHRTYPE
                info.devmajor, info.devminor = 1, 3
            else:
                if mutation == "oversize" and name == "LICENSE":
                    data = b"X" * 65537
                if mutation == "bad-checksum" and name == "SHA256SUMS":
                    data = (b"0" * 64) + data[64:]
                info.size = len(data)
                info.type = tarfile.REGTYPE
                tar.addfile(info, io.BytesIO(data))
                continue
            info.size = 0
            tar.addfile(info)
PY
for mutation in symlink hardlink device setuid oversize traversal duplicate bad-checksum; do
  fake="$scratch/adversarial/$mutation/stl_dev-${short_sha}_linux_${arch}_local-install.tar.gz"
  digest=$(sha256sum -- "$fake" | awk '{print $1}')
  if bash scripts/install.sh unpack --archive "$fake" --destination "$scratch/adversarial/unsafe-$mutation" \
      --sha256 "$digest" > "$scratch/adversarial/$mutation.log" 2>&1; then
    fail "unsafe archive unexpectedly extracted: $mutation"
  fi
  [[ ! -e "$scratch/adversarial/unsafe-$mutation" ]] ||
    fail "unsafe archive left an extract directory: $mutation"
done
echo 'SNAPSHOT_UNSAFE_ARCHIVE_TYPES_SIZE_AND_NAMES_REFUSED=PASS'

# A correctly signed archive can still have unsafe filesystem permissions.
# Reject owner-controlled 0620/0666 inputs before creating the destination;
# callers may not confuse UID equality with exclusive write permission.
for unsafe_mode in 0620 0666; do
  chmod "$unsafe_mode" -- "$archive"
  unsafe_destination="$scratch/adversarial/archive-permission-$unsafe_mode"
  if bash scripts/install.sh unpack --archive "$archive" --destination "$unsafe_destination" \
      --sha256 "$outer_digest" > "$scratch/adversarial/permission-$unsafe_mode.log" 2>&1; then
    fail "writable archive mode was accepted: $unsafe_mode"
  fi
  grep -q 'local source archive is writable by group or others' \
    "$scratch/adversarial/permission-$unsafe_mode.log" ||
    fail "writable archive was rejected for an unrelated reason: $unsafe_mode"
  [[ ! -e $unsafe_destination ]] ||
    fail "writable archive left an extract directory: $unsafe_mode"
done
chmod 0600 -- "$archive"
echo 'SNAPSHOT_WRITABLE_SOURCE_ARCHIVE_REFUSED=PASS'

# Never overwrite an existing directory, even with correct official bytes.
mkdir -m 0700 "$scratch/adversarial/existing"
printf 'owned sentinel\n' > "$scratch/adversarial/existing/keep"
if bash scripts/install.sh unpack --archive "$archive" --destination "$scratch/adversarial/existing" \
    --sha256 "$outer_digest" > "$scratch/adversarial/existing.log" 2>&1; then
  fail 'existing extraction destination was overwritten'
fi
grep -qx 'owned sentinel' "$scratch/adversarial/existing/keep" ||
  fail 'existing extraction destination was modified'
echo 'SNAPSHOT_EXISTING_DESTINATION_PRESERVED=PASS'
native_package="$scratch/archive-$arch"

# Offline nondefault prefix: no package installation, /usr/local writes,
# privileged systemd calls, daemon activation, or network operations.
bash "$one_file" --prefix "$scratch/prefix"
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
bash "$one_file" --prefix "$scratch/prefix"
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
echo 'SNAPSHOT_LITERAL_ONE_FILE_ENTRYPOINT=PASS'
echo 'SNAPSHOT_LOCAL_REINSTALL_NOOP=PASS'
