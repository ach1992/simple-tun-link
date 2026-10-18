#!/usr/bin/env bash
# Online transport for the SAME verified offline installer; no source build.
# Requires an independently trusted exact 64-hex SHA256 for the final archive.
# Does not publish a release, trust latest, or download Go/Python/packages.
set -euo pipefail
umask 077
export LC_ALL=C
fail(){ printf 'spoofdiag online bootstrap: %s\n' "$*" >&2; exit 1; }
usage(){
  echo 'Usage: online-bootstrap.sh --version spoofdiag-vX.Y.Z --sha256 EXPECTED_ARCHIVE_DIGEST [--verify-only|--install] [--accept] [--destdir CANONICAL_ROOT]' >&2
  echo 'Test-only: --local-url http://127.0.0.1:PORT --version dev-NAME' >&2
  exit 2
}
version='' expected='' operation=install accept=0 destdir='' localURL=''
while (($#)); do
  case "$1" in
    --version) shift; (($#)) || usage; version=$1 ;;
    --sha256) shift; (($#)) || usage; expected=$1 ;;
    --verify-only) operation=verify ;;
    --install) operation=install ;;
    --accept) accept=1 ;;
    --destdir) shift; (($#)) || usage; destdir=$1 ;;
    --local-url) shift; (($#)) || usage; localURL=$1 ;;
    *) usage ;;
  esac
  shift
done
[[ $expected =~ ^[a-f0-9]{64}$ ]] || fail 'supply exact independently authenticated 64-character --sha256'
if [[ -z $localURL ]]; then
  [[ $version =~ ^spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] ||
    fail 'online release must use an exact spoofdiag-vX.Y.Z tag, never latest/STL v*'
else
  [[ $version =~ ^dev-[a-z0-9.-]+$ ]] || fail 'local test accepts only dev-*'
  [[ $localURL =~ ^http://127\.0\.0\.1:([0-9]{2,5})$ ]] || fail 'local URL restricted to http://127.0.0.1:PORT'
  port=${BASH_REMATCH[1]}
  ((port>=1024 && port<=65535)) || fail 'unprivileged local test port required'
fi
[[ $operation == verify || $operation == install ]] || usage
if [[ -n $destdir ]]; then
  [[ $destdir == /* && -d $destdir && ! -L $destdir ]] || fail '--destdir must be an existing absolute nonsymlink root'
fi
for tool in curl tar sha256sum uname mktemp grep bash sort; do
  command -v "$tool" >/dev/null || fail "missing prerequisite: $tool (online transport only)"
done
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) fail "no prebuilt binary available for this architecture: $(uname -m)" ;;
esac
archive="spoofdiag-${version}_linux_${arch}.tar.gz"
if [[ -n $localURL ]]; then origin=$localURL; else
  origin="https://github.com/ach1992/simple-tun-link/releases/download/$version"
fi
scratch=$(mktemp -d "${TMPDIR:-/tmp}/.spoofdiag-online.XXXXXXXX") || fail 'cannot allocate private staging'
on_exit(){ if [[ -d $scratch && ! -L $scratch ]]; then rm -rf -- "$scratch"; fi; }
trap on_exit EXIT
archivePath="$scratch/$archive"
echo "Fetching exactly: $version / linux/$arch"
if [[ -n $localURL ]]; then
  curl -fsS --proto '=http' --proto-redir '=http' --max-redirs 0 --connect-timeout 5 --max-time 90 -o "$archivePath" "$origin/$archive" ||
    fail 'local test archive download failed (no installer executed)'
else
  curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 --retry 1 \
    -o "$archivePath" "$origin/$archive" ||
    fail 'release archive download failed; use offline package instead'
fi
actual=$(sha256sum "$archivePath" | cut -d ' ' -f1)
[[ $actual == "$expected" ]] || fail 'archive SHA256 mismatch against independent trusted expectation; nothing executed'
tar -tzf "$archivePath" > "$scratch/list" || fail 'invalid archive'
expectedMembers=$'stl-spoofdiag/\nstl-spoofdiag/BUILD-MANIFEST.txt\nstl-spoofdiag/LICENSE\nstl-spoofdiag/README.md\nstl-spoofdiag/SHA256SUMS\nstl-spoofdiag/evidence-private.json\nstl-spoofdiag/install-offline.sh\nstl-spoofdiag/sources-private.csv\nstl-spoofdiag/stl-spoofdiag'
listed=$(sort "$scratch/list")
[[ $listed == "$(printf '%s\n' "$expectedMembers" | sort)" ]] ||
  fail 'archive has unexpected, missing, or duplicate product members'
tar -tvzf "$archivePath" > "$scratch/member-types" || fail 'invalid archive metadata'
if grep -E '^[^d-]' "$scratch/member-types" >/dev/null; then
  fail 'archive contains symlink/hardlink/non-regular member'
fi
mkdir "$scratch/unpack"
tar -xzf "$archivePath" -C "$scratch/unpack" --no-same-owner --no-same-permissions ||
  fail 'verified archive could not be extracted'
bundle="$scratch/unpack/stl-spoofdiag"
[[ -f "$bundle/install-offline.sh" && ! -L "$bundle/install-offline.sh" ]] || fail 'unsafe installer member'
bash -n "$bundle/install-offline.sh" || fail 'invalid installer shell syntax'
bash "$bundle/install-offline.sh" --verify || fail 'offline package identity/checksum verification failed'
if [[ $operation == verify ]]; then
  printf 'VERIFIED_ONLY: archive SHA256=%s, version=%s, linux/%s; no install performed\n' "$actual" "$version" "$arch"
  exit 0
fi
args=(--install)
[[ -z $destdir ]] || args+=(--destdir "$destdir")
((accept==0)) || args+=(--accept)
bash "$bundle/install-offline.sh" "${args[@]}" || fail 'offline installation failed'
printf 'Installed from verified %s archive SHA256 %s (no compiler fetched)\n' "$version" "$actual"
