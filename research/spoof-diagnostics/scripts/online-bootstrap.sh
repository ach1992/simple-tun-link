#!/usr/bin/env bash
# Online transport for the SAME verified offline installer; no source build.
# Requires an independently trusted exact 64-hex SHA256 for the final archive.
# Does not publish a release, trust latest, or download Go/Python/packages.
set -euo pipefail
umask 077
export LC_ALL=C
fail(){ printf 'spoofdiag online bootstrap: %s\n' "$*" >&2; exit 1; }
usage(){
  echo 'Usage: online-bootstrap.sh --version spoofdiag-vX.Y.Z --sha256 EXPECTED_ARCHIVE_DIGEST [--verify-only|--install] [--accept] [--inbox PRIVATE_DIRECTORY]' >&2
  echo 'Developer-only: --local-url http://127.0.0.1:PORT --version dev-NAME --inbox PRIVATE_DIRECTORY [--destdir TEST_ROOT]' >&2
  exit 2
}
version='' expected='' operation=install accept=0 destdir='' localURL='' inbox=''
while (($#)); do
  case "$1" in
    --version) shift; (($#)) || usage; version=$1 ;;
    --sha256) shift; (($#)) || usage; expected=$1 ;;
    --verify-only) operation=verify ;;
    --install) operation=install ;;
    --accept) accept=1 ;;
    --destdir) shift; (($#)) || usage; destdir=$1 ;;
    --local-url) shift; (($#)) || usage; localURL=$1 ;;
    --inbox) shift; (($#)) || usage; inbox=$1 ;;
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
for tool in curl tar sha256sum uname mktemp grep bash sort stat ln; do
  command -v "$tool" >/dev/null || fail "missing prerequisite: $tool (online transport only)"
done
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) fail "no prebuilt binary available for this architecture: $(uname -m)" ;;
esac
# Keep the release asset name byte-identical to package-offline.sh.
if [[ $version == dev-* ]]; then
  archive="spoofdiag-${version}_linux_${arch}.tar.gz"
else
  archive="${version}_linux_${arch}.tar.gz"
fi
if [[ -n $localURL ]]; then origin=$localURL; else
  origin="https://github.com/ach1992/simple-tun-link/releases/download/$version"
fi
# The operator's download inbox is distinct from the installed versioned
# binary. Never use host /root accidentally when testing --destdir.
if [[ -z $inbox ]]; then
  [[ -z $destdir ]] || fail '--destdir requires explicit --inbox test directory'
  inbox=/root/stl-spoofdiag
  if [[ ! -e $inbox && ! -L $inbox ]]; then
    [[ -d /root && ! -L /root ]] || fail 'unsafe root home directory'
    mkdir -m 0700 -- "$inbox" || fail 'cannot create private root download inbox'
  fi
fi
[[ $inbox == /* && $inbox != */../* && $inbox != */./* && $inbox != */.. && $inbox != */. ]] ||
  fail '--inbox must be a canonical absolute directory'
[[ -d $inbox && ! -L $inbox && $(cd -P -- "$inbox" && pwd -P) == "$inbox" ]] ||
  fail 'inbox must be an existing, canonical, nonsymlink directory'
[[ $(stat -c %u -- "$inbox") == "$(id -u)" ]] || fail 'inbox owned by a different user'
inbox_perms=$(stat -c %a -- "$inbox")
[[ $inbox_perms == 700 ]] || fail 'inbox must be private mode 0700'
scratch=$(mktemp -d "$inbox/.spoofdiag-online.XXXXXXXX") ||
  fail 'cannot allocate private staging inside the download inbox'
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
expectedMembers=$'stl-spoofdiag/\nstl-spoofdiag/BUILD-MANIFEST.txt\nstl-spoofdiag/docs/\nstl-spoofdiag/docs/ARCHITECTURE.md\nstl-spoofdiag/docs/GO-REFERENCE.md\nstl-spoofdiag/docs/INSTALL-AND-RELEASE.md\nstl-spoofdiag/docs/LOCAL-LAB-ACCEPTANCE.md\nstl-spoofdiag/docs/VALIDATION-MATRIX.md\nstl-spoofdiag/LICENSE\nstl-spoofdiag/README.md\nstl-spoofdiag/SHA256SUMS\nstl-spoofdiag/evidence-field.json\nstl-spoofdiag/install-offline.sh\nstl-spoofdiag/sources-field.csv\nstl-spoofdiag/stl-spoofdiag'
listed=$(sort "$scratch/list")
# The v1 standalone release predates the optional offline exchange reference.
# Accept its exact legacy layout OR that layout plus exactly one new,
# checksum-covered documentation member. Keep rejecting everything else.
expectedLegacy=$(printf '%s\n' "$expectedMembers" | sort)
expectedWithExchange=$(printf '%s\n%s\n' "$expectedMembers" 'stl-spoofdiag/docs/OFFLINE-EXCHANGE.md' | sort)
# This standalone revision adds a disconnected A/B manual-evidence guide.
# Preserve exact legacy and Exchange-only members, with no wildcard members.
expectedWithDisconnected=$(printf '%s\n%s\n' "$expectedWithExchange" 'stl-spoofdiag/docs/DISCONNECTED-THREE-STAGE.md' | sort)
[[ $listed == "$expectedLegacy" || $listed == "$expectedWithExchange" || $listed == "$expectedWithDisconnected" ]] ||
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
# Keep a verified, architecture-specific archive in the operator's inbox
# without overwriting unknown files or following a symlink. Since scratch
# lives under inbox this exclusive hard link is atomic on the same filesystem.
stored="$inbox/$archive"
if [[ -e $stored || -L $stored ]]; then
  [[ -f $stored && ! -L $stored && $(stat -c %u -- "$stored") == "$(id -u)" ]] ||
    fail 'foreign/nonregular archive already occupies the download path'
  stored_digest=$(sha256sum "$stored")
  [[ ${stored_digest%% *} == "$expected" ]] ||
    fail 'existing inbox archive differs; refusing overwrite'
else
  ln -- "$archivePath" "$stored" || fail 'could not retain the verified archive safely'
fi
printf 'Verified archive retained at %s\n' "$stored"
if [[ $operation == verify ]]; then
  printf 'VERIFIED_ONLY: archive SHA256=%s, version=%s, linux/%s; no install performed\n' "$actual" "$version" "$arch"
  exit 0
fi
args=(--install)
[[ -z $destdir ]] || args+=(--destdir "$destdir")
((accept==0)) || args+=(--accept)
bash "$bundle/install-offline.sh" "${args[@]}" || fail 'offline installation failed'
printf 'Installed from verified %s archive SHA256 %s (no compiler fetched)\n' "$version" "$actual"
