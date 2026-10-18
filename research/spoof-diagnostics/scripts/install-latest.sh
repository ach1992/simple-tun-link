#!/usr/bin/env bash
# Versionless SpoofDiag channel installer: exactly one publisher-curated
# version and checksums, never STL's shared releases/latest endpoint.
# GitHub HTTPS/source authentication is distinct from independent signing.
set -euo pipefail
umask 077
export LC_ALL=C

fail() { printf 'SpoofDiag channel installer: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'Usage: install-latest.sh [--accept] [--verify-only] [--inbox PRIVATE_DIRECTORY]\n' >&2
  printf 'Developer-only: --local-url http://127.0.0.1:PORT --destdir /existing/test-root\n' >&2
  exit 2
}

mode=install accept=0 local_url='' destdir='' inbox=''
while (($#)); do
  case "$1" in
    --accept) accept=1 ;;
    --verify-only) mode=verify ;;
    --local-url) shift; (($#)) || usage; local_url=$1 ;;
    --destdir) shift; (($#)) || usage; destdir=$1 ;;
    --inbox) shift; (($#)) || usage; inbox=$1 ;;
    *) usage ;;
  esac
  shift
done

for tool in curl bash sha256sum uname mktemp; do
  command -v "$tool" >/dev/null || fail "missing prerequisite: $tool"
done
if [[ -n $local_url ]]; then
  [[ $local_url =~ ^http://127\.0\.0\.1:([0-9]{2,5})$ ]] ||
    fail 'local fixture must be exactly http://127.0.0.1:PORT'
  port=${BASH_REMATCH[1]}
  ((port>=1024 && port<=65535)) || fail 'local fixture port must be 1024..65535'
  origin=$local_url
else
  [[ -z $destdir ]] || fail '--destdir is developer-only with --local-url'
  origin='https://raw.githubusercontent.com/ach1992/simple-tun-link/dev-spoof/research/spoof-diagnostics'
fi
if [[ -n $destdir ]]; then
  [[ $destdir == /* && $destdir != */../* && -d $destdir && ! -L $destdir ]] ||
    fail '--destdir requires an existing, absolute nonsymlink test root'
fi
if [[ -n $inbox ]]; then
  [[ $inbox == /* && $inbox != */../* && -d $inbox && ! -L $inbox ]] ||
    fail '--inbox requires an existing, absolute nonsymlink directory'
fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/.spoofdiag-channel.XXXXXXXX") ||
  fail 'cannot create private discovery directory'
cleanup() { if [[ -d $scratch && ! -L $scratch ]]; then rm -rf -- "$scratch"; fi; }
trap cleanup EXIT
channel="$scratch/channel.txt"
if [[ -n $local_url ]]; then
  curl -fsS --proto '=http' --proto-redir '=http' --max-redirs 0 \
    --connect-timeout 5 --max-time 20 --max-filesize 4096 \
    -o "$channel" "$origin/release-channel.txt" ||
    fail 'cannot retrieve the local test channel'
else
  curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 4096 \
    -o "$channel" "$origin/release-channel.txt" ||
    fail 'cannot retrieve the SpoofDiag release channel over HTTPS'
fi

mapfile -t fields < "$channel"
if [[ ${#fields[@]} -eq 1 && ${fields[0]} == 'status=unpublished' ]]; then
  fail 'NO_PUBLIC_SPOOFDIAG_RELEASE: the dev-spoof channel is not published yet; STL releases are not substitutes'
fi
[[ ${#fields[@]} -eq 5 ]] || fail 'unexpected release-channel field count'
if [[ -n $local_url ]]; then
  [[ ${fields[0]} == status=local-test ]] || fail 'local fixture must use status=local-test'
else
  [[ ${fields[0]} == status=published ]] || fail 'channel not yet approved or published'
fi
[[ ${fields[1]} == version=* && ${fields[2]} == linux_amd64_sha256=* &&
   ${fields[3]} == linux_arm64_sha256=* && ${fields[4]} == bootstrap_sha256=* ]] ||
  fail 'release-channel keys must occur exactly once in canonical order'
version=${fields[1]#version=}
amd64_sha=${fields[2]#linux_amd64_sha256=}
arm64_sha=${fields[3]#linux_arm64_sha256=}
bootstrap_sha=${fields[4]#bootstrap_sha256=}
if [[ -n $local_url ]]; then
  [[ $version =~ ^dev-[a-z0-9.-]+$ ]] || fail 'local fixture requires dev-* version'
else
  [[ $version =~ ^spoofdiag-v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] ||
    fail 'channel is not a tool-prefixed release tag'
fi
for digest in "$amd64_sha" "$arm64_sha" "$bootstrap_sha"; do
  [[ $digest =~ ^[a-f0-9]{64}$ ]] || fail 'invalid SHA256 in channel'
done
case "$(uname -m)" in
  x86_64) selected_sha=$amd64_sha ;;
  aarch64) selected_sha=$arm64_sha ;;
  *) fail 'no prebuilt Linux amd64/arm64 SpoofDiag archive for this architecture' ;;
esac

bootstrap="$scratch/online-bootstrap.sh"
if [[ -n $local_url ]]; then
  curl -fsS --proto '=http' --proto-redir '=http' --max-redirs 0 \
    --connect-timeout 5 --max-time 20 --max-filesize 16384 \
    -o "$bootstrap" "$origin/online-bootstrap.sh" ||
    fail 'cannot fetch the local test bootstrap'
else
  curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 40 --max-filesize 16384 \
    -o "$bootstrap" "$origin/scripts/online-bootstrap.sh" ||
    fail 'cannot fetch the exact reviewed tool bootstrap'
fi
actual_bootstrap=$(sha256sum "$bootstrap")
actual_bootstrap=${actual_bootstrap%% *}
[[ $actual_bootstrap == "$bootstrap_sha" ]] ||
  fail 'bootstrap checksum mismatch; refusing to execute downloaded code'
bash -n "$bootstrap" || fail 'invalid online bootstrap syntax'

args=(--version "$version" --sha256 "$selected_sha")
if [[ $mode == verify ]]; then args+=(--verify-only); else args+=(--install); fi
((accept==0)) || args+=(--accept)
[[ -z $destdir ]] || args+=(--destdir "$destdir")
[[ -z $inbox ]] || args+=(--inbox "$inbox")
[[ -z $local_url ]] || args+=(--local-url "$local_url")
printf 'Selected SpoofDiag channel release: %s (linux/%s)\n' "$version" "$(uname -m)"
# Must delegate to the SAME independently-tested, SHA-pinned engine, not
# reproduce downloader/install/archive validation in a second implementation.
bash "$bootstrap" "${args[@]}"
