#!/usr/bin/env bash
# Bounded QUIC initial ingress integration: real nft create/readback in a
# new user/net/pid/mount namespace, and official pinned materials in a
# privately owned disposable chroot. Host iptables is NOT tested here:
# two test runners supply explicit empty legacy snapshots because this Dev
# image lacks iptables; this is not production firewall acceptance.
set -euo pipefail

if [[ $# != 1 ]]; then
  echo "Usage: $0 /absolute/path/to/official-pinned-hysteria-binary" >&2
  exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
helper=$1
[[ "$helper" == /* && -f "$helper" && ! -L "$helper" ]] || {
  echo "A regular absolute approved helper fixture is required" >&2
  exit 2
}
for cmd in go nft ldd unshare chroot mount mktemp cp awk readlink stat; do
  command -v "$cmd" >/dev/null || { echo "Missing isolated-test prerequisite: $cmd" >&2; exit 2; }
done
nft_binary=$(command -v nft)
[[ "$nft_binary" == /* && -f "$nft_binary" && ! -L "$nft_binary" ]] || {
  echo "A regular system nft binary is required" >&2; exit 2;
}

root=$(mktemp -d /tmp/stl-quic-guard.XXXXXXXX)
cleanup(){
  if [[ -n "${root:-}" && "$root" == /tmp/stl-quic-guard.* && -d "$root" && ! -L "$root" &&
        $(stat -c '%u' -- "$root") == "$(id -u)" ]]; then
    rm -rf -- "$root"
  fi
}
trap cleanup EXIT

mkdir -p "$root/usr/sbin" "$root/opt" "$root/proc" "$root/tmp" "$root/dev" "$root/lib64"
chmod 1777 "$root/tmp"
# Go's os/exec opens /dev/null when Stdin is unspecified. Inside this
# disposable private chroot an empty regular file is sufficient; no
# device creation or host /dev mutation is needed.
: > "$root/dev/null"
chmod 0666 "$root/dev/null"
cp -- "$nft_binary" "$root/usr/sbin/nft"
cp -- "$helper" "$root/opt/hysteria"
chmod 0700 "$root/opt/hysteria"

copy_libraries(){
  local binary=$1
  while IFS= read -r lib; do
    [[ -f "$lib" ]] || { echo "Missing runtime library: $lib" >&2; exit 2; }
    mkdir -p -- "$root$(dirname -- "$lib")"
    cp -L -- "$lib" "$root$lib"
  done < <(ldd "$binary" | awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' | sort -u)
}
copy_libraries "$nft_binary"
cp -L -- /lib64/ld-linux-x86-64.so.2 "$root/lib64/ld-linux-x86-64.so.2"

cd "$repo"
GOTOOLCHAIN=local go test -c -o "$root/linux-test" ./internal/linux
GOTOOLCHAIN=local go test -c -o "$root/app-test" ./internal/app
copy_libraries "$root/linux-test"
copy_libraries "$root/app-test"

export STL_QUIC_PARENT_NETNS="$(readlink /proc/self/ns/net)"
export STL_QUIC_PARENT_USERNS="$(readlink /proc/self/ns/user)"
export STL_QUIC_HYSTERIA_BIN=/opt/hysteria
export STL_QUIC_GUARD_NFT_E2E=1
export STL_QUIC_TEST_ROOT="$root"

unshare --user --map-root-user --net --mount --pid --fork bash -euo pipefail -c '
  mount -t proc proc "$STL_QUIC_TEST_ROOT/proc"
  chroot "$STL_QUIC_TEST_ROOT" /linux-test -test.run "^TestQUICOriginalGuardRealNFTDisposableUserNetNS$" -test.v
  chroot "$STL_QUIC_TEST_ROOT" /app-test -test.run "^TestQUICOriginalGuardEngineMaterialAndRealNFTInDisposableNetNS$" -test.v
'
echo 'QUIC guard isolated original nft and Engine-material integration: PASS'
