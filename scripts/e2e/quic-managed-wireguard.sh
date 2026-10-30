#!/usr/bin/env bash
# Public CLI + real kernel WG/nft + official Hysteria. Manager/boot trust is
# explicitly a test-only shim; this does not demonstrate systemd or reboot.
set -euo pipefail
refuse() { echo "QUIC managed lab refused: $1" >&2; exit 2; }
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
if [[ "${1:-}" != --isolated ]]; then
  [[ $# == 0 && ${STL_RUN_PRIVILEGED_E2E:-} == 1 ]] || refuse 'explicit disposable E2E opt-in required'
  [[ $(id -u) != 0 ]] || refuse 'run as an unprivileged user'
  helper=${STL_QUIC_HYSTERIA_BIN:-}
  [[ $helper == /* && -f $helper && ! -L $helper && $(stat -c %u -- "$helper") == $(id -u) ]] || refuse 'owned official helper fixture required'
  wg_binary=${STL_QUIC_WG_BINARY:-}
  if [[ -z $wg_binary ]]; then wg_binary=$(command -v wg || true); fi
  [[ $wg_binary == /* && -f $wg_binary && -x $wg_binary && ! -L $wg_binary ]] || refuse 'absolute regular WireGuard tool required (set STL_QUIC_WG_BINARY for an approved local fixture)'
  for command in go python3 unshare nsenter mount chroot ip ss nft iptables ip6tables iptables-save ip6tables-save iptables-legacy-save ip6tables-legacy-save ping; do
    command -v "$command" >/dev/null || refuse "missing prerequisite $command"
  done
  case $(uname -m) in
    x86_64) expected=907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691 ;;
    aarch64) expected=a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7 ;;
    *) refuse 'no pinned official helper for this architecture' ;;
  esac
  [[ $(sha256sum -- "$helper" | cut -d' ' -f1) == "$expected" ]] || refuse 'official helper digest mismatch'
  exec python3 "$repo/scripts/e2e/quic-managed-supervisor.py" outer "$repo" "$helper" "$wg_binary" "$repo/scripts/e2e/quic-managed-wireguard.sh"
fi

# An internal flag alone never permits host mutation. The independent parent
# created the exact private directory and nonce before entering all namespaces.
fixture=${STL_QUIC_MANAGED_ROOT:-}
[[ $fixture =~ ^/tmp/stl-quic-managed\.[A-Za-z0-9_-]{8}$ && -d $fixture && ! -L $fixture &&
   $(stat -c '%u:%a' -- "$fixture") == 0:700 && -f $fixture/data/namespace-guard &&
   -f $fixture/data/parent-namespaces && ${STL_QUIC_MANAGED_LAB:-} =~ ^[a-f0-9]{32}$ ]] || refuse 'private fixture witness missing'
[[ $(cat "$fixture/data/namespace-guard") == "$STL_QUIC_MANAGED_LAB" ]] || refuse 'fixture nonce differs'
mapfile -t parents < "$fixture/data/parent-namespaces"
[[ ${#parents[@]} == 3 && $(id -u) == 0 && $$ == 1 &&
   $(readlink /proc/self/ns/user) != "${parents[0]}" &&
   $(readlink /proc/self/ns/net) != "${parents[1]}" &&
   $(readlink /proc/self/ns/pid) != "${parents[2]}" &&
   $(readlink /proc/1/ns/pid) == "$(readlink /proc/self/ns/pid)" ]] || refuse 'independent rootless PID-1/user/network namespace required'
[[ $(awk 'NF==3 {n++; if($1==0 && $2>0 && $3==1) ok++} END {print(n==1&&ok==1)?"yes":"no"}' /proc/self/uid_map) == yes ]] || refuse 'one-user rootless mapping required'
# Negative control must fail before even a mount or a network command.
if env -u STL_QUIC_MANAGED_LAB bash "$0" --isolated >/dev/null 2>&1; then refuse 'untrusted reentry admitted'; fi

echo 'QUIC_MANAGED_UNAUTHORIZED_REENTRY=BLOCKED'
umask 077
mount --make-rprivate /
root="$fixture/rootfs"
mkdir -p "$root"/{usr/bin,usr/sbin,usr/lib,usr/local/bin,usr/local/libexec/stl,etc/alternatives,proc,dev,run,tmp,lab}
chmod 0755 "$root" "$root/usr" "$root/usr/local" "$root/usr/local/bin" "$root/usr/local/libexec" "$root/usr/local/libexec/stl"
# New owner-controlled parents keep the genuine pinned executable verifier in
# use; existing host binaries/libraries are mounted read-only only for tools.
for dir in /usr/bin /usr/sbin /usr/lib; do
  mount --bind "$dir" "$root$dir"
  mount -o remount,bind,ro "$root$dir"
done
if [[ -d /usr/lib64 ]]; then mkdir -p "$root/usr/lib64"; mount --bind /usr/lib64 "$root/usr/lib64"; mount -o remount,bind,ro "$root/usr/lib64"; fi
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
if [[ -d /usr/lib64 ]]; then ln -s usr/lib64 "$root/lib64"; fi
if [[ -d /etc/alternatives ]]; then mount --bind /etc/alternatives "$root/etc/alternatives"; mount -o remount,bind,ro "$root/etc/alternatives"; fi
if [[ -f /etc/ld.so.cache ]]; then touch "$root/etc/ld.so.cache"; mount --bind /etc/ld.so.cache "$root/etc/ld.so.cache"; mount -o remount,bind,ro "$root/etc/ld.so.cache"; fi
printf 'root:x:0:0:disposable:/root:/bin/bash\n' > "$root/etc/passwd"
printf 'root:x:0:\n' > "$root/etc/group"
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=755,nosuid tmpfs "$root/dev"
for device in null zero random urandom; do touch "$root/dev/$device"; mount --bind "/dev/$device" "$root/dev/$device"; done
ln -s /proc/self/fd "$root/dev/fd"
ln -s /proc/self/fd/0 "$root/dev/stdin"
ln -s /proc/self/fd/1 "$root/dev/stdout"
ln -s /proc/self/fd/2 "$root/dev/stderr"
mount -t tmpfs -o mode=700,nosuid,nodev tmpfs "$root/tmp"
mount -t tmpfs -o mode=755,nosuid,nodev tmpfs "$root/run"
mount --bind "$fixture/data" "$root/lab"
install -m 0755 "$fixture/data/hysteria" "$root/usr/local/libexec/stl/hysteria"
# The selected distro tool was snapshotted through a retained source fd by
# the original user. Recheck those bytes before and after this private copy;
# never attempt to install into the read-only host /usr/bin bind mount.
[[ -f $fixture/data/wg && ! -L $fixture/data/wg && -f $fixture/data/wg.sha256 && ! -L $fixture/data/wg.sha256 ]] || refuse 'private WireGuard tool snapshot missing'
wg_digest=$(cat "$fixture/data/wg.sha256")
[[ $wg_digest =~ ^[a-f0-9]{64}$ && $(sha256sum -- "$fixture/data/wg" | cut -d' ' -f1) == "$wg_digest" ]] || refuse 'private WireGuard tool snapshot changed'
install -m 0755 "$fixture/data/wg" "$root/usr/local/bin/wg"
[[ $(sha256sum -- "$root/usr/local/bin/wg" | cut -d' ' -f1) == "$wg_digest" ]] || refuse 'private chroot WireGuard tool copy differs'
cmp -s -- "$fixture/data/wg" "$root/usr/local/bin/wg" || refuse 'private WireGuard tool copy readback differs'
# Exit of this PID-1 task tears down both peers and every test-owned child.
# The outer pidfd supervisor and independent janitor also handle SIGKILL.
exec chroot "$root" /usr/bin/env PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/python3 /lab/driver.py run
