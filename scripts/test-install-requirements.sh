#!/usr/bin/env bash
# Offline distro/selection matrix for the release installer's apt planner.
# No sudo, APT commands, network accesses or host package changes.
set -Eeuo pipefail
umask 077
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
installer="$(cd "$(dirname "$0")" && pwd -P)/install.sh"
fail() { printf 'requirements test FAILED: %s\n' "$*" >&2; exit 1; }
write_os() {
  printf 'ID=%s\nVERSION_ID="%s"\n' "$1" "$2" > "$root/os-release"
}
plan() {
  bash "$installer" requirements --backends "$1" --os-release-file "$root/os-release" > "$root/out" 2> "$root/err"
}
bad() {
  if "$@" > "$root/out" 2> "$root/err"; then fail "unsafe or unsupported input accepted"; fi
}
for distro in 'ubuntu 22.04' 'ubuntu 22.10' 'ubuntu 24.04' 'ubuntu 26.04' \
              'debian 11' 'debian 12' 'debian 13' 'debian 14'; do
  read -r os version <<< "$distro"
  write_os "$os" "$version"
  plan native
  grep -qx "distribution=$os" "$root/out" || fail "wrong distro for $distro"
  grep -qx "version=$version" "$root/out" || fail "wrong version for $distro"
  grep -qx "packages=iproute2 iptables" "$root/out" || fail "wrong native package list on $distro"
  plan native,wireguard
  grep -qx "packages=iproute2 iptables wireguard-tools" "$root/out" || fail "wrong WireGuard package list on $distro"
  plan native,ipsec
  grep -qx "packages=iproute2 iptables charon-systemd strongswan-swanctl libstrongswan-standard-plugins" "$root/out" || fail "wrong IPsec package list on $distro"
  grep -q 'notice=IPsec packages can enable/start' "$root/out" || fail 'IPsec daemon change not flagged'
  plan all
  grep -qx "packages=iproute2 iptables wireguard-tools charon-systemd strongswan-swanctl libstrongswan-standard-plugins" "$root/out" ||
    fail "wrong all-backend package list on $distro"
  if [[ $distro == 'debian 11' ]]; then
    grep -q 'Debian 11 LTS ended 2026-08-31' "$root/err" || fail 'Debian 11 security EOL warning missing'
  fi
done

# Fail early for unsupported/old systems rather than pretending APT works.
for distro in 'ubuntu 20.04' 'ubuntu 22.03' 'debian 10' \
              'debian 9' 'fedora 42' 'linuxmint 22'; do
  read -r os version <<< "$distro"
  write_os "$os" "$version"
  bad bash "$installer" requirements --backends all --os-release-file "$root/os-release"
done
printf 'ID=debian\nVERSION_ID="eleven"\n' > "$root/os-release"
bad bash "$installer" requirements --os-release-file "$root/os-release"
printf 'ID=debian\nID=ubuntu\nVERSION_ID="13"\n' > "$root/os-release"
bad bash "$installer" requirements --os-release-file "$root/os-release"

# A malicious os-release field is DATA; the read-only parser never sources it.
touch_marker="$root/should-not-exist"
printf 'ID=$(touch %s)\nVERSION_ID="13"\n' "$touch_marker" > "$root/os-release"
bad bash "$installer" requirements --os-release-file "$root/os-release"
[[ ! -e $touch_marker ]] || fail 'OS release contents were executed as shell'
write_os debian 13

for backends in native, native,,wireguard wireguard,wireguard all,wireguard ipsec,ipsec nativex; do
  bad bash "$installer" requirements --backends "$backends" --os-release-file "$root/os-release"
done

# Only the read-only requirements action accepts an OS release fixture.
mkdir -p "$root/prefix/bin" "$root/prefix/lib"
bad bash "$installer" install --bundle "$root/missing-bundle" --prefix "$root/prefix" \
  --os-release-file "$root/os-release"
[[ ! -e "$root/prefix/bin/stl" ]] || fail 'fixture input modified installed identity'
bad bash "$installer" uninstall --prefix "$root/prefix" --backends all

printf 'Installer requirements checks PASS (Ubuntu 22.04+, Debian 11+, package plans, unsafe inputs, EOL).\n'
