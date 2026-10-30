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
  grep -qx "packages=iproute2 iptables kmod" "$root/out" || fail "wrong native package list on $distro"
  plan native,wireguard
  grep -qx "packages=iproute2 iptables kmod wireguard-tools" "$root/out" || fail "wrong WireGuard package list on $distro"
  plan native,quic
  grep -qx "packages=iproute2 iptables kmod wireguard-tools nftables" "$root/out" || fail "wrong QUIC package list on $distro"
  plan quic,wireguard
  grep -qx "packages=iproute2 iptables kmod wireguard-tools nftables" "$root/out" || fail "duplicate QUIC provider packages on $distro"
  plan native,ipsec
  grep -qx "packages=iproute2 iptables kmod charon-systemd strongswan-swanctl libstrongswan-standard-plugins" "$root/out" || fail "wrong IPsec package list on $distro"
  grep -q 'notice=IPsec PREPARE may briefly activate a new vendor strongSwan service' "$root/out" || fail 'IPsec package activation risk not flagged'
  plan all
  grep -qx "packages=iproute2 iptables kmod wireguard-tools nftables charon-systemd strongswan-swanctl libstrongswan-standard-plugins" "$root/out" ||
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

for backends in native, native,,wireguard wireguard,wireguard all,wireguard ipsec,ipsec quic,quic quic, nativex; do
  bad bash "$installer" requirements --backends "$backends" --os-release-file "$root/os-release"
done

# Only the read-only requirements action accepts an OS release fixture.
mkdir -p "$root/prefix/bin" "$root/prefix/lib"
bad bash "$installer" install --bundle "$root/missing-bundle" --prefix "$root/prefix" \
  --os-release-file "$root/os-release"
[[ ! -e "$root/prefix/bin/stl" ]] || fail 'fixture input modified installed identity'
bad bash "$installer" uninstall --prefix "$root/prefix" --backends all

# Read-only installed-host plan now includes a live dpkg inventory but
# never touches APT, even when one of the selected distro packages is missing.
live_out="$(bash "$installer" requirements --backends native 2>"$root/live.err")"
grep -q '^missing_packages=' <<< "$live_out" ||
  fail 'normal-host read-only requirements lost missing package field'
# A mismatched/unsafe expected package plan must not be accepted for any
# action other than explicit prepare, even with attacker shell variables.
bad bash "$installer" requirements --expected-missing iptables
bad bash "$installer" install --expected-missing iptables --bundle "$root/missing-bundle" --prefix "$root/prefix"

# Package preparation must not act on a foreign or offline executable
# and has no fixture, bundle, version or implicit backend selection.
bad bash "$installer" prepare
bad bash "$installer" prepare --backends native --prefix "$root/prefix"
bad bash "$installer" prepare --backends native --bundle "$root/foreign"
bad bash "$installer" prepare --backends wireguard --version v0.1.0
bad bash "$installer" prepare --backends ipsec --os-release-file "$root/os-release"
# Under test-user (non-root), even the canonical prefix must reject APT
# before package resolution or any package-manager modifications.
if [[ $EUID -ne 0 ]]; then
  bad bash "$installer" prepare --backends wireguard
fi
[[ ! -e "$root/prefix/bin/stl" ]] || fail 'package preparation modified offline installation'

# Exercise the ACTUAL canonical function, extracted verbatim without running
# the installer or mutating the host. A Go doctor query can leave a harmless
# private-unit LOAD=not-found placeholder that is not a foreign service.
sed -n '/^ipsec_only_not_found_private_placeholder() {/,/^}/p' "$installer" > "$root/ipsec-placeholder-function.sh"
[[ $(grep -c '^ipsec_only_not_found_private_placeholder() {' "$root/ipsec-placeholder-function.sh") == 1 ]] ||
  fail 'canonical placeholder parser unavailable'
# shellcheck source=/dev/null
source "$root/ipsec-placeholder-function.sh"
ghost=$'simple-tun-link-ipsec.service not-found inactive dead simple-tun-link-ipsec.service\n'
ipsec_only_not_found_private_placeholder "$ghost" ||
  fail 'benign absent STL-private systemd placeholder was rejected'
blocked=(
  ''
  'strongswan.service not-found inactive dead Vendor'
  'simple-tun-link-ipsec.service loaded inactive dead User'
  'simple-tun-link-ipsec.service not-found active running Bad'
  'simple-tun-link-ipsec.service not-found inactive dead'
  "$ghost"$'strongswan.service loaded active running Foreign\n'
  $'simple-tun-link-ipsec.service not-found inactive dead Unit\nsecond\n'
  $'simple-tun-link-ipsec.service not-found inactive dead Unit\r\n'
  $'simple-tun-link-ipsec.service not-found inactive dead \303\251\n'
  "$(printf 'simple-tun-link-ipsec.service not-found inactive dead %01200d\n' 0)"
)
for item in "${blocked[@]}"; do
  if ipsec_only_not_found_private_placeholder "$item"; then
    printf 'Unexpectedly accepted: %q\n' "$item" >&2
    fail 'foreign/malformed/overlong loaded-service identity was accepted'
  fi
done
echo 'IPSEC_CANONICAL_NOT_FOUND_GHOST_VS_FOREIGN_INVENTORY=PASS'

# Test the ACTUAL canonical command-invocation boundary as well as its
# parser. A fake systemctl writes independently controlled stdout/stderr;
# no host systemctl, package or service operation is performed.
sed -n '/^ipsec_loaded_unit_inventory_clean() (/,/^)/p' "$installer" > "$root/ipsec-loaded-units-function.sh"
[[ $(grep -c '^ipsec_loaded_unit_inventory_clean() (' "$root/ipsec-loaded-units-function.sh") == 1 ]] ||
  fail 'canonical systemctl observation boundary unavailable'
# shellcheck source=/dev/null
source "$root/ipsec-loaded-units-function.sh"
mkdir -p "$root/fake-systemd"
cat > "$root/fake-systemd/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ " $* " == *" list-units "* ]] || exit 44
cat "$STL_TEST_SYSTEMCTL_STDOUT"
cat "$STL_TEST_SYSTEMCTL_STDERR" >&2
exit "$STL_TEST_SYSTEMCTL_EXIT"
EOF
chmod 0700 "$root/fake-systemd/systemctl"
export STL_TEST_SYSTEMCTL_STDOUT="$root/systemctl-stdout"
export STL_TEST_SYSTEMCTL_STDERR="$root/systemctl-stderr"
export STL_TEST_SYSTEMCTL_EXIT=0
original_path=$PATH
PATH="$root/fake-systemd:$PATH"
printf '%s' "$ghost" > "$STL_TEST_SYSTEMCTL_STDOUT"
: > "$STL_TEST_SYSTEMCTL_STDERR"
ipsec_loaded_unit_inventory_clean || fail 'real benign stdout-only ghost invocation rejected'
printf 'systemctl warning: incomplete metadata' > "$STL_TEST_SYSTEMCTL_STDERR"
if ipsec_loaded_unit_inventory_clean; then
  fail 'real invocation accepted benign ghost despite nonempty stderr'
fi
# A merged-stream parser could falsely accept this stdout fragment completed
# by stderr: require independent stderr rejection, not only shape matching.
printf '%s' 'simple-tun-link-ipsec.service not-found inactive dead ' > "$STL_TEST_SYSTEMCTL_STDOUT"
printf '%s\n' 'systemctl warning' > "$STL_TEST_SYSTEMCTL_STDERR"
if ipsec_loaded_unit_inventory_clean; then
  fail 'real invocation accepted stderr completing a truncated placeholder'
fi
printf '%s' "$ghost" > "$STL_TEST_SYSTEMCTL_STDOUT"
: > "$STL_TEST_SYSTEMCTL_STDERR"
STL_TEST_SYSTEMCTL_EXIT=7
if ipsec_loaded_unit_inventory_clean; then
  fail 'real invocation accepted nonzero systemctl exit'
fi
STL_TEST_SYSTEMCTL_EXIT=0
printf '%s' 'simple-tun-link-ipsec.service not-found inactive dead truncated' > "$STL_TEST_SYSTEMCTL_STDOUT"
if ipsec_loaded_unit_inventory_clean; then
  fail 'real invocation accepted stdout lacking its final newline'
fi
printf '%sstrongswan.service loaded active running Foreign\n' "$ghost" > "$STL_TEST_SYSTEMCTL_STDOUT"
if ipsec_loaded_unit_inventory_clean; then
  fail 'real invocation accepted multiple loaded units'
fi
: > "$STL_TEST_SYSTEMCTL_STDOUT"
ipsec_loaded_unit_inventory_clean || fail 'real successful empty systemctl stdout rejected'
PATH=$original_path
echo 'IPSEC_SYSTEMCTL_INDEPENDENT_STDOUT_STDERR_AND_EXIT_BOUNDARY=PASS'

# Exercise the canonical index-refresh helpers against a fake APT process and
# fake clock. Never run the host's apt-get, sleep, dpkg or package hooks.
sed -n '/^apt_update_is_only_lists_lock() {/,/^}/p' "$installer" > "$root/apt-update-functions.sh"
sed -n '/^apt_update_indexes() {/,/^}/p' "$installer" >> "$root/apt-update-functions.sh"
[[ $(grep -c '^apt_update_indexes() {' "$root/apt-update-functions.sh") == 1 ]] || fail 'canonical APT refresh function unavailable'
# shellcheck source=/dev/null
source "$root/apt-update-functions.sh"
apt_safety=()
fake_apt_mode=
apt-get() {
  [[ ${*: -1} == update ]] || { echo 'unexpected APT operation' >&2; return 77; }
  local strict=0
  [[ " $* " != *' APT::Update::Error-Mode=any '* ]] || strict=1
  local calls=0
  [[ ! -f $root/apt-calls ]] || read -r calls < "$root/apt-calls"
  printf '%s\n' "$((calls+1))" > "$root/apt-calls"
  case "$fake_apt_mode" in
    transient) if (( calls == 0 )); then fake_apt_lock; return 100; fi ;;
    permanent) fake_apt_lock; return 100 ;;
    untrusted) printf 'E: The repository is not signed.\n' >&2; return 100 ;;
    mixed) fake_apt_lock; printf 'E: The repository is not signed.\n' >&2; return 100 ;;
    mixed_warning) fake_apt_lock; printf 'W: GPG error: the repository signature is invalid.\n' >&2; return 100 ;;
    mixed_err) fake_apt_lock; printf 'Err:1 https://invalid.example.invalid repository metadata failed\n' >&2; return 100 ;;
    mixed_unrelated) fake_apt_lock; printf 'N: An unrelated package-manager notice\n' >&2; return 100 ;;
    mixed_progress) fake_apt_lock; printf 'Hit:1 distribution repository index\n' >&2; return 100 ;;
    missing_primary) printf 'E: Unable to lock directory /var/lib/apt/lists/\n' >&2; return 100 ;;
    transient_progress) if (( calls == 0 )); then printf 'Reading package lists... Done\n'; fake_apt_lock; return 100; fi ;;
    transient_old_lock) if (( calls == 0 )); then printf 'E: Could not get lock /var/lib/apt/lists/lock - open (11: Resource temporarily unavailable)\nE: Unable to lock directory /var/lib/apt/lists/\n' >&2; return 100; fi ;;
    wrong_exit) fake_apt_lock; return 17 ;;
    partial_index)
      printf 'W: Failed to fetch repository index; using old index files instead.\n' >&2
      [[ $strict == 1 ]] && return 100
      return 0 ;;
    *) : ;;
  esac
  printf 'Reading package lists... Done\n'
}
fake_apt_lock() {
  printf 'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 840337 (apt-get)\nN: Be aware that removing the lock file is not a solution and may break your system.\nE: Unable to lock directory /var/lib/apt/lists/\n' >&2
}
sleep() {
  [[ $1 == 5 ]] || fail 'unexpected APT retry interval'
  printf 'wait\n' >> "$root/apt-waits"
}
reset_fake_apt() { rm -f "$root/apt-calls" "$root/apt-waits"; }
reset_fake_apt
fake_apt_mode=transient
apt_update_indexes > "$root/apt.out" 2> "$root/apt.err" || fail 'temporary APT lists lock was not retried'
[[ $(cat "$root/apt-calls") == 2 && $(wc -l < "$root/apt-waits") == 1 ]] || fail 'APT lock was not retried exactly once'
grep -q 'Reading package lists' "$root/apt.out" || fail 'successful APT refresh output lost'
for fake_apt_mode in transient_progress transient_old_lock; do
  reset_fake_apt
  apt_update_indexes > "$root/apt.out" 2> "$root/apt.err" || fail "expected APT lock variant was rejected: $fake_apt_mode"
  [[ $(cat "$root/apt-calls") == 2 && $(wc -l < "$root/apt-waits") == 1 ]] ||
    fail "legitimate APT lock variant was not retried once: $fake_apt_mode"
done
for fake_apt_mode in untrusted mixed mixed_warning mixed_err mixed_unrelated mixed_progress missing_primary wrong_exit partial_index; do
  reset_fake_apt
  if ( apt_update_indexes > "$root/apt.out" 2> "$root/apt.err" ); then
    fail "APT refresh accepted non-lock error: $fake_apt_mode"
  fi
  [[ $(cat "$root/apt-calls") == 1 && ! -e $root/apt-waits ]] || fail "APT retried non-lock error: $fake_apt_mode"
  if [[ $fake_apt_mode == partial_index ]]; then
    grep -q 'APT_INDEX_REFRESH failed; missing selected packages:' "$root/apt.err" ||
      fail 'partial APT index failure passed without actionable diagnostics'
  fi
done
reset_fake_apt
fake_apt_mode=permanent
if ( apt_update_indexes > "$root/apt.out" 2> "$root/apt.err" ); then
  fail 'APT permanent lock was not bounded'
fi
[[ $(cat "$root/apt-calls") == 12 && $(wc -l < "$root/apt-waits") == 11 ]] || fail 'APT lock retry budget was not bounded'
grep -q 'Do not delete APT lock files' "$root/apt.err" || fail 'permanent APT lock lacks safe recovery guidance'
unset -f apt-get sleep fake_apt_lock reset_fake_apt
printf 'APT_CANONICAL_LOCK_RETRY_AND_NONLOCK_FAIL_CLOSED=PASS\n'
printf 'APT_PARTIAL_INDEX_ERROR_MODE_ANY=PASS\n'

printf 'Installer requirements checks PASS (Ubuntu 22.04+, Debian 11+, package plans, unsafe inputs, EOL).\n'
