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
for distro in 'ubuntu 20.04' 'ubuntu 22.04' 'ubuntu 22.10' 'ubuntu 24.04' 'ubuntu 26.04' \
              'debian 10' 'debian 11' 'debian 12' 'debian 13' 'debian 14'; do
  read -r os version <<< "$distro"
  write_os "$os" "$version"
  plan masque
  grep -qx "packages=iproute2" "$root/out" || fail "wrong MASQUE-only package list on $distro"
  plan native,masque
  grep -qx "packages=iproute2 iptables kmod" "$root/out" || fail "MASQUE changed native packages on $distro"
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
done

# Do not guess capability from a numeric release. Unsupported package
# managers and malformed OS identities still fail before package effects.
for distro in 'fedora 42' 'linuxmint 22'; do
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

for backends in native, native,,wireguard wireguard,wireguard all,wireguard ipsec,ipsec quic,quic quic, masque,masque masque, nativex; do
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

# Exercise the real GPGV machine-status parser directly. InRelease may carry
# both an official archive signature and a newer unknown co-signature. Never
# accept an unknown-only, malformed, bad, revoked or expired signer.
sed -n '/^apt_archive_signature_status_valid() {/,/^}/p' "$installer" > "$root/stl-archive-verify.sh"
[[ $(grep -c '^apt_archive_signature_status_valid() {' "$root/stl-archive-verify.sh") == 1 ]] ||
  fail 'canonical GPGV status parser unavailable'
# shellcheck source=/dev/null
source "$root/stl-archive-verify.sh"
key=78DBA3BC47EF2265
{
  printf '[GNUPG:] GOODSIG 6ED0E7B82643E131 Debian Archive Automatic Signing Key\n'
  printf '[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131 2026-07-11 1783765031 0 4 0 1 8 01 B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8\n'
  printf '[GNUPG:] ERRSIG %s 1 8 01 1783765032 9 B8E5F13176D2A7A75220028078DBA3BC47EF2265\n' "$key"
  printf '[GNUPG:] NO_PUBKEY %s\n' "$key"
  printf '[GNUPG:] VALIDSIG 4D64FEC119C2029067D6E791F8D2585B8783D481 2026-07-11 1783765141 0 4 0 22 8 01 4D64FEC119C2029067D6E791F8D2585B8783D481\n'
} > "$root/gpgv-status"
apt_archive_signature_status_valid 2 "$root/gpgv-status" || fail 'real Debian co-signed archive rejected'
apt_archive_signature_status_valid 0 "$root/gpgv-status" || fail 'verified co-signed archive rejected with success code'
bad_status="$root/gpgv-status"
printf '[GNUPG:] ERRSIG %s 1 8 01 1783765032 9 %s\n[GNUPG:] NO_PUBKEY %s\n' "$key" "$key" "$key" > "$bad_status"
if apt_archive_signature_status_valid 2 "$bad_status"; then fail 'unknown-only signer accepted'; fi
printf '[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131\n' > "$bad_status"
if apt_archive_signature_status_valid 2 "$bad_status"; then fail 'unexpected verifier error accepted'; fi
if apt_archive_signature_status_valid 1 "$bad_status"; then fail 'bad verifier exit accepted'; fi
for bad_code in BADSIG REVKEYSIG EXPKEYSIG EXPSIG KEYREVOKED KEYEXPIRED SIGEXPIRED NODATA FAILURE ERROR; do
  printf '[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131\n[GNUPG:] %s AAAAAAAA\n' "$bad_code" > "$bad_status"
  if apt_archive_signature_status_valid 0 "$bad_status"; then fail "$bad_code signer accepted"; fi
done
printf '[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131\n[GNUPG:] ERRSIG %s 1 8 01 1783765032 4 %s\n' "$key" "$key" > "$bad_status"
if apt_archive_signature_status_valid 2 "$bad_status"; then fail 'unknown non-missing signer failure accepted'; fi
printf '[GNUPG:] VALIDSIG 4CB50190207B4758A3F73A796ED0E7B82643E131\n[GNUPG:] ERRSIG %s 1 8 01 1783765032 9 %s\n' "$key" "$key" > "$bad_status"
if apt_archive_signature_status_valid 2 "$bad_status"; then fail 'unpaired NO_PUBKEY accepted'; fi
echo 'APT_OFFICIAL_COSIGNATURE_MISSING_KEY_AND_INVALID_SIGNER_GATES=PASS'

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
sed -n '/^apt_update_only_lists_lock_stream() {/,/^}/p' "$installer" > "$root/apt-update-functions.sh"
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
    progressive)
      printf 'APT_REFRESH_EARLY_PROGRESS\n'
      touch "$root/apt-progress-start"
      while [[ ! -e $root/apt-allow-finish ]]; do /bin/sleep 0.05; done
      printf 'Reading package lists... Done\n'
      return 0 ;;

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
grep -q 'Reading package lists' "$root/apt.err" || fail 'successful APT refresh output lost'
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
# A live APT update must show progress before apt-get returns. The fake
# process blocks after writing the first line until the test opens the gate.
reset_fake_apt
fake_apt_mode=progressive
apt_update_indexes > "$root/apt-progress.out" 2> "$root/apt-progress.err" &
progress_pid=$!
progress_seen=0
for ((wait_attempt=0; wait_attempt<100; wait_attempt++)); do
  if grep -Fq 'APT_REFRESH_EARLY_PROGRESS' "$root/apt-progress.err" 2>/dev/null; then
    progress_seen=1
    break
  fi
  /bin/sleep 0.05
done
touch "$root/apt-allow-finish"
wait "$progress_pid" || fail 'progressive APT refresh unexpectedly failed'
[[ $progress_seen == 1 ]] || fail 'APT progress stayed buffered until the child exited'
grep -Fq 'Reading package lists... Done' "$root/apt-progress.err" ||
  fail 'APT final progress line was lost'

# The streaming classifier must forward the original bytes, even when a
# non-retryable line is longer than its bounded read chunk or lacks newline.
printf 'E: Could not get lock /var/lib/apt/lists/lock - open (11: Resource temporarily unavailable)\n' > "$root/apt-raw.txt"
printf '%02100d\n' 0 >> "$root/apt-raw.txt"
if apt_update_only_lists_lock_stream < "$root/apt-raw.txt" 2> "$root/apt-raw.err"; then
  fail 'long APT diagnostic was mistakenly classified as lists-lock-only'
fi
cmp -s "$root/apt-raw.txt" "$root/apt-raw.err" ||
  fail 'long APT diagnostic was truncated or modified'
printf 'E: Could not get lock /var/lib/apt/lists/lock - truncated' > "$root/apt-raw.txt"
if apt_update_only_lists_lock_stream < "$root/apt-raw.txt" 2> "$root/apt-raw.err"; then
  fail 'non-newline-terminated lock diagnostic was retried'
fi
cmp -s "$root/apt-raw.txt" "$root/apt-raw.err" ||
  fail 'non-newline-terminated APT diagnostic was lost or modified'
unset -f apt-get sleep fake_apt_lock reset_fake_apt
printf 'APT_CANONICAL_LOCK_RETRY_AND_NONLOCK_FAIL_CLOSED=PASS\n'
printf 'APT_PARTIAL_INDEX_ERROR_MODE_ANY=PASS\n'


# Run actual canonical read-only simulation and capture helpers with a
# mock package manager. No host APT, disk inventory or package changes.
sed -n '/^apt_plan_capture_selected() {/,/^}/p' "$installer" > "$root/apt-resolver-functions.sh"
sed -n '/^apt_resolve_plan() {/,/^}/p' "$installer" >> "$root/apt-resolver-functions.sh"
[[ $(grep -c '^apt_plan_capture_selected() {' "$root/apt-resolver-functions.sh") == 1 &&
   $(grep -c '^apt_resolve_plan() {' "$root/apt-resolver-functions.sh") == 1 ]] ||
  fail 'canonical read-only resolver functions unavailable'
# shellcheck source=/dev/null
source "$root/apt-resolver-functions.sh"
apt_safety=()
missing=(wireguard-tools)
apt_sources_must_be_authenticated() { :; }
apt_verify_distro_candidates() { :; }
package_installed() { return 1; }
fake_plan_mode=success
apt-get() {
  [[ $1 == -s ]] || { echo 'Wrong fake simulation action' >&2; return 91; }
  case "$fake_plan_mode" in
    success)
      printf 'Reading package lists...\n'
      printf 'Inst wireguard-tools (1.2.3 Ubuntu:24.04 [amd64])\n'
      printf 'Conf wireguard-tools (1.2.3 Ubuntu:24.04 [amd64])\n'
      ;;
    fail_stdout)
      printf 'E: Unable to correct dependency problems: stdout-only resolver detail\n'
      return 100 ;;
    fail_stderr)
      printf 'W: simulated partial plan context\n'
      printf 'E: Dependency version conflict: stderr-only resolver detail\n' >&2
      return 100 ;;
    verbose_success)
      printf 'APT_SIMULATION_EARLY\n'
      printf '%070000d\n' 0
      printf 'APT_SIMULATION_LAST_LINE\n'
      printf 'Inst wireguard-tools (1.2.3 Ubuntu:24.04 [amd64])\n'
      ;;
    removal_after_verbose)
      printf '%070000d\n' 0
      printf 'Inst wireguard-tools (1.2.3 Ubuntu:24.04 [amd64])\n'
      printf 'Remv old-package [1.0]\n'
      ;;
    empty_plan)
      printf 'Reading package lists...\n'
      ;;
    unterminated_diagnostic)
      printf 'Inst wireguard-tools (1.2.3 Ubuntu:24.04 [amd64])\n'
      printf 'APT_DIAG_NO_FINAL_NEWLINE'
      ;;
    *) return 88 ;;
  esac
}
apt_resolve_plan > "$root/plan.out" 2> "$root/plan.err" ||
  fail 'valid APT simulation failed'
[[ $apt_plan == 'wireguard-tools=1.2.3' ]] ||
  fail "APT simulated plan parsing changed: $apt_plan"
grep -Fq 'Inst wireguard-tools' "$root/plan.err" ||
  fail 'valid APT simulation details were not displayed'
fake_plan_mode=unterminated_diagnostic
apt_resolve_plan > "$root/plan.out" 2> "$root/plan.err" ||
  fail 'valid simulation with non-newline-terminated trailing diagnostic was rejected'
[[ $apt_plan == wireguard-tools=1.2.3 ]] ||
  fail 'unterminated APT diagnostic changed the install plan'
[[ $(tail -c 25 "$root/plan.err") == 'APT_DIAG_NO_FINAL_NEWLINE' ]] ||
  fail 'unterminated APT diagnostic bytes were changed'
fake_plan_mode=verbose_success
apt_resolve_plan > "$root/plan.out" 2> "$root/plan.err" ||
  fail 'valid plan after 70 KiB of diagnostics was rejected'
[[ $apt_plan == 'wireguard-tools=1.2.3' ]] ||
  fail 'large diagnostics changed the selected plan'
[[ $apt_plan_sha256 == "$(printf '%s' "$apt_plan" | sha256sum | cut -d' ' -f1)" ]] ||
  fail 'selected APT plan fingerprint drifted'
grep -Fq 'APT_SIMULATION_LAST_LINE' "$root/plan.err" ||
  fail 'large APT diagnostics were not forwarded in full'
for fake_plan_mode in fail_stdout fail_stderr removal_after_verbose empty_plan; do
  apt_plan='unset'
  if ( apt_resolve_plan > "$root/plan.out" 2> "$root/plan.err" ); then
    fail "invalid simulation $fake_plan_mode was accepted"
  fi
  [[ $apt_plan == unset ]] ||
    fail "failed $fake_plan_mode published partial approved plan"
  case "$fake_plan_mode" in
    fail_stdout)
      grep -Fq 'stdout-only resolver detail' "$root/plan.err" || {
        cat "$root/plan.err" >&2
        fail 'failed APT simulation suppressed stdout diagnostic'
      } ;;
    fail_stderr)
      grep -Fq 'stderr-only resolver detail' "$root/plan.err" &&
      grep -Fq 'simulated partial plan context' "$root/plan.err" ||
        fail 'failed APT simulation suppressed stderr or stdout' ;;
    removal_after_verbose)
      grep -Fq 'Remv old-package' "$root/plan.err" ||
        fail 'late destructive APT fact was not observed' ;;
    empty_plan)
      grep -Fq 'Reading package lists' "$root/plan.err" ||
        fail 'empty plan diagnostics were suppressed' ;;
  esac
  if [[ $fake_plan_mode == removal_after_verbose ]]; then
    grep -Fq 'APT plan would remove packages' "$root/plan.err" ||
      fail 'late destructive APT operation was not rejected'
  elif [[ $fake_plan_mode == empty_plan ]]; then
    grep -Fq 'APT plan omitted a required selected package' "$root/plan.err" ||
      fail 'empty simulated plan was accepted'
  else
    grep -Fq 'APT_DEPENDENCY_PLAN' "$root/plan.err" ||
      fail "failed APT simulation lacked a typed stage: $fake_plan_mode"
  fi
  if [[ $fake_plan_mode == fail_stdout || $fake_plan_mode == fail_stderr ]]; then
    grep -Fq 'apt_get_exit=100' "$root/plan.err" ||
      fail "APT failure lost actual process exit code: $fake_plan_mode"
  fi
done
unset -f apt-get apt_sources_must_be_authenticated apt_verify_distro_candidates package_installed
printf 'APT_SIMULATION_SELECTIVE_CAPTURE_AND_FULL_DIAGNOSTICS=PASS\n'

# Package names are not the admission contract when an existing tool is
# usable. Exercise the exact production helper, not a duplicate test policy;
# nothing below runs APT or alters the host package database.
(
  sed -n '/^prerequisite_tool_usable() {/,/^}/p' "$installer" > "$root/prerequisite-probe.sh"
  sed -n '/^prerequisite_satisfied() {/,/^}/p' "$installer" >> "$root/prerequisite-probe.sh"
  [[ $(grep -c '^prerequisite_tool_usable() {' "$root/prerequisite-probe.sh") == 1 &&
     $(grep -c '^prerequisite_satisfied() {' "$root/prerequisite-probe.sh") == 1 ]] ||
    fail 'canonical capability-based package reuse functions unavailable'
  # shellcheck source=/dev/null
  source "$root/prerequisite-probe.sh"
  prerequisite_tool_usable cat --version || fail 'working root-controlled system executable not accepted'
  if prerequisite_tool_usable cat --not-an-option; then
    fail 'unusable executable accepted solely because it exists'
  fi
  package_installed() { [[ $1 == "${existing_package:-none}" ]]; }
  prerequisite_tool_usable() {
    case "$*" in
      'ip -json address show'|'iptables -V'|'ip6tables -V'|'modprobe --version'|'modinfo --version'|'wg --version'|'nft --version') return 0 ;;
      *) return 1 ;;
    esac
  }
  existing_package=
  for pkg in iproute2 iptables kmod wireguard-tools nftables; do
    prerequisite_satisfied "$pkg" || fail "functional alternative blocked by package name: $pkg"
  done
  for pkg in charon-systemd strongswan-swanctl libstrongswan-standard-plugins; do
    if prerequisite_satisfied "$pkg"; then
      fail "unverified IPsec vendor service/plugin accepted on tool-version proof: $pkg"
    fi
  done
  existing_package=iproute2
  prerequisite_tool_usable() { return 1; }
  prerequisite_satisfied iproute2 || fail 'already installed official package became a forced reinstall'
  if prerequisite_satisfied iptables; then fail 'unusable alternate firewall tool accepted'; fi
  existing_package=
  prerequisite_tool_usable() { [[ $1 != ip6tables ]]; }
  if prerequisite_satisfied iptables; then fail 'missing IPv6 firewall command was ignored'; fi
  prerequisite_tool_usable() { [[ $1 != modinfo ]]; }
  if prerequisite_satisfied kmod; then fail 'missing module metadata capability was ignored'; fi
)
printf 'PREREQUISITE_WORKING_TOOL_REUSE_NO_VERSION_PIN_AND_IPSEC_BOUNDARY=PASS\n'

# Reused prerequisites must not depend on functional APT or configured
# repositories. The exact canonical Ensure function is exercised with APT
# operations forbidden; a truly missing prerequisite must still fail closed.
(
  sed -n '/^ensure_packages() {/,/^}/p' "$installer" > "$root/ensure-reuse.sh"
  [[ $(grep -c '^ensure_packages() {' "$root/ensure-reuse.sh") == 1 ]] ||
    fail 'cannot extract canonical selected-package installer gate'
  # shellcheck source=/dev/null
  source "$root/ensure-reuse.sh"
  packages=(iproute2 iptables kmod)
  action=install backends=native os_id=debian os_version=13 want_ipsec=0
  expected_missing_supplied=0 expected_apt_plan_supplied=0 expected_apt_plan_sha256_supplied=0
  prerequisite_satisfied() { return 0; }
  command() {
    if [[ ${1:-} == -v && ( ${2:-} == apt-get || ${2:-} == dpkg-query ) ]]; then return 1; fi
    builtin command "$@"
  }
  apt_sources_must_be_authenticated() { fail 'unnecessary APT source check'; }
  apt_update_indexes() { fail 'unnecessary APT network refresh'; }
  apt_resolve_plan() { fail 'unnecessary APT dependency resolution'; }
  ensure_packages > "$root/available-reuse.out" 2>&1 ||
    fail 'working prerequisites still required unavailable APT'
  grep -Fq 'no APT changes' "$root/available-reuse.out" ||
    fail 'no-APT success result not explained'
  prerequisite_satisfied() { [[ $1 != iproute2 ]]; }
  if ( ensure_packages > "$root/missing-requires-apt.out" 2>&1 ); then
    fail 'actually missing prerequisite bypassed APT dependency gate'
  fi
  grep -Fq 'selected prerequisites are missing' "$root/missing-requires-apt.out" ||
    fail 'missing prerequisite had no actionable package-manager error'
)
printf 'ALREADY_USABLE_TOOLS_SKIP_MISSING_APT_AND_REPOSITORY_GATES=PASS\n'

printf 'Installer requirements checks PASS (capability-based Debian/Ubuntu, signed GPGV status, package plans, unsafe inputs).\n'
