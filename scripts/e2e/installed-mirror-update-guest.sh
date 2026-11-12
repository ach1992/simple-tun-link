#!/usr/bin/env bash
# Exercise installed /usr/local/bin/stl CLI and confirmed mirror Update menu
# in a disposable Debian/Ubuntu root guest. Never mount networking, Docker socket, host
# package database, host STL State, or an Owner/Agent production filesystem.
set -Eeuo pipefail
umask 077

fail() { printf 'INSTALLED_MIRROR_GUEST_FAILED=%s\n' "$1" >&2; exit 1; }
[[ $EUID == 0 && -f /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]] ||
  fail not_disposable_root_guest
[[ ${STL_E2E_BOOTSTRAP_SHA:-} =~ ^[0-9a-f]{64}$ &&
   ${STL_E2E_OLDER_SHA:-} =~ ^[0-9a-f]{64}$ ]] || fail invalid_pinned_fixture
[[ ${STL_E2E_OLDER_NAME:-} =~ ^stl_v999\.0\.0_linux_(amd64|arm64)_local-install\.sh$ ]] ||
  fail invalid_test_file_name
arch=${BASH_REMATCH[1]}
case "$(uname -m)" in
  x86_64) [[ $arch == amd64 ]] || fail wrong_guest_arch ;;
  aarch64) [[ $arch == arm64 ]] || fail wrong_guest_arch ;;
  *) fail unsupported_guest_arch ;;
esac
[[ ! -e /usr/local/bin/stl ]] || fail guest_not_fresh
[[ -f /mnt/stl-older.sh && -d /mnt/stl-mirror &&
   -f /mnt/stl-test.crt && -f /mnt/stl-test.key &&
   -f /mnt/stl-server.py && -f /mnt/stl-install-doc ]] || fail incomplete_ro_mounts

# Only this disposable guest performs any APT transactions. A fixed signed
# Debian/Ubuntu distribution archive provides the selected prerequisites.
apt-get update -o APT::Update::Error-Mode=any >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  curl ca-certificates python3 iproute2 iptables kmod wireguard-tools >/dev/null

install -m 0644 /mnt/stl-test.crt /usr/local/share/ca-certificates/stl-mirror-e2e.crt
update-ca-certificates >/dev/null
export NO_PROXY=localhost,127.0.0.1
export no_proxy=$NO_PROXY
export HTTPS_PROXY=http://127.0.0.1:9
export ALL_PROXY=http://127.0.0.1:9
install -d -m 0700 /root/stl
install -m 0600 -- /mnt/stl-older.sh "/root/stl/$STL_E2E_OLDER_NAME"

root_line=$(grep '^/usr/bin/env -i HOME=/root .*fail SHA256_MISMATCH' /mnt/stl-install-doc)
[[ $(printf '%s\n' "$root_line" | wc -l) == 1 ]] || fail missing_literal_trusted_local_command
root_line=${root_line/TRUSTED_SHA256/$STL_E2E_OLDER_SHA}
eval "$root_line"
[[ -x /usr/local/bin/stl && -f /usr/local/lib/simple-tun-link/install-record ]] ||
  fail initial_installed_version_or_record_missing
/usr/local/bin/stl version --json | grep -Fq '"version":"v999.0.0"' ||
  fail older_installed_version_wrong
before_binary=$(sha256sum /usr/local/bin/stl | cut -d' ' -f1)
before_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1)
# This is a clean disposable installation: failed download paths must not
# create canonical Link State. The root guest contains no user Link data.
[[ ! -e /var/lib/simple-tun-link && ! -L /var/lib/simple-tun-link ]] ||
  fail synthetic_guest_has_unexpected_link_state
# Preserve the list of unrelated preexisting /tmp scratch entries. The
# verified root command and canonical Bash must remove their OWN new ones.
tmp_before=$(find /tmp -maxdepth 1 -name 'tmp.*' -printf '%f\n' | sort)
# A successful canonical install intentionally retains its COMMITTED journal
# pending a subsequent installer reconciliation; rejecting a Mirror response
# may retire that old journal but must never leave a new/uncommitted stage.
preexisting_committed=$(find /usr/local/bin -maxdepth 1 -type d -name '.stl-install.*' -printf '%f\n')

mode=/root/stl-mirror-fixture-mode
printf 'normal\n' > "$mode"
python3 /mnt/stl-server.py /mnt/stl-mirror /mnt/stl-test.crt /mnt/stl-test.key "$mode" "$arch" \
  > /root/stl-mirror-server.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true' EXIT
mirror_url='https://localhost:8443/install.sh'
ready=0
for _ in {1..100}; do
  if curl -fsS --connect-timeout 1 --max-time 2 "$mirror_url" -o /dev/null 2>/dev/null; then
    ready=1
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || fail tls_fixture_server_crashed
  sleep 0.1
done
[[ $ready == 1 ]] || { cat /root/stl-mirror-server.log >&2; fail tls_fixture_not_ready; }
echo 'DISPOSABLE_INSTALLED_CLI_TLS_TRUST_AND_SOURCE=PASS'

# The real root CLI (not just an old bash bootstrap) must stop at each
# first/second/third-hop integrity and streaming bound. After each refusal,
# verify both installed identities and that no private candidate survives.
assert_unchanged() {
  [[ $(sha256sum /usr/local/bin/stl | cut -d' ' -f1) == "$before_binary" ]] ||
    fail "rejected_$1_changed_binary"
  [[ $(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1) == "$before_record" ]] ||
    fail "rejected_$1_changed_ownership_record"
  [[ ! -e /var/lib/simple-tun-link && ! -L /var/lib/simple-tun-link ]] ||
    fail "rejected_$1_created_link_state"
  [[ $(find /tmp -maxdepth 1 -name 'tmp.*' -printf '%f\n' | sort) == "$tmp_before" ]] ||
    fail "rejected_$1_retained_unowned_tmp_download"
  shopt -s nullglob
  local residue=(/root/.stl-mirror-preflight.* /root/.stl-preflight.*)
  local committed=(/usr/local/bin/.stl-install.*)
  shopt -u nullglob
  (( ${#residue[@]} == 0 )) || fail "rejected_$1_retained_private_snapshot"
  local path
  for path in "${committed[@]}"; do
    [[ -d $path && ! -L $path && -f $path/COMMITTED &&
       $(printf '%s\n' "$preexisting_committed" | grep -Fxc "${path##*/}") == 1 ]] ||
      fail "rejected_$1_retained_new_or_uncommitted_transaction_stage"
  done
}
try_bad() {
  local case_name=$1 reason=$2 digest=${3:-$STL_E2E_BOOTSTRAP_SHA}
  # Atomic publication of the test-only fault selector prevents accidental
  # transitional zero-byte reads by the isolated HTTPS server.
  printf '%s\n' "$case_name" > "$mode.new"
  mv -f -- "$mode.new" "$mode"
  if /usr/local/bin/stl update --mirror "$mirror_url" --sha256 "$digest" \
      > "/root/stl-$case_name.out" 2>&1; then
    fail "accepted_unverified_$case_name"
  fi
  grep -Fq "$reason" "/root/stl-$case_name.out" ||
    { cat "/root/stl-$case_name.out" >&2; fail "missing_recovery_reason_$case_name"; }
  assert_unchanged "$case_name"
  echo "DISPOSABLE_MIRROR_REJECT_${case_name^^}=PASS"
}
try_bad normal 'independent SHA256 mismatch' "$(printf '%064d' 0)"
try_bad bootstrap-tamper 'independent SHA256 mismatch'
try_bad installer-oversize-known 'mirror_canonical_installer_unverified'
try_bad installer-oversize-chunked 'mirror_canonical_installer_unverified'
try_bad sums-oversize-chunked 'mirror_release_asset_unverified'
try_bad manifest-oversize-known 'mirror_release_asset_unverified'
try_bad manifest-truncated 'mirror_release_asset_unverified'
try_bad sums-tamper 'mirror_release_asset_unverified'
try_bad asset-tamper 'release_integrity_unverified'
try_bad asset-oversize-chunked 'mirror_release_asset_unverified'

printf 'normal\n' > "$mode.new"
mv -f -- "$mode.new" "$mode"
# Real installed-root, narrow NO_COLOR PTY menu: select the GitHub-free
# trusted HTTPS mirror, reject invalid input/digest, require fresh UPDATE,
# and delegate the successful path to the existing CLI/canonical installer.
python3 /mnt/stl-menu-pty.py "$mirror_url" "$STL_E2E_BOOTSTRAP_SHA" \
  /root/stl-mirror-valid-update.out ||
  fail valid_exact_pinned_mirror_menu_update_failed
/usr/local/bin/stl version --json | grep -Fq '"version":"v999.0.1"' ||
  fail valid_mirror_update_version_not_changed
[[ $(sha256sum /usr/local/bin/stl | cut -d' ' -f1) != "$before_binary" &&
   $(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1) != "$before_record" ]] ||
  fail valid_mirror_update_did_not_publish_owned_binary
grep -Fq '[OK] Canonical Update reported success: v999.0.1' /root/stl-mirror-valid-update.out ||
  fail valid_mirror_update_missing_success_identity
shopt -s nullglob
residue=(/root/.stl-mirror-preflight.* /root/.stl-preflight.*)
committed=(/usr/local/bin/.stl-install.*)
shopt -u nullglob
(( ${#residue[@]} == 0 )) || fail valid_mirror_update_retained_private_snapshot
# Post-commit evidence is intentionally durable and must not be mistaken
# for an unclean download. The next canonical invocation reconciles it.
for path in "${committed[@]}"; do
  [[ -d $path && ! -L $path && -f $path/COMMITTED ]] ||
    fail successful_mirror_update_retained_uncommitted_stage
done
[[ ! -e /tmp/stl-apt-was-called ]] || fail unexpected_apt_stub_invocation
[[ ! -e /var/lib/simple-tun-link && ! -L /var/lib/simple-tun-link ]] ||
  fail verified_update_unexpectedly_created_link_state
echo 'INSTALLED_STL_MIRROR_UPDATE_FULL_TLS_BOUNDING_AND_IDENTITY=PASS'
