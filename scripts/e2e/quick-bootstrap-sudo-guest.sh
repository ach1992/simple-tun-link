#!/usr/bin/env bash
# Genuine sudo handoff and root-private canonical snapshot in a disposable
# guest only. The canonical payload is a harmless test script; no STL/APT
# installation, service or host networking is changed by this fixture.
set -Eeuo pipefail
umask 077
fail() { echo "QUICK_SUDO_ROOT_GUEST_FAILED=$*" >&2; exit 1; }
[[ $EUID == 0 && -e /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]] ||
  fail not_an_approved_disposable_root_guest
[[ -x /usr/bin/sudo && -f /mnt/stl-quick-install.sh ]] || fail missing_sudo_or_source
id stloperator >/dev/null || fail missing_real_nonroot_sudo_operator
prefix=/home/stloperator/quick-test
install -d -o stloperator -g stloperator -m 0700 "$prefix"
install -d -o stloperator -g stloperator -m 0700 "$prefix/bin"
# A pinned, harmless "canonical" fixture exercises the complete real
# quick bootstrap -> genuine sudo -> root-owned snapshot boundary.
cat > "$prefix/canonical.sh" <<'CANONICAL'
#!/bin/bash
set -Eeuo pipefail
printf 'ROOT_CANONICAL_RAN=%s\n' "$1" >> /tmp/stl-quick-root-ran
CANONICAL
chmod 0644 "$prefix/canonical.sh"
digest=$(/usr/bin/sha256sum < "$prefix/canonical.sh")
digest=${digest%% *}
[[ $digest =~ ^[0-9a-f]{64}$ ]] || fail invalid_fixture_digest
sed '$d' /mnt/stl-quick-install.sh > "$prefix/bootstrap.sh"
printf 'quick_install_main "v0.9.99" "" "%s" "" "$@"\n' "$digest" >> "$prefix/bootstrap.sh"
chmod 0644 "$prefix/bootstrap.sh"
[[ $(tail -n 1 "$prefix/bootstrap.sh") == *"$digest"* ]] || fail missing_pinned_fixture
cat > "$prefix/bin/curl" <<'CURL'
#!/bin/bash
set -Eeuo pipefail
[[ ${!#} == https://raw.githubusercontent.com/ach1992/simple-tun-link/v0.9.99/scripts/install.sh ]] ||
  exit 89
cat /home/stloperator/quick-test/canonical.sh
CURL
chmod 0755 "$prefix/bin/curl"
chown -R stloperator:stloperator "$prefix"
run_operator() {
  local args=$*
  su -s /bin/bash stloperator -c     "PATH=/home/stloperator/quick-test/bin:/usr/sbin:/usr/bin:/sbin:/bin /bin/bash $prefix/bootstrap.sh $args"
}
# Existing installed Core/State from the regular sudo-operator acceptance is
# preserved before and after this isolated handoff.
before_bin=$(/usr/bin/sha256sum < /usr/local/bin/stl)
before_record=$(/usr/bin/sha256sum < /usr/local/lib/simple-tun-link/install-record)
run_operator > /tmp/stl-quick-positive.out 2> /tmp/stl-quick-positive.err ||
  { cat /tmp/stl-quick-positive.err >&2; fail genuine_sudo_positive_install; }
run_operator update > /tmp/stl-quick-update.out 2> /tmp/stl-quick-update.err ||
  { cat /tmp/stl-quick-update.err >&2; fail genuine_sudo_positive_update; }
[[ $(grep -c '^ROOT_CANONICAL_RAN=' /tmp/stl-quick-root-ran) == 2 ]] ||
  fail positive_install_and_update_not_executed_as_root
# Controlled same-UID replacement at the exact sudo boundary. A naive
# pre-sudo hash followed by sudo bash user-path would have run these bytes.
mv -- /usr/bin/sudo /usr/bin/stl-test-sudo-real
cat > /usr/bin/sudo <<'SUDO_INTERCEPT'
#!/bin/bash
set -Eeuo pipefail
if [[ -f /home/stloperator/quick-test/arm-swap ]]; then
  args=("$@")
  for ((i=0; i+2 < ${#args[@]}; i++)); do
    if [[ ${args[i]} == stl && ${args[i+1]} == /tmp/*/install.sh ]]; then
      source=${args[i+1]}
      printf '#!/bin/bash\necho MALICIOUS_ROOT_EXECUTED >> /tmp/stl-quick-root-ran\n' > "$source"
      rm -- /home/stloperator/quick-test/arm-swap
      break
    fi
  done
fi
exec -a sudo /usr/bin/stl-test-sudo-real "$@"
SUDO_INTERCEPT
chmod 0755 /usr/bin/sudo
su -s /bin/bash stloperator -c "touch $prefix/arm-swap"
if run_operator > /tmp/stl-quick-race.out 2> /tmp/stl-quick-race.err; then
  fail same_uid_source_replacement_executed_as_root
fi
grep -q 'Privileged private snapshot SHA256 mismatch after sudo' /tmp/stl-quick-race.out ||
  { cat /tmp/stl-quick-race.out /tmp/stl-quick-race.err >&2; fail missing_root_snapshot_mismatch_diagnostic; }
[[ ! -e "$prefix/arm-swap" ]] || fail race_fixture_not_triggered
[[ $(grep -c '^ROOT_CANONICAL_RAN=' /tmp/stl-quick-root-ran) == 2 ]] ||
  fail race_changed_root_executions
! grep -q 'MALICIOUS_ROOT_EXECUTED' /tmp/stl-quick-root-ran ||
  fail replaced_source_executed_as_root
mv -- /usr/bin/stl-test-sudo-real /usr/bin/sudo
# Root-only private snapshots must not survive either successful or rejected
# execution. No package, binary, State or service mutation is authorized.
shopt -s nullglob
remaining=(/root/.stl-quick-bootstrap.*)
shopt -u nullglob
[[ ${#remaining[@]} -eq 0 ]] || fail root_private_snapshot_not_cleaned
[[ $(/usr/bin/sha256sum < /usr/local/bin/stl) == "$before_bin" &&
   $(/usr/bin/sha256sum < /usr/local/lib/simple-tun-link/install-record) == "$before_record" ]] ||
  fail quick_sudo_fixture_mutated_installed_core_or_record
echo 'REAL_NONROOT_SUDO_ROOT_PRIVATE_CANONICAL_SNAPSHOT_INSTALL_UPDATE_AND_SWAP=PASS'
