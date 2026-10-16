#!/usr/bin/env bash
# Run only inside isolated disposable Ubuntu systemd container in CI.
# The installer, candidate binaries, and release bundle are read-only mounts
# provided by the calling workflow; never affect the CI host or Owner hosts.
set -Eeuo pipefail
umask 077
fail() { echo "IPSEC_MANAGED_APT_E2E_FAILED=$1" >&2; exit 1; }
[[ ${STL_E2E_DISPOSABLE_GUEST:-} == approved && $EUID == 0 &&
   -f /.dockerenv && $(cat /proc/1/comm) == systemd ]] ||
  fail not_disposable_systemd_guest
[[ ! -f /usr/sbin/charon-systemd && ! -e /etc/systemd/system/strongswan.service ]] ||
  fail strongswan_not_clean_before_test
[[ -r /mnt/stl-install.sh && -d /mnt/stl-bundle ]] || fail missing_readonly_bundle
bash /mnt/stl-install.sh install --bundle /mnt/stl-bundle --backends native
[[ -x /usr/local/bin/stl ]] || fail no_verified_installed_binary
original=$(sha256sum /usr/local/bin/stl | awk '{print $1}')
record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}')
# Exercise a REAL pre-existing, distro-owned StrongSwan service in an
# isolated guest. Unlike the clean-host package case, this service belongs
# to the operator before PREPARE. Only a fresh, separately typed exact-unit
# STOP consent can change it; the menu must then provision STL separately.
if [[ ${STL_IPSEC_PREPARE_CASE:-} == existing_vendor ]]; then
  if [[ -f /usr/sbin/policy-rc.d ]]; then
    mv /usr/sbin/policy-rc.d /tmp/stl-existing-vendor-policy-rc.d
  fi
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    charon-systemd strongswan-swanctl libstrongswan-standard-plugins >/tmp/stl-existing-vendor-apt.log 2>&1 ||
    fail cannot_install_real_distro_vendor_fixture
  systemctl --system enable --now strongswan.service >/dev/null ||
    fail cannot_start_distro_owned_vendor_fixture
  [[ $(systemctl --system is-active strongswan.service) == active &&
     $(systemctl --system is-enabled strongswan.service) == enabled ]] ||
    fail existing_vendor_not_live_before_user_consent
  plan=$(bash /mnt/stl-install.sh requirements --backends native,ipsec) ||
    fail existing_vendor_package_inventory_unknown
  grep -qx "missing_packages=" <<< "$plan" ||
    fail existing_vendor_has_incomplete_package_install
  [[ ! -e /var/lib/simple-tun-link/ipsec ]] ||
    fail private_service_exists_before_consent
  /usr/bin/expect /mnt/managed-existing.exp || fail operator_vendor_consent_failed
  [[ $(systemctl --system is-active strongswan.service) == inactive &&
     $(systemctl --system is-enabled strongswan.service) == disabled ]] ||
    fail consented_vendor_not_stopped_disabled
  [[ $(systemctl --system is-active simple-tun-link-ipsec.service) == active ]] ||
    fail new_stl_private_service_not_started
  /usr/local/bin/stl doctor ipsec --json | grep -q '"activation_allowed":true' ||
    fail new_stl_private_service_not_admitted
  [[ $(sha256sum /usr/local/bin/stl | awk '{print $1}') == "$original" &&
     $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}') == "$record" ]] ||
    fail existing_vendor_workflow_modified_STL_installation
  echo "IPSEC_REAL_PRIOR_DISTRIBUTION_SERVICE_EXACT_OPERATOR_CONSENT=PASS"
  exit 0
fi

# An independently signed, APT-trusted third-party repository may spoof
# Origin/Label Ubuntu. Even if its higher version wins normal APT selection,
# the read-only STL preview must reject it before any package effects.
if [[ ${STL_IPSEC_PREPARE_CASE:-} == forged_origin ]]; then
  repo=/tmp/stl-test-untrusted-apt
  mkdir -p "$repo/pool" "$repo/dists/noble/main/binary-amd64" \
           /tmp/stl-test-fake-package/DEBIAN /tmp/stl-test-gnupg
  chmod 0700 /tmp/stl-test-gnupg
  cat > /tmp/stl-test-fake-package/DEBIAN/control <<'EOF'
Package: charon-systemd
Version: 999.1
Architecture: amd64
Maintainer: Disposable test <test@localhost>
Description: Disposable counterfeit candidate; never install
EOF
  chmod 0755 /tmp/stl-test-fake-package /tmp/stl-test-fake-package/DEBIAN
  chmod 0644 /tmp/stl-test-fake-package/DEBIAN/control
  dpkg-deb --build /tmp/stl-test-fake-package "$repo/pool/charon-systemd_999.1_amd64.deb" >/dev/null
  (cd "$repo" && dpkg-scanpackages pool /dev/null >dists/noble/main/binary-amd64/Packages)
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=Ubuntu \
    -o APT::FTPArchive::Release::Label=Ubuntu \
    -o APT::FTPArchive::Release::Suite=noble \
    -o APT::FTPArchive::Release::Codename=noble \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    release "$repo/dists/noble" > "$repo/dists/noble/Release"
  export GNUPGHOME=/tmp/stl-test-gnupg
  gpg --batch --passphrase '' --quick-generate-key 'Untrusted STL test signer <fake@localhost>' rsa2048 sign 0 >/dev/null 2>&1
  gpg --batch --output /tmp/stl-untrusted-archive.gpg --export 'Untrusted STL test signer'
  gpg --batch --yes --clearsign --output "$repo/dists/noble/InRelease" "$repo/dists/noble/Release"
  # APT acquires as _apt. Only these throwaway *public* repo artifacts and
  # archive public key may be world-readable; the signing private key stays
  # mode 0700 in the disposable guest's private GNUPGHOME.
  chmod 0644 /tmp/stl-untrusted-archive.gpg
  chmod 0755 "$repo" "$repo/pool" "$repo/dists" "$repo/dists/noble" "$repo/dists/noble/main" "$repo/dists/noble/main/binary-amd64"
  chmod 0644 "$repo"/pool/*.deb "$repo/dists/noble/main/binary-amd64/Packages" "$repo/dists/noble/Release" "$repo/dists/noble/InRelease"
  printf 'deb [signed-by=/tmp/stl-untrusted-archive.gpg] file:%s noble main\n' "$repo" > /etc/apt/sources.list.d/stl-test-untrusted.list
  apt-get update -qq
  policy=$(apt-cache policy charon-systemd)
  grep -qx '  Candidate: 999.1' <<< "$policy" || fail attacker_did_not_win_apt_candidate
  LC_ALL=C apt-get -s install --no-install-recommends charon-systemd \
    | grep -q 'Inst charon-systemd (999.1 Ubuntu:' || fail spoofed_apt_origin_not_observed
  if bash /mnt/stl-install.sh requirements --backends native,ipsec \
      >/tmp/stl-forged-preview 2>/tmp/stl-forged-stderr; then
    fail forged_origin_accepted_as_official_distro
  fi
  grep -q 'not signed by the distribution archive' /tmp/stl-forged-stderr ||
    fail forged_origin_not_rejected_by_signer
  [[ ! -e /usr/sbin/charon-systemd ]] || fail forged_origin_changed_packages
  [[ ! -e /var/lib/simple-tun-link/ipsec ]] || fail forged_origin_started_private_service
  echo 'IPSEC_FORGED_APT_ORIGIN_WITH_VALID_THIRD_PARTY_SIGNATURE_DENIED=PASS'
  exit 0
fi
if ! plan=$(bash /mnt/stl-install.sh requirements --backends native,ipsec); then
  # Source format triage only inside this stock disposable Ubuntu guest.
  apt-get indextargets --format 'APT_INDEX id=$(IDENTIFIER) file=$(FILENAME) component=$(COMPONENT) arch=$(ARCHITECTURE)' | head -n 16 >&2 || :
  fail real_ipsec_readonly_signer_preview_failed
fi
missing=$(sed -n 's/^missing_packages=//p' <<< "$plan")
apt_plan=$(sed -n 's/^apt_install=//p' <<< "$plan")
[[ $missing == *charon-systemd* && $apt_plan == *charon-systemd=* ]] ||
  fail no_real_strongswan_dependency_plan

case "${STL_IPSEC_PREPARE_CASE:-}" in
  ghost)
    # A read-only systemctl query can retain a harmless missing private-unit
    # placeholder. Prove it is genuinely not loaded and still allow PREPARE.
    systemctl --system --no-pager show -p LoadState simple-tun-link-ipsec.service \
      | grep -qx 'LoadState=not-found' || fail ghost_fixture_unit_is_real
    ghost_list=$(systemctl --system --no-pager --no-legend --plain --all \
      --type=service list-units 'strongswan*.service' 'charon*.service' \
      'ipsec.service' 'simple-tun-link-ipsec.service') ||
      fail ghost_fixture_systemd_query_failed
    # Some systemd versions garbage-collect missing-unit placeholders on
    # each read-only query. Both the empty inventory and a single benign
    # private-unit not-found record are safe; any other unit is forbidden.
    if [[ -n $ghost_list ]]; then
      [[ $ghost_list == 'simple-tun-link-ipsec.service not-found inactive dead '* ]] ||
        fail ghost_fixture_unexpected_loaded_service
      echo 'IPSEC_EXACT_NOT_FOUND_PLACEHOLDER_CACHED=PASS'
    else
      echo 'IPSEC_ABSENT_PLACEHOLDER_GARBAGE_COLLECTED=OBSERVED'
    fi
    [[ ! -e /etc/systemd/system/simple-tun-link-ipsec.service &&
       ! -e /usr/lib/systemd/system/simple-tun-link-ipsec.service ]] ||
      fail ghost_fixture_has_real_service
    echo 'IPSEC_EXACT_NOT_FOUND_PLACEHOLDER_OBSERVED=PASS'
    ;;
  foreign)
    # A dormant foreign drop-in is NOT made STL-owned by PREPARE consent.
    mkdir -p /etc/systemd/system/strongswan.service.d
    printf '[Service]\nExecStartPre=/usr/bin/touch /tmp/foreign-service-executed\n' \
      >/etc/systemd/system/strongswan.service.d/foreign.conf
    if bash /mnt/stl-install.sh prepare --backends native,ipsec \
       --expected-missing "$missing" --expected-apt-plan "$apt_plan"; then
      fail foreign_unit_override_accepted
    fi
    [[ ! -e /tmp/foreign-service-executed &&
       ! -e /usr/sbin/charon-systemd ]] || fail foreign_hook_or_package_touched
    echo "IPSEC_FOREIGN_PREEXISTING_DROPIN_DENIED_BEFORE_APT=PASS"
    exit 0
    ;;
  foreign_alias|foreign_prefix|foreign_attached|foreign_transient)
    case "$STL_IPSEC_PREPARE_CASE" in
      foreign_alias) dir=/etc/systemd/system/strongswan-swanctl.service.d ;;
      foreign_prefix) dir=/etc/systemd/system/strongswan-.service.d ;;
      foreign_attached) dir=/etc/systemd/system.attached/strongswan-swanctl.service.d ;;
      foreign_transient) dir=/run/systemd/transient/strongswan-swanctl.service.d ;;
    esac
    # Confirm new negative fixture paths are in this guest manager's UnitPath.
    if [[ $STL_IPSEC_PREPARE_CASE == foreign_attached ||
          $STL_IPSEC_PREPARE_CASE == foreign_transient ]]; then
      unitpaths=$(systemctl --system --no-pager show -p UnitPath) || fail missing_unitpath
      parent=${dir%/strongswan-swanctl.service.d}
      [[ " ${unitpaths#UnitPath=} " == *" $parent "* ]] ||
        fail fixture_unit_path_not_in_system_manager
    fi
    mkdir -p "$dir"
    printf '[Service]\nExecStartPre=/usr/bin/touch /tmp/foreign-alias-executed\n' \
      > "$dir/foreign.conf"
    foreign_checksum=$(sha256sum "$dir/foreign.conf" | awk '{print $1}')
    if bash /mnt/stl-install.sh prepare --backends native,ipsec \
       --expected-missing "$missing" --expected-apt-plan "$apt_plan"; then
      fail foreign_alias_override_accepted
    fi
    [[ ! -e /tmp/foreign-alias-executed && ! -e /usr/sbin/charon-systemd &&
       ! -e /var/lib/simple-tun-link/ipsec ]] ||
      fail foreign_alias_hook_package_or_service_touched
    [[ $(sha256sum "$dir/foreign.conf" | awk '{print $1}') == "$foreign_checksum" ]] ||
      fail foreign_override_content_was_modified
    [[ $(sha256sum /usr/local/bin/stl | awk '{print $1}') == "$original" &&
       $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}') == "$record" ]] ||
      fail foreign_override_replaced_stl_installation
    echo "IPSEC_FOREIGN_UNITPATH_DROPIN_DENIED_BEFORE_APT=$STL_IPSEC_PREPARE_CASE:PASS"
    exit 0
    ;;
  clean|partial|ghost) ;;
  *) fail invalid_case ;;
esac

# Consent is scoped to an exact simulated install/dependency set.
# A stale plan must be refused before APT, not silently refreshed.
if bash /mnt/stl-install.sh prepare --backends native,ipsec \
     --expected-missing "$missing" --expected-apt-plan 'incorrect=1'; then
  fail stale_apt_plan_accepted
fi
[[ ! -e /usr/sbin/charon-systemd ]] || fail stale_plan_installed_anything
echo "IPSEC_STALE_APT_DEPENDENCY_PLAN_DENIED=PASS"

# Docker's stock policy-rc.d vetoes vendor service starts, hiding the
# lifecycle that the user explicitly approved. Remove ONLY this disposable
# guest's packaging hook veto so the real distro maintainer scripts can
# start/enable the new vendor service. No host/CI service policy is touched.
if [[ -f /usr/sbin/policy-rc.d ]]; then
  mv /usr/sbin/policy-rc.d /tmp/stl-disposable-policy-rc.d
fi
# Inject an APT failure after its normal dpkg package configuration/hook
# phase. This is NOT an STL code failpoint: the actual vendor daemon may
# already be running when apt-get reports a nonzero result. The installer
# must not normalize an unverified transaction or start a private service.
if [[ ${STL_IPSEC_PREPARE_CASE:-} == partial ]]; then
  cat > /etc/apt/apt.conf.d/99-stl-test-interruption <<'EOF'
DPkg::Post-Invoke { "if systemctl --system is-active --quiet strongswan.service; then mkdir -p /run/systemd/system.attached; if [ -L /etc/systemd/system/strongswan-swanctl.service ]; then mv /etc/systemd/system/strongswan-swanctl.service /run/systemd/system.attached/strongswan-swanctl.service; else ln -s /usr/lib/systemd/system/strongswan.service /run/systemd/system.attached/strongswan-swanctl.service; fi; exit 17; fi"; };
EOF
  if bash /mnt/stl-install.sh prepare --backends native,ipsec \
    --expected-missing "$missing" --expected-apt-plan "$apt_plan" \
    >/tmp/stl-partial-out 2>/tmp/stl-partial-err; then
    fail interrupted_apt_was_reported_as_success
  fi
  rm -f /etc/apt/apt.conf.d/99-stl-test-interruption
  [[ -x /usr/sbin/charon-systemd ]] || fail partial_injection_never_reached_vendor_hooks
  [[ $(systemctl is-active strongswan.service 2>/dev/null || :) == active ]] ||
    fail partial_injection_never_started_vendor
  grep -q '^STL_IPSEC_APT_RECOVERY dpkg_audit=' /tmp/stl-partial-err ||
    fail no_readonly_dpkg_recovery_classification
  grep -q '^STL_IPSEC_APT_RECOVERY vendor_active=active ' /tmp/stl-partial-err ||
    fail no_readonly_vendor_recovery_classification
  # Deliberately require an attached-path-only alias, so the previous
  # /etc-only recovery classifier would incorrectly report "absent".
  [[ -L /run/systemd/system.attached/strongswan-swanctl.service &&
     ! -e /etc/systemd/system/strongswan-swanctl.service &&
     ! -L /etc/systemd/system/strongswan-swanctl.service ]] ||
    fail partial_alias_attached_only_fixture_not_created
  grep -q '^STL_IPSEC_APT_RECOVERY vendor_active=active .* alias=present_unverified$' /tmp/stl-partial-err ||
    fail partial_alias_in_attached_path_falsely_absent
  grep -q 'result=RECONCILIATION_REQUIRED retry=BLOCKED private_service=NOT_STARTED link=NOT_CREATED' \
    /tmp/stl-partial-err || fail partial_state_not_truthfully_reported
  [[ ! -e /var/lib/simple-tun-link/ipsec ]] || fail partial_attempt_created_private_service
  [[ $(sha256sum /usr/local/bin/stl | awk '{print $1}') == "$original" ]] ||
    fail partial_attempt_replaced_stl_binary
  [[ $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}') == "$record" ]] ||
    fail partial_attempt_mutated_stl_record
  if bash /mnt/stl-install.sh prepare --backends native,ipsec \
      --expected-missing "$missing" --expected-apt-plan "$apt_plan"; then
    fail blind_retry_of_interrupted_transaction
  fi
  echo 'IPSEC_PARTIAL_APT_AFTER_VENDOR_HOOK_READONLY_CLASSIFIED_AND_RETRY_BLOCKED=PASS'
  exit 0
fi

# Independently observe the actual new vendor daemon while distro package
# hooks run. This reads /proc only: polling systemctl before installation
# could itself create a misleading "not-found" loaded-unit placeholder.
observe_vendor_process() {
  local proc name
  until [[ -e /tmp/stl-vendor-observation-done ]]; do
    for proc in /proc/[0-9]*/comm; do
      [[ -r $proc ]] || continue
      IFS= read -r name < "$proc" || continue
      if [[ $name == charon-systemd ]]; then
        : > /tmp/stl-vendor-start-observed
        return 0
      fi
    done
    sleep .025
  done
}
observe_vendor_process &
observer=$!
# Only the selected exact packages may be installed, with signed metadata.
if ! bash /mnt/stl-install.sh prepare --backends native,ipsec \
    --expected-missing "$missing" --expected-apt-plan "$apt_plan"; then
  : > /tmp/stl-vendor-observation-done
  wait "$observer"
  fail real_strongswan_apt_preparation_failed
fi
: > /tmp/stl-vendor-observation-done
wait "$observer"
[[ -f /tmp/stl-vendor-start-observed ]] ||
  fail vendor_start_hook_not_exercised
echo "IPSEC_DISTRO_VENDOR_TEMPORARY_START_OBSERVED=PASS"

dpkg-query -W -f='${Status}' charon-systemd | grep -qx 'install ok installed' ||
  fail charon_not_installed
[[ $(sha256sum /usr/local/bin/stl | awk '{print $1}') == "$original" ]] ||
  fail stl_binary_changed
[[ $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}') == "$record" ]] ||
  fail stl_install_receipt_changed
[[ ! -e /var/lib/simple-tun-link/ipsec ]] || fail installer_provisioned_private_service
[[ $(systemctl is-active strongswan.service 2>/dev/null || :) == inactive ]] ||
  fail vendor_not_inactive
[[ $(systemctl is-enabled strongswan.service 2>/dev/null || :) == disabled ]] ||
  fail vendor_not_disabled
echo "IPSEC_REAL_SIGNED_APT_AND_VENDOR_NORMALIZATION=PASS"

# The approved PREPARE UI now continues to the EXISTING exact source-bound
# provisioner. The unit/runtime admission is separately tested on this guest.
# The native service test requires no default host route; removing it alters
# ONLY this disposable container, after APT network access has completed.
ip -4 route del default 2>/dev/null || :
[[ -z $(ip -4 route show default) ]] || fail unexpected_guest_default_route
# This must run the installed STL executable under a genuine PTY. A Go
# test executable is a DIFFERENT inode and correctly fails the installation
# identity gate; bypassing that gate in production would be unsafe.
/usr/bin/expect /mnt/managed-menu.exp
[[ $(systemctl is-active simple-tun-link-ipsec.service) == active ]] ||
  fail stl_private_ipsec_not_active
/usr/local/bin/stl doctor ipsec --json | grep -q '"activation_allowed":true' ||
  fail private_service_not_admitted
[[ $(systemctl is-enabled strongswan.service 2>/dev/null || :) == disabled &&
   $(systemctl is-active strongswan.service 2>/dev/null || :) == inactive ]] ||
  fail vendor_reactivated_during_private_admission
echo "IPSEC_REAL_FIRST_INSTALL_AND_PRIVATE_ADMISSION=PASS"
