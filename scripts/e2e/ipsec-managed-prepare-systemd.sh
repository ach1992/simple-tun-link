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
# Release bundle input remains read-only mounted from the runner. The guest
# must use a root-owned 0700 source; a user-owned host bind mount must not be
# silently promoted into a trusted root installer input.
install -d -m 0700 /root/stl-e2e-bundle
cp -a /mnt/stl-bundle/. /root/stl-e2e-bundle/
chown -R 0:0 /root/stl-e2e-bundle
bash /mnt/stl-install.sh install --bundle /root/stl-e2e-bundle --backends native
[[ -x /usr/local/bin/stl ]] || fail no_verified_installed_binary
original=$(sha256sum /usr/local/bin/stl | awk '{print $1}')
record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}')
# Exercise a REAL pre-existing, distro-owned StrongSwan service in an
# isolated guest. Unlike the clean-host package case, this service belongs
# to the operator before PREPARE. Only a fresh, separately typed exact-unit
# STOP consent can change it; the menu must then provision STL separately.
if [[ ${STL_IPSEC_PREPARE_CASE:-} == existing_vendor* ]]; then
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
  if [[ ${STL_IPSEC_EXPECT_SYSTEMD_MAJOR:-} == 249 ]]; then
    # Prove a real v249 PID1 and missing UpheldBy property, not a mocked
    # version string or a distribution branding claim.
    [[ $(systemctl --version | head -n 1) == 'systemd 249'* &&
       $(systemctl --system --no-pager show -p Version) == Version=249* ]] ||
      fail actual_systemd_249_pid1_not_verified
    [[ -z $(systemctl --system --no-pager --all show strongswan.service -p UpheldBy) ]] ||
      fail v249_upheldby_property_unexpectedly_available
    echo 'IPSEC_PID1_V249_UPHOLDS_WITHOUT_DBUS_UPHELDBY=PASS'
  fi
  plan=$(bash /mnt/stl-install.sh requirements --backends native,ipsec) ||
    fail existing_vendor_package_inventory_unknown
  grep -qx "missing_packages=" <<< "$plan" ||
    fail existing_vendor_has_incomplete_package_install
  [[ ! -e /var/lib/simple-tun-link/ipsec ]] ||
    fail private_service_exists_before_consent
  if [[ "${STL_IPSEC_PREPARE_CASE}" == existing_vendor ]]; then
    # Status-only diagnostic in a disposable guest, no package secrets.
    optional_rc=0
    optional_state=$(LC_ALL=C dpkg-query -W '-f=${Status}' -- libcharon-extauth-plugins 2>&1) ||
      optional_rc=$?
    printf 'IPSEC_DISPOSABLE_OPTIONAL_DPKG_STATUS rc=%d value=%q\n' "$optional_rc" "$optional_state"
  fi
  case "${STL_IPSEC_PREPARE_CASE}" in
    existing_vendor) ;;
    existing_vendor_optional_clean)
      # An entirely official optional plugin package must remain eligible
      # for the SAME separate vendor STOP after full archive attestation.
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libcharon-extauth-plugins >/tmp/stl-existing-optional-apt.log 2>&1 ||
        fail cannot_install_clean_optional_vendor_fixture
      [[ $(dpkg-query -W '-f=${Status}' libcharon-extauth-plugins) == 'install ok installed' ]] ||
        fail official_optional_vendor_not_fully_configured
      ;;
    existing_vendor_foreign_config)
      mkdir -p /etc/swanctl/conf.d
      printf 'foreign connection; must not be adopted\n' >/etc/swanctl/conf.d/foreign.conf
      ;;
    existing_vendor_direct_upholds)
      # Exercise a separate ACTIVE unit's direct [Unit] Upholds=.
      # No *.upholds filesystem link exists for this case.
      /usr/bin/bash /mnt/stl-direct-upholder.sh ||
        fail cannot_construct_direct_upheldby_fixture
      ;;
    existing_vendor_late_direct_upholds)
      # The same dependency is introduced by the Expect operator driver
      # AFTER preview but BEFORE typed STOP, proving locked reinspection.
      ;;
    existing_vendor_upholds)
      # An UpheldBy edge can restart a consented-to-STOP distro service.
      # The foreign dependency is not owned by STL.
      edge=/etc/systemd/system/stl-disposable.target.upholds
      mkdir -p "$edge"
      ln -s /usr/lib/systemd/system/strongswan.service "$edge/strongswan.service"
      systemctl --system daemon-reload || fail cannot_reload_upheld_vendor_fixture
      ;;
    existing_vendor_foreign_alias)
      mkdir -p /run/systemd/system.attached/strongswan-swanctl.service.d
      printf '[Service]\nExecStartPre=/usr/bin/false\n' \
        >/run/systemd/system.attached/strongswan-swanctl.service.d/foreign.conf
      ;;
    existing_vendor_private_conflict)
      # Existing partial STL-private inventory must not be adopted.
      mkdir -p /var/lib/simple-tun-link
      mkdir -m 0700 /var/lib/simple-tun-link/ipsec
      ;;
    existing_vendor_untrusted_config_owner)
      # A default package-owned config with unchanged bytes must still
      # reject STOP when its inode becomes writable by another UID.
      chown 65534:65534 /etc/strongswan.d/charon/pgp.conf
      ;;
    existing_vendor_foreign_process)
      /mnt/stl-foreign-process-marker &
      foreign_pid=$!
      for _ in 1 2 3 4 5; do
        [[ $(cat /proc/$foreign_pid/comm) == charon ]] && break
        sleep .1
      done
      [[ $(cat /proc/$foreign_pid/comm) == charon ]] ||
        fail foreign_daemon_fixture_not_running
      ;;
    existing_vendor_optional_modified)
      # Optional official plug-in configuration must be attested just as
      # strictly as required package configs before any real vendor STOP.
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libcharon-extauth-plugins >/tmp/stl-existing-optional-apt.log 2>&1 ||
        fail cannot_install_optional_vendor_fixture
      conf=/etc/strongswan.d/charon/eap-mschapv2.conf
      [[ -f $conf ]] || fail optional_distro_conf_not_present
      printf '\n# Disposable modified optional plugin configuration\n' >> "$conf"
      ;;
    existing_vendor_optional_partial)
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libcharon-extauth-plugins >/tmp/stl-existing-optional-apt.log 2>&1 ||
        fail cannot_install_optional_vendor_fixture
      (cd /tmp && apt-get download libcharon-extauth-plugins >/dev/null 2>&1) ||
        fail cannot_obtain_optional_vendor_fixture
      dpkg --unpack /tmp/libcharon-extauth-plugins_*.deb >/dev/null 2>&1 ||
        fail cannot_construct_partial_optional_package
      [[ -n $(dpkg --audit) ]] || fail optional_package_not_actually_partial
      ;;
    existing_vendor_local_metadata_forgery)
      # Forge a *previously installed* package, not a future APT candidate:
      # keep dpkg's own md5 metadata internally consistent with a changed
      # package-owned runtime plugin. A signed official .deb must still win
      # the byte comparison and forbid stopping the live vendor daemon.
      plugin=$(dpkg -L libstrongswan-standard-plugins |
        awk '/\/plugins\/.*\.so$/ && !found {print; found=1}')
      [[ -f $plugin ]] || fail no_distro_plugin_for_forgery_fixture
      metadata=''
      for candidate in /var/lib/dpkg/info/libstrongswan-standard-plugins*.md5sums; do
        [[ -f $candidate ]] || continue
        if grep -qF "  ${plugin#/}" "$candidate"; then
          metadata=$candidate
          break
        fi
      done
      [[ -n $metadata ]] || fail plugin_metadata_for_forgery_not_found
      printf '\n' >> "$plugin"
      spoofed_digest=$(md5sum "$plugin" | awk '{print $1}')
      # dpkg .md5sums requires TWO spaces between each checksum and
      # relative filename; awk's default print would make an invalid
      # metadata file, accidentally passing a negative E2E for the wrong
      # reason. Generate correct md5sum syntax for EVERY line.
      awk -v wanted="${plugin#/}" -v digest="$spoofed_digest" '
        $2 == wanted { $1 = digest; found = 1 }
        NF == 2 { printf "%s  %s\n", $1, $2; next }
        { exit 3 }
        END { if (!found) exit 2 }
      ' "$metadata" > "$metadata.fixture" ||
        fail cannot_construct_well_formed_dpkg_forgery_fixture
      chmod 0644 "$metadata.fixture"
      mv -f -- "$metadata.fixture" "$metadata"
      LC_ALL=C dpkg --verify libstrongswan-standard-plugins \
        >/tmp/stl-forged-dpkg-verify-stdout \
        2>/tmp/stl-forged-dpkg-verify-stderr ||
        fail forged_dpkg_metadata_failed_its_own_integrity_check
      [[ ! -s /tmp/stl-forged-dpkg-verify-stderr ]] ||
        fail forged_dpkg_metadata_emitted_diagnostics
      # Missing documentation may be normal in lean distro guests; no
      # operational file or configuration mismatch is permissible.
      if grep -Ev '^missing[[:space:]]+/usr/share/(doc|man)/' \
          /tmp/stl-forged-dpkg-verify-stdout |
          grep -q .; then
        fail forged_dpkg_metadata_did_not_mask_local_tampering
      fi
      echo 'IPSEC_INSTALLED_LOCAL_DPKG_METADATA_VALID_BUT_FORGED=PASS'
      ;;
    existing_vendor_plugin_world_writable|existing_vendor_plugin_parent_writable|existing_vendor_plugin_parent_symlink)
      # Preserve official signed runtime bytes and locally consistent dpkg
      # checksums: ONLY unsafe filesystem metadata must prevent vendor STOP.
      plugin=$(dpkg -L libstrongswan-standard-plugins |
        awk '/\/plugins\/.*\.so$/ && !found {print; found=1}')
      [[ -f $plugin && ! -L $plugin ]] || fail missing_regular_plugin_metadata_fixture
      plugin_hash=$(sha256sum "$plugin" | awk '{print $1}')
      case "$STL_IPSEC_PREPARE_CASE" in
        existing_vendor_plugin_world_writable)
          chmod o+w "$plugin"
          [[ -n $(find "$plugin" -maxdepth 0 -perm /002 -print -quit) ]] ||
            fail runtime_plugin_writable_fixture_not_applied
          ;;
        existing_vendor_plugin_parent_writable)
          plugin_parent=$(dirname "$plugin")
          chmod g+w "$plugin_parent"
          [[ -n $(find "$plugin_parent" -maxdepth 0 -perm /020 -print -quit) ]] ||
            fail plugin_parent_writable_fixture_not_applied
          ;;
        existing_vendor_plugin_parent_symlink)
          plugin_parent=$(dirname "$plugin")
          [[ ! -e "${plugin_parent}.stl-fixture" ]] || fail symlink_fixture_conflict
          mv -- "$plugin_parent" "${plugin_parent}.stl-fixture"
          ln -s -- "$(basename "$plugin_parent").stl-fixture" "$plugin_parent"
          [[ -L $plugin_parent ]] || fail plugin_parent_symlink_fixture_not_applied
          ;;
      esac
      [[ $(sha256sum "$plugin" | awk '{print $1}') == "$plugin_hash" ]] ||
        fail plugin_bytes_modified_by_metadata_fixture
      LC_ALL=C dpkg --verify libstrongswan-standard-plugins \
        >/tmp/stl-metadata-mode-dpkg-stdout \
        2>/tmp/stl-metadata-mode-dpkg-stderr ||
        fail metadata_only_fixture_invalidated_dpkg_status
      [[ ! -s /tmp/stl-metadata-mode-dpkg-stderr ]] ||
        fail metadata_only_fixture_emitted_dpkg_diagnostics
      if grep -Ev '^missing[[:space:]]+/usr/share/(doc|man)/' \
          /tmp/stl-metadata-mode-dpkg-stdout | grep -q .; then
        fail metadata_only_fixture_invalidated_local_dpkg_checksums
      fi
      echo "IPSEC_OFFICIAL_RUNTIME_BYTES_UNCHANGED_UNSAFE_METADATA=PASS case=$STL_IPSEC_PREPARE_CASE"
      ;;
    existing_vendor_late_config) ;;
    *) fail unrecognized_existing_vendor_case ;;
  esac
  if [[ "${STL_IPSEC_PREPARE_CASE}" == existing_vendor_direct_upholds ||
        "${STL_IPSEC_PREPARE_CASE}" == existing_vendor_late_direct_upholds ]]; then
    vendor_pid_before=$(systemctl --system --no-pager --value -p MainPID show strongswan.service) ||
      fail cannot_read_original_vendor_pid
    vendor_activation_before=$(systemctl --system --no-pager --value -p ActiveEnterTimestampMonotonic show strongswan.service) ||
      fail cannot_read_original_vendor_activation
    [[ $vendor_pid_before =~ ^[1-9][0-9]*$ &&
       $vendor_activation_before =~ ^[1-9][0-9]*$ ]] ||
      fail vendor_running_identity_not_proven
  fi
  if [[ "${STL_IPSEC_PREPARE_CASE}" == existing_vendor ||
        "${STL_IPSEC_PREPARE_CASE}" == existing_vendor_optional_clean ]]; then
    /usr/bin/expect /mnt/managed-existing.exp || fail operator_vendor_consent_failed
    [[ $(systemctl --system is-active strongswan.service) == inactive &&
       $(systemctl --system is-enabled strongswan.service) == disabled ]] ||
      fail consented_vendor_not_stopped_disabled
    [[ $(systemctl --system is-active simple-tun-link-ipsec.service) == active ]] ||
      fail new_stl_private_service_not_started
    /usr/local/bin/stl doctor ipsec --json | grep -q '"activation_allowed":true' ||
      fail new_stl_private_service_not_admitted
    echo 'IPSEC_REAL_PRIOR_DISTRIBUTION_SERVICE_EXACT_OPERATOR_CONSENT=PASS'
  else
    /usr/bin/expect /mnt/managed-existing-denied.exp || fail forbidden_vendor_stop_not_denied
    if [[ "${STL_IPSEC_PREPARE_CASE}" == existing_vendor_direct_upholds ||
          "${STL_IPSEC_PREPARE_CASE}" == existing_vendor_late_direct_upholds ]]; then
      [[ $(systemctl --system --no-pager --value -p MainPID show strongswan.service) == "$vendor_pid_before" &&
         $(systemctl --system --no-pager --value -p ActiveEnterTimestampMonotonic show strongswan.service) == "$vendor_activation_before" ]] ||
        fail upheld_vendor_restarted_or_was_stopped
      [[ $(systemctl --system is-active stl-disposable-direct-upholder.service) == active ]] ||
        fail direct_upholder_not_preserved
      echo "IPSEC_DIRECT_UPHELDBY_ZERO_STOP_TRANSITIONS=${STL_IPSEC_PREPARE_CASE}:PASS"
    fi
    [[ $(systemctl --system is-active strongswan.service) == active &&
       $(systemctl --system is-enabled strongswan.service) == enabled ]] ||
      fail existing_vendor_was_changed_despite_foreign_conflict
    if [[ "${STL_IPSEC_PREPARE_CASE}" == existing_vendor_private_conflict ]]; then
      # Deliberately pre-existing empty directory must persist without a
      # private-service publication or adoption.
      [[ -d /var/lib/simple-tun-link/ipsec &&
         -z $(find /var/lib/simple-tun-link/ipsec -mindepth 1 -maxdepth 1 -print -quit) ]] ||
        fail private_conflict_was_adopted_or_modified
    else
      [[ ! -e /var/lib/simple-tun-link/ipsec ]] ||
        fail private_service_published_despite_foreign_conflict
    fi
    [[ ! -e /etc/systemd/system/simple-tun-link-ipsec.service ]] ||
      fail private_service_unit_published_despite_foreign_conflict
    echo "IPSEC_PRE_STOP_MIXED_HOST_CONFLICT_REJECTED=${STL_IPSEC_PREPARE_CASE}:PASS"
  fi
  [[ $(sha256sum /usr/local/bin/stl | awk '{print $1}') == "$original" &&
     $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}') == "$record" ]] ||
    fail existing_vendor_workflow_modified_STL_installation
  echo "IPSEC_EXISTING_VENDOR_SCENARIO_COMPLETED=PASS"
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
  foreign_upholds|foreign_upholds_alias)
    # Reject a dormant .upholds dependency before installing packages,
    # including aliases whose filename differs from the selected unit.
    edge=/etc/systemd/system/stl-disposable.target.upholds
    [[ ! -e $edge && ! -L $edge ]] || fail unexpected_upheld_fixture
    mkdir -p "$edge"
    target=charon-systemd.service
    if [[ $STL_IPSEC_PREPARE_CASE == foreign_upholds_alias ]]; then
      target=stl-disposable-charon-alias.service
    fi
    ln -s charon-systemd.service "$edge/$target"
    systemctl --system daemon-reload || fail cannot_reload_upheld_fixture
    if bash /mnt/stl-install.sh prepare --backends native,ipsec \
       --expected-missing "$missing" --expected-apt-plan "$apt_plan" \
       >/tmp/stl-upheld-stdout 2>/tmp/stl-upheld-stderr; then
      fail foreign_upheld_identity_accepted
    fi
    grep -q 'service boot edge' /tmp/stl-upheld-stderr ||
      fail foreign_upheld_identity_rejected_for_unrelated_reason
    [[ ! -e /usr/sbin/charon-systemd && ! -e /var/lib/simple-tun-link/ipsec ]] ||
      fail foreign_upheld_identity_allowed_apt_or_private_publication
    [[ $(sha256sum /usr/local/bin/stl | awk '{print $1}') == "$original" &&
       $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk '{print $1}') == "$record" ]] ||
      fail foreign_upheld_identity_replaced_installed_binary
    echo "IPSEC_FOREIGN_UPHOLDS_DENIED_BEFORE_APT=$STL_IPSEC_PREPARE_CASE:PASS"
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
