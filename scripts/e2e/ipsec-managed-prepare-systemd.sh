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
plan=$(bash /mnt/stl-install.sh requirements --backends native,ipsec)
missing=$(sed -n 's/^missing_packages=//p' <<< "$plan")
apt_plan=$(sed -n 's/^apt_install=//p' <<< "$plan")
[[ $missing == *charon-systemd* && $apt_plan == *charon-systemd=* ]] ||
  fail no_real_strongswan_dependency_plan

case "${STL_IPSEC_PREPARE_CASE:-}" in
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
  clean) ;;
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

# Only the selected exact packages may be installed, with signed metadata.
bash /mnt/stl-install.sh prepare --backends native,ipsec \
    --expected-missing "$missing" --expected-apt-plan "$apt_plan"

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
