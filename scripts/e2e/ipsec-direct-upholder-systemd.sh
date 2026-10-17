#!/usr/bin/env bash
# An active direct [Unit] Upholds= dependency, NOT a .upholds symlink.
# Strictly limited to a fresh disposable PID1-systemd Docker guest in CI.
set -Eeuo pipefail
fail() { echo "DIRECT_UPHOLDS_FIXTURE_FAILED=$1" >&2; exit 2; }
[[ ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]] || fail unapproved_guest
case ${STL_IPSEC_PREPARE_CASE:-} in
  existing_vendor_direct_upholds|existing_vendor_late_direct_upholds) ;;
  *) fail unapproved_scenario ;;
esac
[[ $EUID == 0 && -f /.dockerenv &&
   $(cat /proc/1/comm) == systemd ]] || fail not_disposable_systemd_guest

upholder=/etc/systemd/system/stl-disposable-direct-upholder.service
[[ ! -e $upholder && ! -L $upholder ]] || fail preexisting_upholder
/usr/bin/systemctl --system is-active --quiet strongswan.service ||
  fail vendor_not_active_before_fixture
/usr/bin/systemctl --system is-enabled --quiet strongswan.service ||
  fail vendor_not_enabled_before_fixture

# The dependency lives only in this separately loaded unit's [Unit] section.
# No .upholds symlink is created by this driver or systemctl start.
cat > "$upholder" <<'UNIT'
[Unit]
Description=Disposable externally owned StrongSwan direct upholder
Upholds=strongswan.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
UNIT
/usr/bin/systemctl --system daemon-reload || fail manager_reload
/usr/bin/systemctl --system start stl-disposable-direct-upholder.service ||
  fail upholder_start
[[ $(/usr/bin/systemctl --system is-active stl-disposable-direct-upholder.service) == active ]] ||
  fail upholder_not_active
[[ $(/usr/bin/systemctl --system --no-pager --all show strongswan.service -p UpheldBy) == UpheldBy=stl-disposable-direct-upholder.service ]] ||
  fail direct_reverse_dependency_not_visible

for base in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
  for edge in "$base"/*.upholds; do
    [[ ! -e "$edge/strongswan.service" && ! -L "$edge/strongswan.service" ]] ||
      fail unexpected_upholds_filesystem_edge
  done
done
echo 'IPSEC_DIRECT_EFFECTIVE_UPHELDBY_WITHOUT_SYMLINK=PASS'
