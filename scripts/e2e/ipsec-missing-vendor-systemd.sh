#!/usr/bin/env bash
# Exclusive to an isolated disposable PID1-systemd guest in GitHub CI.
# Never run on an operator/Agent host. Files are task-owned fixtures.
set -Eeuo pipefail
[[ ${STL_E2E_DISPOSABLE_GUEST:-} == approved &&
   ${STL_IPSEC_MISSING_VENDOR_NEGATIVE:-} == approved &&
   $EUID == 0 && -f /.dockerenv &&
   $(cat /proc/1/comm) == systemd &&
   -z $(/usr/sbin/ip -4 route show default) ]] || {
  echo 'REFUSED_NON_DISPOSABLE_SYSTEMD_FIXTURE' >&2
  exit 2
}
prefix=/run/systemd/system/charon-.service.d
alias=/run/systemd/system/stl-disposable-charon-alias.service
legacy=/etc/init.d/charon-systemd
[[ ! -e $prefix && ! -L $prefix && ! -e $alias && ! -L $alias &&
   ! -e $legacy && ! -L $legacy ]] || {
  echo 'REFUSED_EXISTING_FIXTURE_IDENTITY' >&2
  exit 2
}
reload() { /usr/bin/systemctl --system --no-pager daemon-reload; }
verify() {
  STL_E2E_DISPOSABLE_HOST=approved STL_IPSEC_ISOLATED=approved \
  STL_IPSEC_SYSTEMD_FIXTURE=approved STL_IPSEC_VENDOR_MISSING_CASE="$1" \
    /usr/local/bin/stl-ipsec-provision-test \
      -test.run '^TestIsolatedNativeMissingVendorFixture$' -test.v
}
cleanup() {
  # Only these exact task-created fixtures, inside an ephemeral guest.
  /usr/bin/rm -f -- "$prefix/foreign.conf" "$alias" "$legacy"
  /usr/bin/rmdir -- "$prefix" 2>/dev/null || :
  reload || :
}
trap cleanup EXIT

verify clean
/usr/bin/mkdir -m 0755 "$prefix"
/usr/bin/printf '[Service]\nEnvironment=STL_DISPOSABLE_VENDOR_PREFIX=1\n' >"$prefix/foreign.conf"
reload
verify prefix
/usr/bin/rm -f -- "$prefix/foreign.conf"
/usr/bin/rmdir -- "$prefix"
reload
verify clean

/usr/bin/ln -s charon-systemd.service "$alias"
reload
verify alias
/usr/bin/rm -f -- "$alias"
reload
verify clean

/usr/bin/printf '%s\n' '#!/bin/sh' '### BEGIN INIT INFO' \
  '# Provides: charon-systemd' '# Required-Start: $remote_fs' \
  '# Required-Stop: $remote_fs' '# Default-Start: 2 3 4 5' \
  '# Default-Stop: 0 1 6' \
  '# Short-Description: disposable systemd generator identity fixture' \
  '### END INIT INFO' 'exit 0' >"$legacy"
/usr/bin/chmod 0755 "$legacy"
reload
verify sysv
/usr/bin/rm -f -- "$legacy"
reload
verify clean
echo 'NATIVE_VENDOR_RELOADED_PREFIX_ALIAS_SYSV_GENERATOR=PASS'
