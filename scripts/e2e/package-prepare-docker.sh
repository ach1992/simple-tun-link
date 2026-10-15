#!/usr/bin/env bash
# Real APT package-only preparation acceptance. ALL package manager mutations
# run as root ONLY in a fresh disposable Ubuntu Docker container. Nothing is
# installed, upgraded or provisioned on the GitHub Actions host.
set -Eeuo pipefail
umask 077

fail() { echo "REAL_PACKAGE_PREPARE_FAILED=$1" >&2; exit 1; }
[[ ${STL_E2E_DISPOSABLE_HOST:-} == approved ]] || fail missing_disposable_runner_optin
[[ $EUID -ne 0 && ! -e /.dockerenv ]] || fail host_must_be_unprivileged_vm
[[ $(uname -m) == x86_64 ]] || fail native_amd64_guest_required
for tool in docker git sha256sum go; do command -v "$tool" >/dev/null || fail missing_host_tool; done
[[ -z $(git status --porcelain) ]] || fail dirty_source
source_sha=$(git rev-parse HEAD)
root=$(mktemp -d /tmp/stl-package-e2e.XXXXXXXX)
trap 'rm -rf -- "$root"' EXIT
bash scripts/build-artifacts.sh --snapshot "$root/bundle" >/dev/null
grep -qx "commit=$source_sha" "$root/bundle/BUILD-MANIFEST.txt" || fail wrong_bundle_source
(
 cd "$root/bundle"
 sha256sum -c SHA256SUMS >/dev/null
) || fail bundle_checksum_mismatch

# The bundle and exact canonical installer are only mounted read-only.
# No Docker socket, extra caps, host PID/namespace, or host package dirs are
# made available to this package installation fixture.
docker run --rm --network bridge \
  -e STL_E2E_DISPOSABLE_GUEST=approved \
  -v "$root/bundle:/mnt/stl-bundle:ro" \
  -v "$PWD/scripts/install.sh:/mnt/stl-install.sh:ro" \
  ubuntu:24.04 /bin/bash -c '
set -Eeuo pipefail
fail() { echo "REAL_PACKAGE_PREPARE_GUEST_FAILED=$1" >&2; exit 1; }
[[ $EUID == 0 && -f /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]] || fail not_disposable_guest
test ! -e /usr/local/bin/stl || fail untrusted_existing_stl
bash /mnt/stl-install.sh install --bundle /mnt/stl-bundle --backends native
test -x /usr/local/bin/stl && test -L /usr/local/bin/stlink || fail canonical_install_failed
before_bin=$(sha256sum /usr/local/bin/stl | awk "{print \$1}")
before_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | awk "{print \$1}")
snapshot=$(bash /mnt/stl-install.sh requirements --backends native,wireguard)
grep -Fxq "missing_packages=wireguard-tools" <<< "$snapshot" || fail unexpected_live_dpkg_plan
bash /mnt/stl-install.sh prepare --backends native,wireguard --expected-missing wireguard-tools
dpkg-query -W -f="\${Status}" wireguard-tools | grep -qx "install ok installed" || fail wireguard_tools_not_installed
after_bin=$(sha256sum /usr/local/bin/stl | awk "{print \$1}")
after_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | awk "{print \$1}")
[[ $before_bin == "$after_bin" && $before_record == "$after_record" ]] || fail package_prepare_changed_installed_binary
test ! -e /var/lib/simple-tun-link || fail package_prepare_created_link_state
if bash /mnt/stl-install.sh prepare --backends native,wireguard --expected-missing wireguard-tools; then
  fail accepted_stale_missing_package_snapshot
fi
bash /mnt/stl-install.sh prepare --backends native,wireguard --expected-missing ""
echo "REAL_APT_SELECTED_MISSING_ONLY=PASS"
echo "REAL_APT_INSTALLED_BINARY_AND_RECORD_PRESERVED=PASS"
echo "REAL_APT_STALE_CONSENT_REJECTED=PASS"
echo "REAL_APT_IDEMPOTENT_NO_OP=PASS"
# An IPsec package set is not automatically installed: effective foreign
# systemd unit/drop-in/generator semantics cannot be proven safe pre-APT.
# Replace the guest-local apt-get AFTER the successful WireGuard
# acceptance. Because the canonical installer sanitizes PATH, a PATH shim
# would not intercept anything and would produce a false no-APT proof.
apt_bin=$(command -v apt-get)
[[ $apt_bin == /usr/bin/apt-get ]] || fail unexpected_guest_apt_path
mv -- "$apt_bin" /tmp/stl-package-guest-apt-original
cat > "$apt_bin" <<MOCK
#!/bin/bash
touch /tmp/stl-package-foreign-apt-called
exit 93
MOCK
chmod 0755 "$apt_bin"
mkdir -p /etc/systemd/system/charon-systemd.service.d
printf "[Service]\\nExecStartPre=/usr/bin/touch /tmp/stl-package-foreign-service-marker\\n" > /etc/systemd/system/charon-systemd.service.d/foreign.conf
plan_ipsec=$(bash /mnt/stl-install.sh requirements --backends native,ipsec)
missing_ipsec=$(sed -n "s/^missing_packages=//p" <<< "$plan_ipsec")
[[ $missing_ipsec == *charon-systemd* ]] || fail expected_missing_ipsec_fixture
if bash /mnt/stl-install.sh prepare --backends native,ipsec --expected-missing "$missing_ipsec"; then
  fail ipsec_missing_packages_were_auto_installed
fi
[[ ! -e /tmp/stl-package-foreign-apt-called && ! -e /tmp/stl-package-foreign-service-marker ]] || fail foreign_service_or_apt_executed
after_ipsec=$(bash /mnt/stl-install.sh requirements --backends native,ipsec)
[[ "$after_ipsec" == "$plan_ipsec" ]] || fail ipsec_refusal_modified_dpkg_inventory
[[ $(sha256sum /usr/local/bin/stl | awk "{print \$1}") == "$after_bin" ]] || fail ipsec_refusal_changed_stl
echo "IPSEC_MISSING_PACKAGE_APT_REFUSED_BEFORE_EFFECT=PASS"
echo "IPSEC_FOREIGN_DROPIN_AND_APT_MARKERS_ABSENT=PASS"
'
echo "REAL_APT_PACKAGE_PREPARATION_GUEST=PASS source=$source_sha"
