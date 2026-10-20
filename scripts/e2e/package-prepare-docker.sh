#!/usr/bin/env bash
# Real APT package-only preparation acceptance. ALL package manager mutations
# run as root ONLY in a fresh disposable Debian/Ubuntu Docker guest. Nothing is
# installed, upgraded or provisioned on the GitHub Actions host.
set -Eeuo pipefail
umask 077

fail() { echo "REAL_PACKAGE_PREPARE_FAILED=$1" >&2; exit 1; }
[[ ${STL_E2E_DISPOSABLE_HOST:-} == approved ]] || fail missing_disposable_runner_optin
[[ $EUID -ne 0 && ! -e /.dockerenv ]] || fail host_must_be_unprivileged_vm
case $(uname -m) in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) fail unsupported_native_arch ;;
esac
image=${STL_E2E_BASE_IMAGE:-ubuntu:24.04}
case $image in
  ubuntu:24.04|debian:bookworm) ;;
  *) fail unsupported_disposable_guest_image ;;
esac
for tool in docker git sha256sum go; do command -v "$tool" >/dev/null || fail missing_host_tool; done
[[ -z $(git status --porcelain) ]] || fail dirty_source
source_sha=$(git rev-parse HEAD)
short_sha=${source_sha:0:12}
root=$(mktemp -d /tmp/stl-package-e2e.XXXXXXXX)
trap 'rm -rf -- "$root"' EXIT
bash scripts/build-artifacts.sh --snapshot "$root/bundle" >/dev/null
grep -qx "commit=$source_sha" "$root/bundle/BUILD-MANIFEST.txt" || fail wrong_bundle_source
(
 cd "$root/bundle"
 sha256sum -c SHA256SUMS >/dev/null
) || fail bundle_checksum_mismatch
archive="$root/bundle/stl_dev-${short_sha}_linux_${arch}_local-install.tar.gz"
[[ -f $archive ]] || fail missing_local_install_archive

# The exact one-architecture release archive and canonical source are mounted
# read-only. Block GitHub names inside the disposable guest, while signed
# distro APT remains usable. No Docker socket, extra caps, host PID/namespace,
# or host package directories are mounted.
docker run --rm --network bridge \
  --add-host github.com:127.0.0.1 \
  --add-host api.github.com:127.0.0.1 \
  --add-host objects.githubusercontent.com:127.0.0.1 \
  --add-host github-releases.githubusercontent.com:127.0.0.1 \
  -e STL_E2E_DISPOSABLE_GUEST=approved \
  -e STL_E2E_BUNDLE_VERSION="dev-${short_sha}" \
  -e STL_E2E_BUNDLE_ARCH="$arch" \
  -v "$archive:/mnt/stl-local-install.tar.gz:ro" \
  -v "$PWD/scripts/install.sh:/mnt/stl-install.sh:ro" \
  "$image" /bin/bash -c '
set -Eeuo pipefail
fail() { echo "REAL_PACKAGE_PREPARE_GUEST_FAILED=$1" >&2; exit 1; }
[[ $EUID == 0 && -f /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]] || fail not_disposable_guest
test ! -e /usr/local/bin/stl || fail untrusted_existing_stl
# A read-only CI bind mount can have an unprivileged host UID. Verify the
# expected members before extracting into a private root-owned directory;
# never weaken the real-prefix source ownership gate.
install -d -m 0700 /root/stl-e2e-bundle
members=$(tar -tzf /mnt/stl-local-install.tar.gz) || fail archive_listing_failed
expected=$(printf "%s\n" "stl_${STL_E2E_BUNDLE_VERSION}_linux_${STL_E2E_BUNDLE_ARCH}" \
  install.sh LICENSE BUILD-MANIFEST.txt LOCAL-INSTALL.txt SHA256SUMS)
[[ $members == "$expected" ]] || fail unsafe_archive_members
tar --extract --gzip --file /mnt/stl-local-install.tar.gz \
  --directory /root/stl-e2e-bundle --no-same-owner --no-same-permissions || fail archive_extract_failed
(cd /root/stl-e2e-bundle && sha256sum --check SHA256SUMS >/dev/null) || fail archive_checksum_failed
cmp -s /mnt/stl-install.sh /root/stl-e2e-bundle/install.sh || fail noncanonical_archived_installer
bash /root/stl-e2e-bundle/install.sh install --bundle /root/stl-e2e-bundle --backends native
test -x /usr/local/bin/stl && test -L /usr/local/bin/stlink || fail canonical_install_failed
before_bin=$(sha256sum /usr/local/bin/stl | awk "{print \$1}")
before_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | awk "{print \$1}")
snapshot=$(bash /mnt/stl-install.sh requirements --backends native,wireguard)
grep -Fxq "missing_packages=wireguard-tools" <<< "$snapshot" || fail unexpected_live_dpkg_plan
# A controlled mirror-outage fixture proves the real installer reports the
# missing package and failed stage without attempting an unsigned fallback.
# Restore the original APT binary before testing signed-repository recovery.
mirror_apt=$(command -v apt-get)
[[ $mirror_apt == /usr/bin/apt-get ]] || fail unexpected_guest_apt_path
mv -- "$mirror_apt" /tmp/stl-package-guest-apt-mirror-original
cat > "$mirror_apt" <<MOCK
#!/bin/bash
# Let the verified read-only dependency preview run against the real signed
# package indexes. Only the later index-refresh simulates mirror failure.
for argument in "\$@"; do
  if [[ \$argument == update ]]; then
    printf "E: Failed to fetch configured mirror metadata\\n" >&2
    exit 100
  fi
done
exec /tmp/stl-package-guest-apt-mirror-original "\$@"
MOCK
chmod 0755 "$mirror_apt"
if bash /mnt/stl-install.sh prepare --backends native,wireguard \
     --expected-missing wireguard-tools > /tmp/stl-apt-mirror-error.log 2>&1; then
  fail missing_package_accepted_unreachable_mirror
fi
if ! grep -q "APT_INDEX_REFRESH failed; missing selected packages: wireguard-tools" \
     /tmp/stl-apt-mirror-error.log; then
  sed -n "1,60p" /tmp/stl-apt-mirror-error.log >&2
  fail missing_mirror_failure_stage
fi
if ! grep -q "manually select an accessible official signed Debian/Ubuntu mirror" \
     /tmp/stl-apt-mirror-error.log; then
  sed -n "1,60p" /tmp/stl-apt-mirror-error.log >&2
  fail missing_signed_mirror_operator_guidance
fi
mv -- /tmp/stl-package-guest-apt-mirror-original "$mirror_apt"
echo "APT_MIRROR_OUTAGE_GUIDED_RECOVERY_FIXTURE=PASS"
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
# This guest intentionally lacks PID1 systemd. Even with valid exact-plan
# approval, the managed IPsec path must refuse BEFORE touching apt or
# overwriting a foreign vendor drop-in.
apt_bin=$(command -v apt-get)
[[ $apt_bin == /usr/bin/apt-get ]] || fail unexpected_guest_apt_path
if ! plan_ipsec=$(bash /mnt/stl-install.sh requirements --backends native,ipsec); then
  # Diagnostic is read-only and runs only in the disposable test guest.
  # No private source secrets are present in this stock Ubuntu fixture.
  apt-get indextargets --format "APT_INDEX id=\$(IDENTIFIER) file=\$(FILENAME) component=\$(COMPONENT) arch=\$(ARCHITECTURE)" | head -n 16 >&2 || :
  fail ipsec_readonly_signer_preview_failed
fi
missing_ipsec=$(sed -n "s/^missing_packages=//p" <<< "$plan_ipsec")
apt_ipsec=$(sed -n "s/^apt_install=//p" <<< "$plan_ipsec")
[[ $missing_ipsec == *charon-systemd* && $apt_ipsec == *charon-systemd=* ]] ||
  fail expected_missing_ipsec_fixture
mv -- "$apt_bin" /tmp/stl-package-guest-apt-original
cat > "$apt_bin" <<MOCK
#!/bin/bash
touch /tmp/stl-package-foreign-apt-called
exit 93
MOCK
chmod 0755 "$apt_bin"
# Reinstall the identical transferred archive with all selected prerequisites
# already present. A failing APT sentinel proves no index refresh/install was
# even attempted; identity must remain untouched.
before_inode=$(stat -c %i /usr/local/bin/stl)
before_record_mtime=$(stat -c %Y /usr/local/lib/simple-tun-link/install-record)
bash /root/stl-e2e-bundle/install.sh install --bundle /root/stl-e2e-bundle --backends native,wireguard
[[ ! -e /tmp/stl-package-foreign-apt-called ]] || fail same_release_reinstall_touched_apt
[[ $(stat -c %i /usr/local/bin/stl) == "$before_inode" &&
   $(stat -c %Y /usr/local/lib/simple-tun-link/install-record) == "$before_record_mtime" &&
   $(sha256sum /usr/local/bin/stl | awk "{print \$1}") == "$after_bin" &&
   $(sha256sum /usr/local/lib/simple-tun-link/install-record | awk "{print \$1}") == "$after_record" ]] ||
  fail same_release_reinstall_changed_identity
echo "LOCAL_ARCHIVE_GITHUB_BLOCKED_SIGNED_APT=PASS"
echo "LOCAL_ARCHIVE_SAME_RELEASE_ZERO_APT_AND_IDENTITY_NOOP=PASS"
mkdir -p /etc/systemd/system/charon-systemd.service.d
printf "[Service]\nExecStartPre=/usr/bin/touch /tmp/stl-package-foreign-service-marker\n" > /etc/systemd/system/charon-systemd.service.d/foreign.conf
if bash /mnt/stl-install.sh prepare --backends native,ipsec \
      --expected-missing "$missing_ipsec" --expected-apt-plan "$apt_ipsec"; then
  fail ipsec_non_systemd_or_foreign_effect_was_accepted
fi
[[ ! -e /tmp/stl-package-foreign-apt-called && ! -e /tmp/stl-package-foreign-service-marker ]] ||
  fail foreign_service_or_apt_executed
# The intentional apt-get sentinel remains installed, so a new requirements
# simulation would legitimately fail. Verify dpkg state directly instead.
if dpkg-query -W -f="\${Status}" charon-systemd 2>/dev/null | grep -qx "install ok installed"; then
  fail ipsec_refusal_modified_dpkg_inventory
fi
[[ $(sha256sum /usr/local/bin/stl | awk "{print \$1}") == "$after_bin" ]] || fail ipsec_refusal_changed_stl
echo "IPSEC_NON_SYSTEMD_GUEST_PREPARE_REFUSED_BEFORE_APT=PASS"
echo "IPSEC_FOREIGN_DROPIN_AND_APT_MARKERS_ABSENT=PASS"
'
echo "REAL_APT_PACKAGE_PREPARATION_GUEST=PASS source=$source_sha arch=$arch guest=$image"
