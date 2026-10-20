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
archive_name=$(basename -- "$archive")
archive_digest=$(awk -v name="$archive_name" '$2 == name {print $1}' "$root/bundle/SHA256SUMS")
[[ $archive_digest =~ ^[0-9a-f]{64}$ ]] || fail missing_outer_archive_checksum

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
  -e STL_E2E_ARCHIVE_SHA256="$archive_digest" \
  -v "$archive:/mnt/stl-local-install.tar.gz:ro" \
  -v "$PWD/scripts/install.sh:/mnt/stl-install.sh:ro" \
  "$image" /bin/bash -c '
set -Eeuo pipefail
fail() { echo "REAL_PACKAGE_PREPARE_GUEST_FAILED=$1" >&2; exit 1; }
[[ $EUID == 0 && -f /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]] || fail not_disposable_guest
test ! -e /usr/local/bin/stl || fail untrusted_existing_stl
# Copy an externally checksummed read-only fixture into a fresh private
# root-owned transfer folder; execute the same canonical streamed unpack
# action documented for operators, before any installation or APT action.
install -d -m 0700 /root/stl-e2e-transfer
source_archive="/root/stl-e2e-transfer/stl_${STL_E2E_BUNDLE_VERSION}_linux_${STL_E2E_BUNDLE_ARCH}_local-install.tar.gz"
cp -- /mnt/stl-local-install.tar.gz "$source_archive"
# Root ownership alone must never admit an archive writable by other users.
chmod 0666 -- "$source_archive"
if bash /mnt/stl-install.sh unpack --archive "$source_archive" \
    --destination /root/stl-e2e-unsafe --sha256 "$STL_E2E_ARCHIVE_SHA256" \
    > /tmp/stl-e2e-archive-permission.log 2>&1; then
  fail root_owned_world_writable_archive_was_accepted
fi
grep -q "local source archive is writable by group or others" \
  /tmp/stl-e2e-archive-permission.log || fail archive_mode_wrong_refusal
[[ ! -e /root/stl-e2e-unsafe ]] || fail writable_source_created_destination
chmod 0600 -- "$source_archive"
echo "ROOT_OWNED_WORLD_WRITABLE_ARCHIVE_REFUSED=PASS"

# Follow the documented operator boundary: a newly root-private *copy*
# becomes the independently hashed source of the streamed canonical script.
# An actor holding an old descriptor to the transferred file cannot mutate it.
install -d -m 0700 /root/stl-e2e-verified
verified_archive="/root/stl-e2e-verified/$(basename -- "$source_archive")"
install -m 0600 -- "$source_archive" "$verified_archive"
[[ $(sha256sum "$verified_archive" | awk "{print \$1}") == "$STL_E2E_ARCHIVE_SHA256" ]] ||
  fail transferred_archive_digest_mismatch
# Fully receive the authenticated installer into the same private directory
# before execution; do not pipeline a large script to an early-exiting bash.
bootstrap="/root/stl-e2e-verified/bootstrap-install.sh"
tar -xOzf "$verified_archive" install.sh > "$bootstrap" ||
  fail incomplete_archive_installer
chmod 0600 "$bootstrap"
bash -n "$bootstrap" || fail malformed_archived_installer
cmp -s /mnt/stl-install.sh "$bootstrap" || fail noncanonical_preexecution_installer
bash "$bootstrap" unpack --archive "$verified_archive" \
  --destination /root/stl-e2e-bundle --sha256 "$STL_E2E_ARCHIVE_SHA256"
[[ -z $(find /root -maxdepth 1 -name ".stl-unpack.*" -print -quit) ]] ||
  fail authenticated_unpacked_snapshot_retained
cmp -s /mnt/stl-install.sh /root/stl-e2e-bundle/install.sh || fail noncanonical_archived_installer
bash /root/stl-e2e-bundle/install.sh install --bundle /root/stl-e2e-bundle --backends native
test -x /usr/local/bin/stl && test -L /usr/local/bin/stlink || fail canonical_install_failed
before_bin=$(sha256sum /usr/local/bin/stl | awk "{print \$1}")
before_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | awk "{print \$1}")
snapshot=$(bash /mnt/stl-install.sh requirements --backends native,wireguard)
grep -Fxq "missing_packages=wireguard-tools" <<< "$snapshot" || fail unexpected_live_dpkg_plan

# APT source bypasses must be rejected for native/WireGuard, before ANY
# package-manager operation. These temporary source entries and mocks live
# only inside this disposable Docker guest.
apt_bin=$(command -v apt-get)
[[ $apt_bin == /usr/bin/apt-get ]] || fail unexpected_guest_apt_path
mv -- "$apt_bin" /tmp/stl-e2e-source-apt-original
printf "#!/bin/bash\\ntouch /tmp/stl-e2e-source-apt-called\\nexit 97\\n" > "$apt_bin"
chmod 0755 "$apt_bin"
printf "deb [trusted=yes] http://127.0.0.1/ nonexisting main\\n" > /etc/apt/sources.list.d/stl-e2e-untrusted.list
if bash /mnt/stl-install.sh prepare --backends native,wireguard \
    --expected-missing wireguard-tools > /tmp/stl-e2e-source-error 2>&1; then
  fail trusted_one_line_source_was_accepted
fi
grep -q "APT sources explicitly bypass signature verification" /tmp/stl-e2e-source-error ||
  fail trusted_one_line_source_wrong_refusal
rm /etc/apt/sources.list.d/stl-e2e-untrusted.list
printf "Types: deb\\nURIs: http://127.0.0.1/\\nSuites: nonexisting\\nComponents: main\\nTrusted: yes\\n" > /etc/apt/sources.list.d/stl-e2e-untrusted.sources
if bash /mnt/stl-install.sh prepare --backends native,wireguard \
    --expected-missing wireguard-tools > /tmp/stl-e2e-source-error 2>&1; then
  fail trusted_deb822_source_was_accepted
fi
grep -q "APT sources explicitly bypass signature verification" /tmp/stl-e2e-source-error ||
  fail trusted_deb822_source_wrong_refusal
rm /etc/apt/sources.list.d/stl-e2e-untrusted.sources
[[ ! -e /tmp/stl-e2e-source-apt-called ]] || fail untrusted_source_reached_apt

# Legitimate disabled source entries are harmless: classic comments and
# Deb822 Enabled: no must not prevent *real* signed selected APT recovery.
printf "# deb [trusted=yes] http://127.0.0.1/ nonexisting main\\n" \
  > /etc/apt/sources.list.d/stl-e2e-inactive.list
printf "Types: deb\\nURIs: http://127.0.0.1/\\nSuites: nonexisting\\nComponents: main\\nTrusted: yes\\nEnabled: no\\n" \
  > /etc/apt/sources.list.d/stl-e2e-inactive.sources
if bash /mnt/stl-install.sh prepare --backends native,wireguard \
    --expected-missing wireguard-tools > /tmp/stl-e2e-source-error 2>&1; then
  fail incomplete_fake_apt_precondition_unexpected_success
fi
[[ -e /tmp/stl-e2e-source-apt-called ]] ||
  { cat /tmp/stl-e2e-source-error >&2; fail inactive_sources_wrongly_blocked_before_apt; }
grep -q "APT_DEPENDENCY_PLAN failed" /tmp/stl-e2e-source-error ||
  fail inactive_sources_failed_before_package_planning
rm /tmp/stl-e2e-source-apt-called
mv -- /tmp/stl-e2e-source-apt-original "$apt_bin"
echo "APT_NATIVE_WG_TRUSTED_SOURCE_BYPASS_REFUSED=PASS"
echo "APT_INACTIVE_TRUST_ENTRIES_PERMIT_PACKAGE_PLAN=PASS"

# An otherwise valid native/WG dependency preview must not acquire trust
# from a foreign candidate source merely claiming to be a normal APT index.
apt_cache=$(command -v apt-cache)
[[ $apt_cache == /usr/bin/apt-cache ]] || fail unexpected_guest_apt_cache_path
candidate_version=$(apt-cache policy wireguard-tools | sed -n "s/^  Candidate: //p")
[[ -n $candidate_version && $candidate_version != "(none)" ]] || fail missing_candidate_version
mv -- "$apt_cache" /tmp/stl-e2e-source-apt-cache-original
cat > "$apt_cache" <<MOCK
#!/bin/bash
printf "  Candidate: %s\\n     %s 500\\n        500 http://thirdparty.invalid fake/main amd64 Packages\\n" "$candidate_version" "$candidate_version"
MOCK
chmod 0755 "$apt_cache"
if bash /mnt/stl-install.sh prepare --backends native,wireguard \
    --expected-missing wireguard-tools > /tmp/stl-e2e-source-error 2>&1; then
  fail foreign_candidate_source_was_accepted
fi
grep -q "APT candidate includes a non-distribution package source" /tmp/stl-e2e-source-error ||
  fail foreign_candidate_wrong_refusal
mv -- /tmp/stl-e2e-source-apt-cache-original "$apt_cache"
echo "APT_NATIVE_WG_FOREIGN_CANDIDATE_SOURCE_REFUSED=PASS"

# Preserve the real configured signed APT indexes for its dependency
# simulation. Substitute only the cryptographic signer result in this
# disposable guest to prove STL refuses a candidate whose InRelease cannot
# verify against the installed official archive keyring.
signer_bin=$(command -v gpgv)
[[ $signer_bin == /usr/bin/gpgv ]] || fail unexpected_guest_gpgv_path
mv -- "$signer_bin" /tmp/stl-e2e-gpgv-original
cat > "$signer_bin" <<MOCK
#!/bin/bash
# Only the STL direct official-release verification call is denied; preserve
# unrelated APT verifier behavior in the disposable package-plan fixture.
if [[ \$1 == --quiet && \$2 == --keyring ]]; then
  touch /tmp/stl-e2e-gpgv-denied
  exit 92
fi
exec /tmp/stl-e2e-gpgv-original "\$@"
MOCK
chmod 0755 "$signer_bin"
if bash /mnt/stl-install.sh prepare --backends native,wireguard \
    --expected-missing wireguard-tools > /tmp/stl-e2e-source-error 2>&1; then
  fail unsigned_candidate_index_was_accepted
fi
[[ -e /tmp/stl-e2e-gpgv-denied ]] || fail candidate_signer_was_not_invoked
grep -q "APT candidate InRelease is not signed by the distribution archive" /tmp/stl-e2e-source-error ||
  { sed -n "1,30p" /tmp/stl-e2e-source-error >&2; fail unsigned_candidate_wrong_refusal; }
mv -- /tmp/stl-e2e-gpgv-original "$signer_bin"
echo "APT_NATIVE_WG_UNSIGNED_CANDIDATE_REFUSED=PASS"

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
