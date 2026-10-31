#!/usr/bin/env bash
# Literal README one-file/one-command acceptance inside DISPOSABLE guests.
# No host packages, STL installation, Docker socket, privileged caps or host
# networking are ever mounted into the guest. Called by package-prepare E2E.
set -Eeuo pipefail
umask 077

if [[ ${1:-} == guest && -e /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]]; then
  [[ $EUID == 0 ]] || exit 98
  fail() { echo "LOCAL_ONE_COMMAND_GUEST_FAILED=$*" >&2; exit 1; }
  # Read and execute the literal release-facing command from README, not
  # a test-local paraphrase. Root guests have no sudo requirement.
  run_root_operator() {
    local line
    line=$(grep '^bash -c .*stl-preflight' /mnt/stl-readme)
    [[ $(printf '%s\n' "$line" | wc -l) == 1 ]] || fail missing_root_operator_command
    # Accepted literal README invocations only; the option string is fixed,
    # never supplied by an untrusted fixture or derived from archive contents.
    case "$*" in
      ""|--with-wss|--with-quic|"--with-wss --with-quic") ;;
      *) fail unexpected_operator_options ;;
    esac
    eval "$line $*"
  }
  run_sudo_operator() {
    local line
    line=$(grep '^sudo bash -c .*stl-preflight' /mnt/stl-install-doc)
    [[ $(printf '%s\n' "$line" | wc -l) == 1 ]] || fail missing_sudo_operator_command
    su -s /bin/bash stloperator -c "$line"
  }
  install -d -m 0700 /root/stl
  install -m 0600 -- /mnt/stl-entry.sh "/root/stl/$STL_E2E_ENTRY_NAME"
  case $STL_E2E_SCENARIO in
    missing-packages)
      # Missing distro packages are genuinely installed through the configured
      # distro-signed APT flow. All GitHub destinations are unreachable.
      [[ ! -e /usr/local/bin/stl ]] || fail existing_stl
      run_root_operator
      for pkg in iproute2 iptables kmod wireguard-tools; do
        dpkg-query -W -f='${Status}' "$pkg" | grep -qx 'install ok installed' || fail "missing_selected_$pkg"
      done
      ;;
    preinstalled-no-apt)
      apt-get update -o APT::Update::Error-Mode=any >/dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iproute2 iptables kmod wireguard-tools >/dev/null
      # The tested installer must not call APT at all when prerequisites exist.
      cat > /usr/sbin/apt-get <<'APT_STUB'
#!/bin/sh
printf 'APT_WAS_CALLED\n' > /tmp/stl-apt-was-called
exit 88
APT_STUB
      chmod 0755 /usr/sbin/apt-get
      run_root_operator
      [[ ! -e /tmp/stl-apt-was-called ]] || fail unnecessary_apt_on_install
      inode=$(stat -c %i -- /usr/local/bin/stl)
      before_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1)
      run_root_operator
      [[ ! -e /tmp/stl-apt-was-called && $(stat -c %i -- /usr/local/bin/stl) == "$inode" &&
         $(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1) == "$before_record" ]] ||
        fail no_op_changed_files_or_used_apt
      ;;
    sudo-operator)
      # Ubuntu/Debian minimum images do not require sudo for root installs.
      # Separately exercise the actual *real* sudo executable as non-root.
      apt-get update -o APT::Update::Error-Mode=any >/dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        sudo iproute2 iptables kmod wireguard-tools >/dev/null
      command -v sudo >/dev/null || fail missing_genuine_sudo
      command -v useradd >/dev/null || fail missing_guest_useradd
      useradd -m -s /bin/bash stloperator
      install -d -m 0755 /etc/sudoers.d
      printf 'stloperator ALL=(root) NOPASSWD: /usr/bin/bash\n' > /etc/sudoers.d/stl-e2e
      chmod 0440 /etc/sudoers.d/stl-e2e
      # The *genuine* sudo path must also refuse an oversized source before
      # allocating staging or touching an existing STL installation.
      file="/root/stl/$STL_E2E_ENTRY_NAME"
      mv -- "$file" /root/stl-sudo-original
      truncate -s 134250001 -- "$file"
      chmod 0600 -- "$file"
      if run_sudo_operator > /tmp/stl-sudo-oversize-failure 2>&1; then
        fail real_sudo_accepted_oversized_source
      fi
      grep -q 'installer file size must be 1..134250000 bytes' /tmp/stl-sudo-oversize-failure ||
        fail real_sudo_size_refusal_wrong_diagnostic
      [[ ! -e /usr/local/bin/stl ]] || fail real_sudo_oversize_modified_installation
      rm -- "$file"
      mv -- /root/stl-sudo-original "$file"
      run_sudo_operator
      [[ -x /usr/local/bin/stl ]] || fail real_sudo_installer_not_run
      ;;
    wss-invalid)
      # Original transfer contains an invalid official-named archive. The
      # complete README command must privately co-snapshot it and reach the
      # PINNED-SHA error, not "archive absent" from the preflight directory.
      c="/root/stl/wstunnel_11.0.0_linux_${STL_E2E_ARCH}.tar.gz"
      head -c 2048 /dev/zero > "$c"
      chmod 0600 "$c"
      if run_root_operator --with-wss > /tmp/stl-wss-invalid.log 2>&1; then
        fail accepted_invalid_optional_companion
      fi
      grep -q 'selected optional WSS archive SHA-256 mismatch' /tmp/stl-wss-invalid.log ||
        { cat /tmp/stl-wss-invalid.log >&2; fail wss_did_not_reach_copied_archive_sha_guard; }
      [[ ! -e /usr/local/bin/stl &&
         ! -e /usr/local/lib/simple-tun-link/install-record ]] ||
        fail invalid_companion_modified_installed_core
      shopt -s nullglob
      leftovers=(/root/.stl-preflight.*)
      shopt -u nullglob
      [[ ${#leftovers[@]} == 0 ]] || fail invalid_wss_left_private_preflight
      echo "LITERAL_WSS_PRIVATE_COMPANION_SNAPSHOT_INVALID_SHA_REFUSED=PASS"
      ;;
    wss-valid)
      # The guest cannot reach GitHub; upstream archive bytes are pinned
      # and SHA-verified by the unprivileged outer test runner.
      [[ -f /mnt/stl-wss-archive ]] || fail missing_pinned_guest_archive
      c="/root/stl/wstunnel_11.0.0_linux_${STL_E2E_ARCH}.tar.gz"
      install -m 0600 -- /mnt/stl-wss-archive "$c"
      run_root_operator --with-wss
      [[ -x /usr/local/bin/stl &&
         -x /usr/local/libexec/stl/wstunnel ]] ||
        fail valid_selected_companion_not_installed
      [[ $(sha256sum /usr/local/libexec/stl/wstunnel | awk '{print $1}') == "$STL_E2E_WSS_EXEC_SHA" ]] ||
        fail selected_wss_helper_executable_hash_drift
      /usr/local/bin/stl version --json |
        grep -Fq "\"version\":\"$STL_E2E_EXPECTED_VERSION\"" ||
        fail selected_wss_changed_core_version
      shopt -s nullglob
      leftovers=(/root/.stl-preflight.*)
      shopt -u nullglob
      [[ ${#leftovers[@]} == 0 ]] || fail valid_wss_left_private_preflight
      echo "LITERAL_OFFLINE_WSS_COMPANION_VALIDATED_AND_INSTALLED=PASS"
      ;;
    quic-invalid)
      # The README command must snapshot the selected transferred Hysteria
      # binary and reach its pinned digest guard before any core mutation.
      c="/root/stl/hysteria-linux-${STL_E2E_ARCH}"
      head -c 2048 /dev/zero > "$c"
      chmod 0600 "$c"
      if run_root_operator --with-quic > /tmp/stl-quic-invalid.log 2>&1; then
        fail accepted_invalid_optional_quic_companion
      fi
      grep -q 'selected optional QUIC binary SHA-256 mismatch' /tmp/stl-quic-invalid.log ||
        { cat /tmp/stl-quic-invalid.log >&2; fail quic_did_not_reach_copied_binary_sha_guard; }
      [[ ! -e /usr/local/bin/stl && ! -e /usr/local/libexec/stl/hysteria &&
         ! -e /usr/local/lib/simple-tun-link/install-record ]] ||
        fail invalid_quic_modified_installed_core
      shopt -s nullglob
      leftovers=(/root/.stl-preflight.*)
      shopt -u nullglob
      [[ ${#leftovers[@]} == 0 ]] || fail invalid_quic_left_private_preflight
      echo "LITERAL_QUIC_PRIVATE_COMPANION_SNAPSHOT_INVALID_SHA_REFUSED=PASS"
      ;;
    quic-valid|both-valid)
      # Only SHA-pinned transferred upstream bytes, not guest downloads.
      [[ -f /mnt/stl-quic-binary ]] || fail missing_pinned_guest_quic_binary
      install -m 0600 -- /mnt/stl-quic-binary "/root/stl/hysteria-linux-${STL_E2E_ARCH}"
      if [[ $STL_E2E_SCENARIO == both-valid ]]; then
        [[ -f /mnt/stl-wss-archive ]] || fail missing_pinned_guest_wss_archive
        install -m 0600 -- /mnt/stl-wss-archive \
          "/root/stl/wstunnel_11.0.0_linux_${STL_E2E_ARCH}.tar.gz"
        run_root_operator --with-wss --with-quic
      else
        run_root_operator --with-quic
      fi
      [[ -x /usr/local/bin/stl && -x /usr/local/libexec/stl/hysteria ]] ||
        fail valid_selected_quic_not_installed
      [[ $(sha256sum /usr/local/libexec/stl/hysteria | awk '{print $1}') == "$STL_E2E_QUIC_EXEC_SHA" ]] ||
        fail selected_quic_helper_executable_hash_drift
      if [[ $STL_E2E_SCENARIO == both-valid ]]; then
        [[ -x /usr/local/libexec/stl/wstunnel ]] || fail combined_selected_wss_not_installed
        [[ $(sha256sum /usr/local/libexec/stl/wstunnel | awk '{print $1}') == "$STL_E2E_WSS_EXEC_SHA" ]] ||
          fail combined_selected_wss_executable_hash_drift
      else
        [[ ! -e /usr/local/libexec/stl/wstunnel ]] || fail unselected_wss_was_installed
      fi
      /usr/local/bin/stl version --json |
        grep -Fq "\"version\":\"$STL_E2E_EXPECTED_VERSION\"" ||
        fail selected_quic_changed_core_version
      shopt -s nullglob
      leftovers=(/root/.stl-preflight.*)
      shopt -u nullglob
      [[ ${#leftovers[@]} == 0 ]] || fail valid_quic_left_private_preflight
      echo "LITERAL_OFFLINE_${STL_E2E_SCENARIO^^}_COMPANIONS_VALIDATED_AND_INSTALLED=PASS"
      ;;
    stable-update)
      # Separate un-released test-tagged binaries exercise real automatic
      # Stable-to-Stable routing, exact ownership, and downgrade refusal.
      apt-get update -o APT::Update::Error-Mode=any >/dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iproute2 iptables kmod wireguard-tools >/dev/null
      cat > /usr/sbin/apt-get <<'APT_STUB'
#!/bin/sh
printf 'APT_WAS_CALLED\n' > /tmp/stl-apt-was-called
exit 88
APT_STUB
      chmod 0755 /usr/sbin/apt-get
      cp -- /mnt/stl-older.sh "/root/stl/$STL_E2E_OLDER_NAME"
      rm -- "/root/stl/$STL_E2E_ENTRY_NAME"
      run_root_operator
      /usr/local/bin/stl version --json | grep -Fq '"version":"v999.0.0"' ||
        fail initial_test_stable_version
      rm -- "/root/stl/$STL_E2E_OLDER_NAME"
      cp -- /mnt/stl-newer.sh "/root/stl/$STL_E2E_NEWER_NAME"
      run_root_operator
      /usr/local/bin/stl version --json | grep -Fq '"version":"v999.0.1"' ||
        fail stable_update_did_not_replace_owned_binary
      after_sha=$(sha256sum /usr/local/bin/stl | cut -d' ' -f1)
      rm -- "/root/stl/$STL_E2E_NEWER_NAME"
      cp -- /mnt/stl-older.sh "/root/stl/$STL_E2E_OLDER_NAME"
      if run_root_operator > /tmp/stl-downgrade-failure 2>&1; then
        fail automatic_downgrade_accepted
      fi
      grep -q 'refusing automatic downgrade/channel change' /tmp/stl-downgrade-failure ||
        fail missing_downgrade_refusal_diagnosis
      [[ $(sha256sum /usr/local/bin/stl | cut -d' ' -f1) == "$after_sha" ]] ||
        fail downgrade_changed_installed_binary
      [[ ! -e /tmp/stl-apt-was-called ]] || fail stable_update_used_apt_without_missing_packages
      ;;
    blocked-mirror)
      [[ ! -e /usr/local/bin/stl ]] || fail existing_stl
      if run_root_operator > /tmp/stl-mirror-failure 2>&1; then
        fail accepted_unavailable_signed_repo
      fi
      grep -Eqi 'APT|mirror|repository|package' /tmp/stl-mirror-failure ||
        { cat /tmp/stl-mirror-failure >&2; fail mirror_failure_has_no_diagnosis; }
      [[ ! -e /usr/local/bin/stl ]] || fail changed_executable_after_failed_mirror
      ;;
    preflight-size)
      # A sparse oversized or empty transferred file MUST be rejected before
      # mktemp/head/cmp and before any installation or APT effect. No 134 MB
      # payload is actually written to the guest's disk.
      file="/root/stl/$STL_E2E_ENTRY_NAME"
      mv -- "$file" /root/stl-size-original
      for size in 0 134250001; do
        truncate -s "$size" -- "$file"
        chmod 0600 -- "$file"
        [[ $(stat -c %s -- "$file") == "$size" ]] || fail sparse_fixture_wrong_size
        if run_root_operator > /tmp/stl-preflight-size-failure 2>&1; then
          fail "accepted_invalid_preflight_size_$size"
        fi
        grep -q 'installer file size must be 1..134250000 bytes' /tmp/stl-preflight-size-failure ||
          { cat /tmp/stl-preflight-size-failure >&2; fail preflight_size_wrong_diagnostic; }
        shopt -s nullglob
        stage_dirs=(/root/.stl-preflight.*)
        shopt -u nullglob
        [[ ${#stage_dirs[@]} == 0 ]] || fail preflight_allocated_staging_before_size_check
        [[ ! -e /usr/local/bin/stl &&
           ! -e /usr/local/lib/simple-tun-link/install-record ]] ||
          fail preflight_size_rejection_modified_installation
      done
      # A truncated but non-empty transferred payload within the size limit
      # must fail the verified archive boundary, not install a broken build.
      cp -- /root/stl-size-original "$file"
      original_size=$(stat -c %s -- "$file")
      (( original_size > 100 )) || fail invalid_fixture_size
      truncate -s "$((original_size - 13))" -- "$file"
      if run_root_operator > /tmp/stl-truncated-failure 2>&1; then
        fail accepted_truncated_embedded_payload
      fi
      grep -Eq 'SHA256 mismatch|invalid or oversized payload' /tmp/stl-truncated-failure ||
        { cat /tmp/stl-truncated-failure >&2; fail truncated_wrong_integrity_diagnostic; }
      [[ ! -e /usr/local/bin/stl &&
         ! -e /usr/local/lib/simple-tun-link/install-record ]] ||
        fail truncated_payload_modified_installation
      ;;
    untrusted-foreign)
      # Inject an executable prelude into the incoming file. An unchanged
      # launcher that rejects 0666 *after* executing would be insufficient.
      file="/root/stl/$STL_E2E_ENTRY_NAME"
      cp -- "$file" /root/stl-original
      printf 'touch /tmp/STL_UNTRUSTED_CODE_EXECUTED\n' > /root/stl-injected
      cat -- /root/stl-original >> /root/stl-injected
      mv -f -- /root/stl-injected "$file"
      chmod 0666 -- "$file"
      if run_root_operator > /tmp/stl-untrusted-failure 2>&1; then
        fail accepted_world_writable_file
      fi
      [[ ! -e /tmp/STL_UNTRUSTED_CODE_EXECUTED ]] || fail untrusted_code_ran_before_checks
      grep -q 'unsafe folder/file' /tmp/stl-untrusted-failure || fail unsafe_mode_wrong_error
      mv -f -- /root/stl-original "$file"
      # A symlink target may contain arbitrary injected shell instructions;
      # the link must be refused by the trusted command, not by that target.
      mv -- "$file" /root/stl-safe-source
      printf 'touch /tmp/STL_UNTRUSTED_CODE_EXECUTED\n' > /root/stl-malicious-target
      ln -s /root/stl-malicious-target "$file"
      if run_root_operator > /tmp/stl-symlink-failure 2>&1; then
        fail accepted_symlink_source
      fi
      [[ ! -e /tmp/STL_UNTRUSTED_CODE_EXECUTED ]] || fail symlink_executed_untrusted_code
      rm -- "$file"
      mv -- /root/stl-safe-source "$file"
      # Now the file itself has the malicious prelude, but is mode 0600;
      # world-writable ancestor must STILL forbid its execution.
      printf 'touch /tmp/STL_UNTRUSTED_CODE_EXECUTED\n' > /root/stl-unsafe-ancestor-source
      cat -- "$file" >> /root/stl-unsafe-ancestor-source
      mv -- "$file" /root/stl-safe-source
      mv -- /root/stl-unsafe-ancestor-source "$file"
      chmod 0600 "$file"
      chmod 0777 /root/stl
      if run_root_operator > /tmp/stl-writable-ancestor-failure 2>&1; then
        fail accepted_writable_source_ancestor
      fi
      [[ ! -e /tmp/STL_UNTRUSTED_CODE_EXECUTED ]] || fail ancestor_executed_untrusted_code
      chmod 0700 /root/stl
      rm -- "$file"
      mv -- /root/stl-safe-source "$file"
      cp -- "$file" /root/stl/stl_duplicate_local-install.sh
      if run_root_operator > /tmp/stl-multiple-failure 2>&1; then
        fail accepted_multiple_installers
      fi
      rm -- /root/stl/stl_duplicate_local-install.sh
      [[ ! -e /usr/local/bin/stl ]] || fail untrusted_source_modified_installation
      printf 'FOREIGN_STL_BINARY\n' > /usr/local/bin/stl
      if run_root_operator > /tmp/stl-foreign-failure 2>&1; then
        fail took_over_foreign_installer
      fi
      grep -qx 'FOREIGN_STL_BINARY' /usr/local/bin/stl || fail modified_foreign_executable
      ;;
    *) fail unexpected_scenario ;;
  esac
  if [[ $STL_E2E_SCENARIO == missing-packages || $STL_E2E_SCENARIO == preinstalled-no-apt ||
        $STL_E2E_SCENARIO == sudo-operator ]]; then
    [[ -x /usr/local/bin/stl && -L /usr/local/bin/stlink ]] || fail missing_installed_binary
    /usr/local/bin/stl version --json | grep -Fq "\"version\":\"$STL_E2E_EXPECTED_VERSION\"" ||
      fail installed_version_mismatch
  fi
  exit 0
fi

fail() { printf 'LOCAL_ONE_COMMAND_E2E_FAILED=%s\n' "$*" >&2; exit 1; }
[[ ${STL_E2E_DISPOSABLE_HOST:-} == approved && $EUID != 0 && ! -e /.dockerenv ]] ||
  fail 'disposable unprivileged test runner required'
[[ $# == 4 ]] || fail 'usage: local-one-command-docker.sh bundle-dir guest-image arch version'
bundle=$1 image=$2 arch=$3 version=$4
case $image in ubuntu:24.04|debian:bookworm) ;; *) fail 'unsupported disposable image' ;; esac
[[ $arch == amd64 || $arch == arm64 ]] || fail 'unsupported arch'
[[ $version =~ ^dev-[0-9a-f]{12}$ ]] || fail 'snapshot candidate required'
entry_name="stl_${version}_linux_${arch}_local-install.sh"
entry="$bundle/$entry_name"
[[ -f $entry && ! -L $entry ]] || fail 'missing tested one-file artifact'
(
  cd "$bundle"
  sha256sum --check --ignore-missing SHA256SUMS > /dev/null
) || fail 'candidate checksums differ'

guest_script=$(realpath -e -- "${BASH_SOURCE[0]}")
# Assert both documentation commands are exactly equivalent, aside from
# the real sudo prefix. The guest executes the actual root/sudo text.
root_line=$(grep '^bash -c .*stl-preflight' README.md)
sudo_line=$(grep '^sudo bash -c .*stl-preflight' docs/INSTALL.md)
[[ -n $root_line && $sudo_line == "sudo $root_line" ]] || fail operator_docs_drift
printf '%s\n' "$root_line" | bash -n || fail malformed_root_operator_command
printf '%s\n' "$sudo_line" | bash -n || fail malformed_sudo_operator_command
# Only the disposable guest executes the third-party helper. Its archive
# is downloaded by the unprivileged runner, SHA-pinned and mounted read-only;
# the guest has GitHub destinations blocked and no host package mounts.
helper_dir=$(mktemp -d /var/tmp/stl-operator-helpers.XXXXXXXX)
trap 'rm -rf -- "$helper_dir"' EXIT
case $arch in
  amd64)
    wss_archive_sha=9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e
    wss_exe_sha=6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49
    quic_exe_sha=907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691 ;;
  arm64)
    wss_archive_sha=b86abf73e340ed0c3ff9a77a5458aa27213784920ec65513132b36def45edc94
    wss_exe_sha=c0fa96ec1ceb9275137939159f095d1063b0365641e9d63f84d032c23c7c81ed
    quic_exe_sha=a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7 ;;
esac
command -v curl >/dev/null || fail missing_verified_upstream_download_tool
wss_file="$helper_dir/wstunnel_11.0.0_linux_${arch}.tar.gz"
curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 12 --max-time 120 --retry 2 \
  "https://github.com/erebe/wstunnel/releases/download/v11.0.0/${wss_file##*/}" \
  -o "$wss_file" || fail pinned_optional_companion_download_failed
[[ $(sha256sum "$wss_file" | awk '{print $1}') == "$wss_archive_sha" ]] ||
  fail pinned_optional_companion_source_sha_mismatch
quic_file="$helper_dir/hysteria-linux-${arch}"
curl -fLSs --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 12 --max-time 120 --retry 2 \
  "https://github.com/HyNetworks/hysteria/releases/download/app%2Fv2.13.0/${quic_file##*/}" \
  -o "$quic_file" || fail pinned_optional_quic_download_failed
[[ $(sha256sum "$quic_file" | awk '{print $1}') == "$quic_exe_sha" ]] ||
  fail pinned_optional_quic_source_sha_mismatch

for scenario in missing-packages preinstalled-no-apt blocked-mirror preflight-size untrusted-foreign sudo-operator wss-invalid wss-valid quic-invalid quic-valid both-valid; do
  network=bridge
  [[ $scenario == blocked-mirror || $scenario == untrusted-foreign ||
     $scenario == preflight-size || $scenario == wss-invalid ||
     $scenario == quic-invalid ]] && network=none
  docker run --rm --network "$network" \
    --add-host github.com:127.0.0.1 \
    --add-host api.github.com:127.0.0.1 \
    --add-host objects.githubusercontent.com:127.0.0.1 \
    --add-host github-releases.githubusercontent.com:127.0.0.1 \
    -e STL_E2E_DISPOSABLE_GUEST=approved \
    -e STL_E2E_SCENARIO="$scenario" \
    -e STL_E2E_ENTRY_NAME="$entry_name" \
    -e STL_E2E_EXPECTED_VERSION="$version" \
    -e STL_E2E_ARCH="$arch" \
    -e STL_E2E_WSS_EXEC_SHA="$wss_exe_sha" \
    -e STL_E2E_QUIC_EXEC_SHA="$quic_exe_sha" \
    -v "$wss_file:/mnt/stl-wss-archive:ro" \
    -v "$quic_file:/mnt/stl-quic-binary:ro" \
    -v "$entry:/mnt/stl-entry.sh:ro" \
    -v "$guest_script:/mnt/stl-guest-driver.sh:ro" \
    -v "$PWD/README.md:/mnt/stl-readme:ro" \
    -v "$PWD/docs/INSTALL.md:/mnt/stl-install-doc:ro" \
    "$image" /bin/bash /mnt/stl-guest-driver.sh guest
  printf 'LOCAL_ONE_COMMAND_%s=PASS (%s linux/%s)\n' "$scenario" "$image" "$arch"
done

# Build two test-tagged artifacts only inside an ephemeral private clone.
# Never publish/push these tags or modify the source worktree's tag namespace.
fixture=$(mktemp -d /var/tmp/stl-local-stable-e2e.XXXXXXXX)
trap 'rm -rf -- "$fixture" "$helper_dir"' EXIT
git clone --quiet --local --no-hardlinks -- "$PWD" "$fixture/repo"
[[ $(git -C "$fixture/repo" rev-parse HEAD) == "$(git rev-parse HEAD)" ]] ||
  fail 'ephemeral release fixture has the wrong candidate HEAD'
for stable in v999.0.0 v999.0.1; do
  [[ -z $(git -C "$fixture/repo" tag -l "$stable") ]] || fail 'synthetic test tag exists'
  git -C "$fixture/repo" tag "$stable"
  (cd "$fixture/repo" && bash scripts/build-artifacts.sh --tag "$stable" "$fixture/$stable" >/dev/null)
done
older_name="stl_v999.0.0_linux_${arch}_local-install.sh"
newer_name="stl_v999.0.1_linux_${arch}_local-install.sh"
[[ -f "$fixture/v999.0.0/$older_name" && -f "$fixture/v999.0.1/$newer_name" ]] ||
  fail 'missing synthetic stable update artifacts'
docker run --rm --network bridge \
  --add-host github.com:127.0.0.1 \
  --add-host api.github.com:127.0.0.1 \
  --add-host objects.githubusercontent.com:127.0.0.1 \
  --add-host github-releases.githubusercontent.com:127.0.0.1 \
  -e STL_E2E_DISPOSABLE_GUEST=approved \
  -e STL_E2E_SCENARIO=stable-update \
  -e STL_E2E_ENTRY_NAME="$entry_name" \
  -e STL_E2E_OLDER_NAME="$older_name" \
  -e STL_E2E_NEWER_NAME="$newer_name" \
  -v "$entry:/mnt/stl-entry.sh:ro" \
  -v "$fixture/v999.0.0/$older_name:/mnt/stl-older.sh:ro" \
  -v "$fixture/v999.0.1/$newer_name:/mnt/stl-newer.sh:ro" \
  -v "$guest_script:/mnt/stl-guest-driver.sh:ro" \
  -v "$PWD/README.md:/mnt/stl-readme:ro" \
  -v "$PWD/docs/INSTALL.md:/mnt/stl-install-doc:ro" \
  "$image" /bin/bash /mnt/stl-guest-driver.sh guest
printf 'LOCAL_ONE_COMMAND_STABLE_UPDATE_AND_DOWNGRADE_REFUSAL=PASS (%s linux/%s)\n' "$image" "$arch"

