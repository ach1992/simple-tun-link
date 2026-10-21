#!/usr/bin/env bash
# Literal README one-file/one-command acceptance inside DISPOSABLE guests.
# No host packages, STL installation, Docker socket, privileged caps or host
# networking are ever mounted into the guest. Called by package-prepare E2E.
set -Eeuo pipefail
umask 077

if [[ ${1:-} == guest && -e /.dockerenv && ${STL_E2E_DISPOSABLE_GUEST:-} == approved ]]; then
  [[ $EUID == 0 ]] || exit 98
  fail() { echo "LOCAL_ONE_COMMAND_GUEST_FAILED=$*" >&2; exit 1; }
  # Root-only disposable guests do not need sudo, but this makes the real
  # README command literal and independent of the distro image's sudo package.
  sudo() { "$@"; }
  install -d -m 0755 /root/stl
  cp -- /mnt/stl-entry.sh "/root/stl/$STL_E2E_ENTRY_NAME"
  case $STL_E2E_SCENARIO in
    missing-packages)
      # Missing distro packages are genuinely installed through the configured
      # distro-signed APT flow. All GitHub destinations are unreachable.
      [[ ! -e /usr/local/bin/stl ]] || fail existing_stl
      sudo bash -c 'bash /root/stl/*_local-install.sh'
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
      sudo bash -c 'bash /root/stl/*_local-install.sh'
      [[ ! -e /tmp/stl-apt-was-called ]] || fail unnecessary_apt_on_install
      inode=$(stat -c %i -- /usr/local/bin/stl)
      before_record=$(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1)
      sudo bash -c 'bash /root/stl/*_local-install.sh'
      [[ ! -e /tmp/stl-apt-was-called && $(stat -c %i -- /usr/local/bin/stl) == "$inode" &&
         $(sha256sum /usr/local/lib/simple-tun-link/install-record | cut -d' ' -f1) == "$before_record" ]] ||
        fail no_op_changed_files_or_used_apt
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
      sudo bash -c 'bash /root/stl/*_local-install.sh'
      /usr/local/bin/stl version --json | grep -Fq '"version":"v999.0.0"' ||
        fail initial_test_stable_version
      rm -- "/root/stl/$STL_E2E_OLDER_NAME"
      cp -- /mnt/stl-newer.sh "/root/stl/$STL_E2E_NEWER_NAME"
      sudo bash -c 'bash /root/stl/*_local-install.sh'
      /usr/local/bin/stl version --json | grep -Fq '"version":"v999.0.1"' ||
        fail stable_update_did_not_replace_owned_binary
      after_sha=$(sha256sum /usr/local/bin/stl | cut -d' ' -f1)
      rm -- "/root/stl/$STL_E2E_NEWER_NAME"
      cp -- /mnt/stl-older.sh "/root/stl/$STL_E2E_OLDER_NAME"
      if sudo bash -c 'bash /root/stl/*_local-install.sh' > /tmp/stl-downgrade-failure 2>&1; then
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
      if sudo bash -c 'bash /root/stl/*_local-install.sh' > /tmp/stl-mirror-failure 2>&1; then
        fail accepted_unavailable_signed_repo
      fi
      grep -Eqi 'APT|mirror|repository|package' /tmp/stl-mirror-failure ||
        { cat /tmp/stl-mirror-failure >&2; fail mirror_failure_has_no_diagnosis; }
      [[ ! -e /usr/local/bin/stl ]] || fail changed_executable_after_failed_mirror
      ;;
    untrusted-foreign)
      chmod 0666 "/root/stl/$STL_E2E_ENTRY_NAME"
      if sudo bash -c 'bash /root/stl/*_local-install.sh' > /tmp/stl-untrusted-failure 2>&1; then
        fail accepted_world_writable_file
      fi
      grep -q 'writable by other users' /tmp/stl-untrusted-failure || fail unsafe_mode_wrong_error
      chmod 0600 "/root/stl/$STL_E2E_ENTRY_NAME"
      printf 'FOREIGN_STL_BINARY\n' > /usr/local/bin/stl
      if sudo bash -c 'bash /root/stl/*_local-install.sh' > /tmp/stl-foreign-failure 2>&1; then
        fail took_over_foreign_installer
      fi
      grep -qx 'FOREIGN_STL_BINARY' /usr/local/bin/stl || fail modified_foreign_executable
      ;;
    *) fail unexpected_scenario ;;
  esac
  if [[ $STL_E2E_SCENARIO == missing-packages || $STL_E2E_SCENARIO == preinstalled-no-apt ]]; then
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
# The guest shell runs the exact line from README. `sudo` is a local shell
# function in root-only Docker to avoid pulling a sudo package into the
# fixture; it simply delegates to bash, without changing the command.
for scenario in missing-packages preinstalled-no-apt blocked-mirror untrusted-foreign; do
  network=bridge
  [[ $scenario == blocked-mirror || $scenario == untrusted-foreign ]] && network=none
  docker run --rm --network "$network" \
    --add-host github.com:127.0.0.1 \
    --add-host api.github.com:127.0.0.1 \
    --add-host objects.githubusercontent.com:127.0.0.1 \
    --add-host github-releases.githubusercontent.com:127.0.0.1 \
    -e STL_E2E_DISPOSABLE_GUEST=approved \
    -e STL_E2E_SCENARIO="$scenario" \
    -e STL_E2E_ENTRY_NAME="$entry_name" \
    -e STL_E2E_EXPECTED_VERSION="$version" \
    -v "$entry:/mnt/stl-entry.sh:ro" \
    -v "$guest_script:/mnt/stl-guest-driver.sh:ro" \
    "$image" /bin/bash /mnt/stl-guest-driver.sh guest
  printf 'LOCAL_ONE_COMMAND_%s=PASS (%s linux/%s)\n' "$scenario" "$image" "$arch"
done

# Build two test-tagged artifacts only inside an ephemeral private clone.
# Never publish/push these tags or modify the source worktree's tag namespace.
fixture=$(mktemp -d /var/tmp/stl-local-stable-e2e.XXXXXXXX)
trap 'rm -rf -- "$fixture"' EXIT
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
  "$image" /bin/bash /mnt/stl-guest-driver.sh guest
printf 'LOCAL_ONE_COMMAND_STABLE_UPDATE_AND_DOWNGRADE_REFUSAL=PASS (%s linux/%s)\n' "$image" "$arch"

