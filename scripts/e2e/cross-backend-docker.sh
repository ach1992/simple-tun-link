#!/usr/bin/env bash
# Release-level real network E2E using freshly created, network-disconnected
# disposable Docker guests. Never invoke on the Agent host or on production.
set -Eeuo pipefail
umask 077
# Root may inspect this aiworker-owned worktree, but must never refresh or
# replace its index. Every invocation here is read-only with respect to Git.
export GIT_OPTIONAL_LOCKS=0
if [[ ${STL_E2E_DISPOSABLE_HOST:-} != approved || $EUID -ne 0 ]]; then
  echo 'REFUSED: explicitly approved disposable Docker host and root required' >&2
  exit 2
fi
for tool in git go docker sha256sum ip iptables mktemp; do
  command -v "$tool" >/dev/null || { echo "MISSING_PREREQUISITE=$tool" >&2; exit 2; }
done
source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$source_root"
[[ -f go.mod ]] || { echo 'REFUSED: missing source root' >&2; exit 2; }
# Executed as root only on the disposable Docker test runner. Do not alter
# the global trust configuration or owner of the checkout.
source_status="$(git -c safe.directory="$source_root" status --porcelain)" || {
  echo 'REFUSED: cannot inspect exact source state' >&2; exit 2;
}
[[ -z "$source_status" ]] || {
  echo 'REFUSED: committed clean source required' >&2; exit 2;
}
source_sha="$(git -c safe.directory="$source_root" rev-parse HEAD)" || exit 2
[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || exit 2
# Real ARM64 acceptance must execute on a native ARM64 kernel; do not
# confuse emulated userspace or a cross-compiled test binary with runtime.
host_arch="$(uname -m)"
case "$host_arch:$(go env GOARCH)" in
  x86_64:amd64|aarch64:arm64) ;;
  *) echo "REFUSED: unsupported or cross-compiled kernel/Go architecture $host_arch" >&2; exit 2 ;;
esac
echo "CROSS_BACKEND_REAL_KERNEL_ARCH=$host_arch"
# Pin exact guest images: caller is responsible for building and reviewing
# these task-only images using cross-backend.Dockerfile first.
ubuntu_image="${STL_E2E_IMAGE_UBUNTU:-stl-cross-backend:ubuntu24}"
debian_image="${STL_E2E_IMAGE_DEBIAN:-stl-cross-backend:debian13}"
for image in "$ubuntu_image" "$debian_image"; do
  docker image inspect -- "$image" >/dev/null || {
    echo "MISSING_DISPOSABLE_IMAGE=$image" >&2; exit 2;
  }
done
host_default_before="$(ip -4 route show default)"
host_input_before="$(iptables -S INPUT)"
temp="$(mktemp -d /tmp/stl-cross-backend.XXXXXXXX)"
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if [[ -d "$temp" && "$temp" == /tmp/stl-cross-backend.* ]]; then
    rm -rf -- "$temp" || rc=1
  fi
  [[ "$(ip -4 route show default)" == "$host_default_before" &&
     "$(iptables -S INPUT)" == "$host_input_before" ]] || {
    echo 'FAIL: Docker host routing/firewall baseline changed (no automatic restore)' >&2
    rc=1
  }
  echo "CROSS_BACKEND_DISPOSABLE_CLEANUP_EXIT=$rc"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

GOTOOLCHAIN=local go test -c -o "$temp/stl-cross.test" ./cmd/stl
binary_sha="$(sha256sum "$temp/stl-cross.test" | awk '{print $1}')"
# No full worktree mount: its private aiworker permissions would otherwise
# require the disconnected guest to gain DAC_OVERRIDE. Stage only committed,
# non-secret fixture inputs and expose them read-only with ordinary 0755/0644.
mkdir -p "$temp/source/scripts/e2e"
git -c safe.directory="$source_root" show "$source_sha:scripts/e2e/gre-netns.sh" > "$temp/source/scripts/e2e/gre-netns.sh"
git -c safe.directory="$source_root" show "$source_sha:scripts/e2e/throughput-bind-netns.sh" > "$temp/source/scripts/e2e/throughput-bind-netns.sh"
git -c safe.directory="$source_root" show "$source_sha:go.mod" > "$temp/source/go.mod"
chmod 0755 "$temp" "$temp/source" "$temp/source/scripts" "$temp/source/scripts/e2e" \
  "$temp/source/scripts/e2e/gre-netns.sh" "$temp/source/scripts/e2e/throughput-bind-netns.sh"
chmod 0644 "$temp/source/go.mod"
script_sha="$(sha256sum "$temp/source/scripts/e2e/gre-netns.sh" | awk '{print $1}')"
echo "CROSS_BACKEND_COMMITTED_SCRIPT_SHA256=$script_sha"
echo "THROUGHPUT_BIND_COMMITTED_SCRIPT_SHA256=$(sha256sum "$temp/source/scripts/e2e/throughput-bind-netns.sh" | awk '{print $1}')"
echo "CROSS_BACKEND_SOURCE_SHA=$source_sha"
echo "CROSS_BACKEND_TEST_BINARY_SHA256=$binary_sha"
echo "CROSS_BACKEND_BUILDER=$(go version)"
echo 'CROSS_BACKEND_SCOPE=DISCONNECTED_CONTAINER_TWO_FRESH_NETNS_NO_HOST_NETWORK_MUTATION'
for entry in "ubuntu:$ubuntu_image" "debian:$debian_image"; do
  distro="${entry%%:*}"
  image="${entry#*:}"
  image_id="$(docker image inspect --format '{{.Id}}' "$image")"
  echo "CROSS_BACKEND_IMAGE_$distro=$image_id"
  # Read-only source, test executable, no host networking, no host /run or
  # systemd, no Docker socket; privileged capabilities confined to guest.
  docker run --rm --network none --pull never --read-only \
    --tmpfs /tmp:exec,nosuid,size=256m,mode=1777 \
    --tmpfs /run:mode=0755,size=32m \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --cap-add NET_BIND_SERVICE \
    --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
    --mount "type=bind,source=$temp/source,target=/proof/source,readonly" \
    --mount "type=bind,source=$temp/stl-cross.test,target=/proof/stl-cross.test,readonly" \
    -e STL_E2E_DISPOSABLE_HOST=approved -e STL_E2E_CROSS_WG=approved \
    -e STL_E2E_CROSS_IPSEC=approved \
    -e STL_E2E_CROSS_NATT=approved \
    -e STL_E2E_THROUGHPUT_BIND=approved \
    -e STL_E2E_PREBUILT_TEST=/proof/stl-cross.test \
    -e "STL_E2E_PREBUILT_SHA256=$binary_sha" \
    -e "STL_E2E_SOURCE_SHA=$source_sha" \
    -e "STL_E2E_EXPECTED_DISTRO=$distro" \
    -e "STL_E2E_EXPECTED_ARCH=$host_arch" \
    "$image" /bin/bash -c '
      set -Eeuo pipefail
      . /etc/os-release
      case "$STL_E2E_EXPECTED_DISTRO:$ID:$VERSION_ID" in
        ubuntu:ubuntu:24.04|debian:debian:13) ;;
        *) echo "REFUSED: image is not declared Ubuntu LTS/Debian stable"; exit 2 ;;
      esac
      [[ "$(uname -m)" == "$STL_E2E_EXPECTED_ARCH" ]] || {
        echo "REFUSED: kernel/guest architecture mismatch $(uname -m)"; exit 2;
      }
      case "$STL_E2E_EXPECTED_ARCH:$(dpkg --print-architecture)" in
        x86_64:amd64|aarch64:arm64) ;;
        *) echo "REFUSED: guest architecture not native to kernel"; exit 2 ;;
      esac
      echo "CROSS_BACKEND_GUEST_ARCH=$STL_E2E_EXPECTED_ARCH"
      echo "CROSS_BACKEND_GUEST_DISTRO=$PRETTY_NAME"
      printf "CROSS_BACKEND_GUEST_KERNEL=%s\n" "$(uname -r)"
      printf "CROSS_BACKEND_GUEST_IPROUTE=%s\n" "$(ip -Version)"
      printf "CROSS_BACKEND_GUEST_WG=%s\n" "$(wg --version)"
      printf "CROSS_BACKEND_GUEST_CHARON_PACKAGE=%s\n" "$(dpkg-query -W charon-systemd)"
      # First prove iperf3 TCP CONTROL and DATA socket binding using only
      # fresh guest-local namespaces; no real external/WAN endpoint.
      /bin/bash /proof/source/scripts/e2e/throughput-bind-netns.sh
      exec /bin/bash /proof/source/scripts/e2e/gre-netns.sh
    '
  echo "CROSS_BACKEND_$distro=PASS"
done
echo 'CROSS_BACKEND_UBUNTU_DEBIAN_REAL_E2E=PASS'
