#!/usr/bin/env bash
# SECURITY: privileged kernel WireGuard acceptance in two fresh isolated
# namespaces on an explicitly approved disposable test host ONLY.
# Never execute this runner on the network namespace of the SSH/MCP agent.
set -Eeuo pipefail
umask 077

if [[ "${STL_E2E_DISPOSABLE_HOST:-}" != approved ]]; then
  echo 'REFUSED: explicit disposable-host approval required (STL_E2E_DISPOSABLE_HOST=approved)' >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo 'REFUSED: isolated network acceptance requires disposable-host root' >&2
  exit 2
fi
for tool in go wg ip iptables ping mktemp git; do
  command -v "$tool" >/dev/null || { echo "MISSING_E2E_PREREQUISITE=$tool" >&2; exit 2; }
done
source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$source_root"
[[ -f go.mod ]] || { echo 'REFUSED: Go source is unavailable' >&2; exit 2; }
[[ -z "$(git status --porcelain)" ]] || { echo 'REFUSED: test source must be committed and clean' >&2; exit 2; }

workdir="$(mktemp -d /tmp/stl-wg-e2e.XXXXXXXX)"
suffix="${workdir##*.}"
ns_a="stlw${suffix}a"
ns_b="stlw${suffix}b"
created_a=0
created_b=0
host_default_before="$(ip -4 route show default)"
cleanup() {
  local status="$1"
  trap - EXIT INT TERM
  set +e
  if (( created_b )); then
    ip netns delete "$ns_b" || { echo 'FAILED_TO_CLEAN_NAMESPACE_B' >&2; status=1; }
  fi
  if (( created_a )); then
    ip netns delete "$ns_a" || { echo 'FAILED_TO_CLEAN_NAMESPACE_A' >&2; status=1; }
  fi
  if [[ "$(ip -4 route show default)" != "$host_default_before" ]]; then
    echo 'HOST_DEFAULT_ROUTE_CHANGED: investigate, never auto-restore' >&2
    status=1
  fi
  if [[ "$workdir" == /tmp/stl-wg-e2e.* && -d "$workdir" ]]; then
    rm -rf -- "$workdir" || status=1
  fi
  printf 'WG_ISOLATED_E2E_CLEANUP_EXIT=%s\n' "$status"
  exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ip netns list | awk '{print $1}' | grep -Fxe "$ns_a" -e "$ns_b" >/dev/null; then
  echo 'REFUSED: generated netns identity already in use' >&2
  exit 2
fi
mkdir -m 0700 "$workdir/a" "$workdir/b"

printf 'WG_E2E_SOURCE_SHA=%s\n' "$(git rev-parse HEAD)"
printf 'WG_E2E_KERNEL=%s\n' "$(uname -r)"
# No module installation/modprobe, host interfaces, host firewall changes,
# root state-root, external peers, public credentials, or broad cleanups.
GOTOOLCHAIN=local go test -c -o "$workdir/wg-e2e.test" ./cmd/stl
ip netns add "$ns_a"
created_a=1
ip netns add "$ns_b"
created_b=1
ip -n "$ns_a" link add stlula type veth peer name stlulb
ip -n "$ns_a" link set stlulb netns "$ns_b"
ip -n "$ns_a" address add 192.0.2.10/31 dev stlula
ip -n "$ns_b" address add 192.0.2.11/31 dev stlulb
for ns in "$ns_a" "$ns_b"; do
  ip -n "$ns" link set lo up
done
ip -n "$ns_a" link set stlula up
ip -n "$ns_b" link set stlulb up
ip netns exec "$ns_a" ping -n -c 1 -W 3 -I 192.0.2.10 192.0.2.11 >/dev/null
ip netns exec "$ns_b" ping -n -c 1 -W 3 -I 192.0.2.11 192.0.2.10 >/dev/null
echo 'WG_SYNTHETIC_UNDERLAY_BIDIRECTIONAL=PASS'

run_side() {
  local side="$1" action="$2" ns root
  if [[ "$side" == a ]]; then
    ns="$ns_a"; root="$workdir/a"
  else
    ns="$ns_b"; root="$workdir/b"
  fi
  ip netns exec "$ns" env \
    STL_WG_NETNS_E2E=1 \
    STL_WG_E2E_ACTION="$action" \
    STL_WG_E2E_STATE_ROOT="$root" \
    "$workdir/wg-e2e.test" -test.run '^TestWireGuardNetnsE2E$' -test.v
}

owned_firewall_count() {
  local ns="$1" observed
  observed="$(ip netns exec "$ns" iptables -w 5 -S INPUT)" || return 1
  grep -Fc 'stl:lnk_88888888888888888888888888888888:' <<< "$observed" || true
}
assert_owned_rule_count() {
  local side="$1" expected="$2" ns
  if [[ "$side" == a ]]; then ns="$ns_a"; else ns="$ns_b"; fi
  local count
  count="$(owned_firewall_count "$ns")" || return 1
  if [[ "$count" != "$expected" ]]; then
    echo "FAIL: expected $expected verified STL-owned INPUT rules in $side, found $count" >&2
    exit 1
  fi
}

run_side a create
run_side b import
run_side a resume
assert_owned_rule_count a 1
assert_owned_rule_count b 1
# The entire test traffic stays in the 10.83.10.0/31 addresses inside veth
# isolated namespaces and requires the authenticated WireGuard session.
ip netns exec "$ns_a" ping -n -c 3 -W 3 -I 10.83.10.0 10.83.10.1 >/dev/null
ip netns exec "$ns_b" ping -n -c 3 -W 3 -I 10.83.10.1 10.83.10.0 >/dev/null
echo 'WG_REAL_BIDIRECTIONAL_PEER_TRAFFIC=PASS'
run_side a status
run_side b status
run_side a remove
run_side b remove
assert_owned_rule_count a 0
assert_owned_rule_count b 0
run_side a retire
run_side b retire
run_side a list
run_side b list
for ns in "$ns_a" "$ns_b"; do
  if ip -n "$ns" -details link show | grep -F 'alias stl:lnk_88888888888888888888888888888888'; then
    echo 'FAIL: WireGuard STL-owned link survived cleanup' >&2
    exit 1
  fi
  if ip netns exec "$ns" wg show interfaces | grep -F 'stlwg8888888888'; then
    echo 'FAIL: WireGuard test peer identity survived cleanup' >&2
    exit 1
  fi
done
echo 'WG_TWO_PEER_HANDSHAKE_TRAFFIC_STATUS_REMOVE_RETIRE=PASS'
