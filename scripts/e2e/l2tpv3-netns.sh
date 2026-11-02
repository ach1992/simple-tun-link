#!/usr/bin/env bash
# Real L2TPv3 Direct-IP kernel/Engine acceptance in two disposable namespaces.
# NEVER run on a shared/production host or rely on a test result from another
# kernel/version as a universal public-path availability guarantee.
set -Eeuo pipefail
umask 077

[[ "${STL_E2E_DISPOSABLE_HOST:-}" == approved && $EUID -eq 0 ]] || {
  echo "REFUSED: requires root and STL_E2E_DISPOSABLE_HOST=approved on a disposable validation VM" >&2
  exit 2
}
for tool in ip iptables ping python3 sha256sum mktemp; do
  command -v "$tool" >/dev/null || { echo "MISSING_PREREQUISITE=$tool" >&2; exit 2; }
done
root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$root"
# Root may inspect an aiworker-owned checkout, but must not refresh or
# rewrite its Git index/locks as a side effect of the acceptance run.
export GIT_OPTIONAL_LOCKS=0
[[ -f go.mod ]] || { echo "REFUSED: absent source identity" >&2; exit 2; }
temp="$(mktemp -d /tmp/stl-l2tpv3-e2e.XXXXXXXX)"
suffix="${temp##*.}"
ns_a="stl2${suffix}a"
ns_b="stl2${suffix}b"
created_a=0; created_b=0
default_before="$(ip -4 route show default)"
input_before="$(iptables -S INPUT)"
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if (( created_b )); then ip netns delete "$ns_b" || rc=1; fi
  if (( created_a )); then ip netns delete "$ns_a" || rc=1; fi
  [[ "$(ip -4 route show default)" == "$default_before" &&
     "$(iptables -S INPUT)" == "$input_before" ]] || {
    echo "HOST_NETWORK_BASELINE_CHANGED: inspect; no automatic restoration" >&2
    rc=1
  }
  if [[ "$temp" == /tmp/stl-l2tpv3-e2e.* && -d "$temp" ]];then
    rm -rf -- "$temp" || rc=1
  fi
  echo "L2TPV3_E2E_CLEANUP_EXIT=$rc"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ip netns list | awk '{print $1}' | grep -Fxe "$ns_a" -e "$ns_b" >/dev/null; then
  echo "REFUSED: test namespace collision" >&2
  exit 2
fi
mkdir -m 700 "$temp/a" "$temp/b"
if [[ -n "${STL_E2E_PREBUILT_TEST:-}" ]]; then
  [[ "${STL_E2E_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ &&
     "${STL_E2E_PREBUILT_SHA256:-}" =~ ^[0-9a-f]{64}$ &&
     -f "$STL_E2E_PREBUILT_TEST" && -x "$STL_E2E_PREBUILT_TEST" ]] || {
       echo "REFUSED: unverified prebuilt test or source identity" >&2; exit 2;
     }
  [[ "$(sha256sum "$STL_E2E_PREBUILT_TEST" | awk '{print $1}')" == "$STL_E2E_PREBUILT_SHA256" ]] || exit 2
  cp -- "$STL_E2E_PREBUILT_TEST" "$temp/l2tp.test"
  source_sha="$STL_E2E_SOURCE_SHA"
else
  command -v git >/dev/null && command -v go >/dev/null || exit 2
  [[ -z "$(git -c safe.directory="$root" status --porcelain)" ]] || {
    echo "REFUSED: source tree is dirty; immutable evidence cannot be established" >&2; exit 2;
  }
  source_sha="$(git -c safe.directory="$root" rev-parse HEAD)"
  GOTOOLCHAIN=local go test -c -o "$temp/l2tp.test" ./cmd/stl
fi
chmod 700 "$temp/l2tp.test"
echo "L2TPV3_TEST_SOURCE_SHA=$source_sha"
echo "L2TPV3_TEST_BINARY_SHA256=$(sha256sum "$temp/l2tp.test" | awk '{print $1}')"
ip netns add "$ns_a"
created_a=1
ip netns add "$ns_b"
created_b=1
ip -n "$ns_a" link add stl2ua type veth peer name stl2ub
ip -n "$ns_a" link set stl2ub netns "$ns_b"
ip -n "$ns_a" addr add 198.18.115.1/30 dev stl2ua
ip -n "$ns_b" addr add 198.18.115.2/30 dev stl2ub
for ns in "$ns_a" "$ns_b"; do ip -n "$ns" link set lo up; done
ip -n "$ns_a" link set stl2ua up
ip -n "$ns_b" link set stl2ub up
ip netns exec "$ns_a" ping -n -q -I 198.18.115.1 -c 2 -W 2 198.18.115.2
ip netns exec "$ns_b" ping -n -q -I 198.18.115.2 -c 2 -W 2 198.18.115.1
run_engine() {
  local role="$1" op="$2" slot="${3:-primary}" ns subdir
  if [[ "$role" == a ]]; then
    ns="$ns_a"; subdir="$temp/a"
  else
    ns="$ns_b"; subdir="$temp/b"
  fi
  ip netns exec "$ns" env \
    STL_L2TPV3_NETNS_E2E=approved \
    STL_L2TPV3_E2E_ROLE="$role" \
    STL_L2TPV3_E2E_ACTION="$op" \
    STL_L2TPV3_E2E_SLOT="$slot" \
    STL_L2TPV3_E2E_STATE_ROOT="$subdir" \
    "$temp/l2tp.test" -test.run '^TestL2TPv3NetnsE2E$' -test.v
}
run_engine a ensure
run_engine b ensure
run_engine a check
run_engine b check
echo "L2TPV3_NETLINK_EXCLUSIVE_NEIGHBOR_PROOF"
run_engine a exclusive-neighbor
run_engine b exclusive-neighbor
echo "L2TPV3_REAL_PRIVATE_ICMP_A_TO_B"
ip netns exec "$ns_a" ping -n -q -I 10.253.115.1 -c 8 -i 0.2 -W 2 10.253.115.2
echo "L2TPV3_REAL_PRIVATE_ICMP_B_TO_A"
ip netns exec "$ns_b" ping -n -q -I 10.253.115.2 -c 8 -i 0.2 -W 2 10.253.115.1
# Receiver-origin SHA-256 receipts prove real private TCP data rather than
# a local-up interface or a ping-only path. Each endpoint starts one transfer.
traffic() {
  local src_role="$1" peer_role="$2" src_ns peer_ns src_ip peer_ip port tag
  if [[ "$src_role" == a ]]; then
    src_ns="$ns_a"; peer_ns="$ns_b"; src_ip=10.253.115.1; peer_ip=10.253.115.2
    port=45115; tag=irrel-a-to-b
  else
    src_ns="$ns_b"; peer_ns="$ns_a"; src_ip=10.253.115.2; peer_ip=10.253.115.1
    port=45116; tag=irrel-b-to-a
  fi
  echo "L2TPV3_PRIVATE_TCP_TRANSFER_$src_role"
  local witness="$temp/tcp-$peer_role.log"
  timeout 45 ip netns exec "$peer_ns" python3 -u "$root/scripts/e2e/l2tpv3-tcp.py" server "$peer_ip" "$src_ip" "$port" 16 "$tag" > "$witness" 2>&1 &
  local server_pid=$!
  sleep 0.25
  # In case of a connection failure the bounded server exits on its own.
  # Wait before removing test namespaces, never signal a guessed PID.
  if ! timeout 45 ip netns exec "$src_ns" python3 -u "$root/scripts/e2e/l2tpv3-tcp.py" client "$src_ip" "$peer_ip" "$port" 16 "$tag"; then
    wait "$server_pid" || :
    cat "$witness"
    return 1
  fi
  wait "$server_pid"
  cat "$witness"
  grep -F '"event": "RECEIVER_SHA256"' "$witness" >/dev/null || return 1
}
traffic a b
traffic b a
echo "L2TPV3_TCP_BILATERAL_16MiB_SHA_PASS"
echo "L2TPV3_IDEMPOTENT_ENSURE"
run_engine a ensure | grep 'changed=false'
run_engine b ensure | grep 'changed=false'
echo "L2TPV3_COLD_KERNEL_LINK_RECREATE_FROM_COMMITTED_STATE"
tunnel_id="$(ip netns exec "$ns_a" ip -json l2tp show tunnel | python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d)==1; print(d[0]["tunnel_id"])')"
session_id="$(ip netns exec "$ns_a" ip -json l2tp show session | python3 -c 'import json,sys; d=json.load(sys.stdin); assert len(d)==1; print(d[0]["session_id"])')"
ip netns exec "$ns_a" ip l2tp del session tunnel_id "$tunnel_id" session_id "$session_id"
ip netns exec "$ns_a" ip l2tp del tunnel tunnel_id "$tunnel_id"
run_engine a restore
run_engine a check
ip netns exec "$ns_a" ping -n -q -I 10.253.115.1 -c 4 -i 0.2 -W 2 10.253.115.2
echo "L2TPV3_MULTILINK_SAME_PUBLIC_UNDERLAY"
run_engine a ensure secondary
run_engine b ensure secondary
run_engine a check secondary
run_engine b check secondary
ip netns exec "$ns_a" ping -n -q -I 10.253.116.1 -c 3 -i 0.2 -W 2 10.253.116.2
ip netns exec "$ns_b" ping -n -q -I 10.253.116.2 -c 3 -i 0.2 -W 2 10.253.116.1
echo "L2TPV3_REMOVE_FIRST_LINK_SECOND_MUST_SURVIVE"
run_engine a remove
run_engine b remove
run_engine a check secondary
run_engine b check secondary
ip netns exec "$ns_a" ping -n -q -I 10.253.116.1 -c 3 -i 0.2 -W 2 10.253.116.2
ip netns exec "$ns_b" ping -n -q -I 10.253.116.2 -c 3 -i 0.2 -W 2 10.253.116.1
run_engine a remove secondary
run_engine b remove secondary
for ns in "$ns_a" "$ns_b"; do
  [[ "$(ip netns exec "$ns" ip -json l2tp show tunnel)" == "[]" ]] || exit 7
  [[ "$(ip netns exec "$ns" ip -json l2tp show session)" == "[]" ]] || exit 8
  if ip -n "$ns" link show sl21234567890ab >/dev/null 2>&1; then exit 9; fi
  if ip -n "$ns" link show sl2abcdefabcdef >/dev/null 2>&1; then exit 9; fi
  if ip -n "$ns" -4 route show | grep -E '10[.]253[.](115|116)[.]'; then exit 10; fi
  if ip netns exec "$ns" iptables -S INPUT | grep -E 'lnk_(1234567890abcdef1234567890abcdef|abcdefabcdefabcdefabcdefabcdefab)'; then exit 11; fi
done
echo "L2TPV3_REAL_TWO_PEER_KERNEL_ENGINE_E2E_PASS"
