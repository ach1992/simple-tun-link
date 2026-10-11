#!/usr/bin/env bash
# Privileged multi-peer acceptance only inside a dedicated disposable test host.
# Never changes host interfaces, routes, firewall, services or kernel modules.
set -Eeuo pipefail
umask 077
if [[ "${STL_E2E_DISPOSABLE_HOST:-}" != approved || $EUID -ne 0 ]]; then
  echo "REFUSED: approved disposable host and root required" >&2; exit 2
fi
for tool in go ip iptables ping mktemp git; do
  command -v "$tool" >/dev/null || { echo "MISSING_PREREQUISITE=$tool" >&2; exit 2; }
done
source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$source_root"
[[ -f go.mod && -z "$(git status --porcelain)" ]] || {
  echo "REFUSED: source must be committed and clean" >&2; exit 2;
}
workdir="$(mktemp -d /tmp/stl-gre-multipeer.XXXXXXXX)"
suffix="${workdir##*.}"
ns_a="stlm${suffix}a"; ns_b="stlm${suffix}b"; ns_c="stlm${suffix}c"
created_a=0; created_b=0; created_c=0
host_route_before="$(ip -4 route show default)"
host_input_before="$(iptables -S INPUT)"
host_primary_if="$(ip -4 route show default | awk 'NR==1 {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')"
host_primary_before=""
if [[ -n "$host_primary_if" ]]; then
  host_primary_before="$(ip -json address show dev "$host_primary_if")"
fi
cleanup() {
  local status="$1" ns
  trap - EXIT INT TERM
  set +e
  if (( created_c )); then ip netns delete "$ns_c" || status=1; fi
  if (( created_b )); then ip netns delete "$ns_b" || status=1; fi
  if (( created_a )); then ip netns delete "$ns_a" || status=1; fi
  for ns in "$ns_a" "$ns_b" "$ns_c"; do
    if ip netns list | awk '{print $1}' | grep -Fxq -- "$ns"; then
      echo "FAIL: owned namespace remains: $ns" >&2; status=1
    fi
  done
  if [[ "$(ip -4 route show default)" != "$host_route_before" ||
        "$(iptables -S INPUT)" != "$host_input_before" ]]; then
    echo "FAIL: host default route or INPUT rules changed; do not auto-restore" >&2; status=1
  fi
  if [[ -n "$host_primary_if" &&
        "$(ip -json address show dev "$host_primary_if")" != "$host_primary_before" ]]; then
    echo "FAIL: host primary-interface addresses changed" >&2; status=1
  fi
  if [[ "$workdir" == /tmp/stl-gre-multipeer.* && -d "$workdir" ]]; then
    rm -rf -- "$workdir" || status=1
  fi
  echo "GRE_MULTI_PEER_CLEANUP_EXIT=$status"
  exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for ns in "$ns_a" "$ns_b" "$ns_c"; do
  if ip netns list | awk '{print $1}' | grep -Fxq -- "$ns"; then
    echo "REFUSED: namespace name is already in use" >&2; exit 2
  fi
done
mkdir -m 0700 "$workdir/a" "$workdir/b" "$workdir/c"
printf 'TEST_SOURCE_SHA=%s\n' "$(git rev-parse HEAD)"
printf 'VERSIONS kernel=%s iproute=%s iptables=%s go=%s\n' \
  "$(uname -r)" "$(ip -Version)" "$(iptables --version)" "$(go version)"
echo "SCOPE=GRE_NATIVE_THREE_PEERS_NO_SYSTEMD"
GOTOOLCHAIN=local go test -c -o "$workdir/gre-mpeer.test" ./cmd/stl
ip netns add "$ns_a"; created_a=1
ip netns add "$ns_b"; created_b=1
ip netns add "$ns_c"; created_c=1
ip -n "$ns_a" link add stlaba type veth peer name stlabb
ip -n "$ns_a" link set stlabb netns "$ns_b"
ip -n "$ns_a" link add stlaca type veth peer name stlacb
ip -n "$ns_a" link set stlacb netns "$ns_c"
ip -n "$ns_a" address add 192.0.2.10/31 dev stlaba
ip -n "$ns_b" address add 192.0.2.11/31 dev stlabb
ip -n "$ns_a" address add 192.0.2.20/31 dev stlaca
ip -n "$ns_c" address add 192.0.2.21/31 dev stlacb
for ns in "$ns_a" "$ns_b" "$ns_c"; do ip -n "$ns" link set lo up; done
ip -n "$ns_a" link set stlaba up
ip -n "$ns_b" link set stlabb up
ip -n "$ns_a" link set stlaca up
ip -n "$ns_c" link set stlacb up
ip netns exec "$ns_a" ping -n -c 1 -W 2 -I 192.0.2.10 192.0.2.11 >/dev/null
ip netns exec "$ns_b" ping -n -c 1 -W 2 -I 192.0.2.11 192.0.2.10 >/dev/null
ip netns exec "$ns_a" ping -n -c 1 -W 2 -I 192.0.2.20 192.0.2.21 >/dev/null
ip netns exec "$ns_c" ping -n -c 1 -W 2 -I 192.0.2.21 192.0.2.20 >/dev/null
echo "TWO_UNDERLAY_PAIRS_BIDIRECTIONAL=PASS"
ab_id=lnk_abababababababababababababababab
ac_id=lnk_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
run_side() {
  local side="$1" pair="$2" action="$3"
  local ns root id ul_local ul_peer link_local link_peer
  case "$side" in
    a) ns="$ns_a" ;; b) ns="$ns_b" ;; c) ns="$ns_c" ;;
    *) echo "invalid side" >&2; return 2 ;;
  esac
  root="$workdir/$side"
  case "$pair/$side" in
    ab/a) id="$ab_id"; ul_local=192.0.2.10; ul_peer=192.0.2.11; link_local=10.85.10.0/31; link_peer=10.85.10.1/31 ;;
    ab/b) id="$ab_id"; ul_local=192.0.2.11; ul_peer=192.0.2.10; link_local=10.85.10.1/31; link_peer=10.85.10.0/31 ;;
    ac/a) id="$ac_id"; ul_local=192.0.2.20; ul_peer=192.0.2.21; link_local=10.85.20.0/31; link_peer=10.85.20.1/31 ;;
    ac/c) id="$ac_id"; ul_local=192.0.2.21; ul_peer=192.0.2.20; link_local=10.85.20.1/31; link_peer=10.85.20.0/31 ;;
    *) echo "invalid side/pair" >&2; return 2 ;;
  esac
  ip netns exec "$ns" env \
    STL_GRE_NETNS_E2E=1 STL_GRE_MULTI_PEER_E2E=approved \
    STL_GRE_E2E_ACTION="$action" STL_GRE_E2E_STATE_ROOT="$root" \
    STL_GRE_E2E_ID="$id" STL_GRE_E2E_ENCAP=native STL_GRE_E2E_KEY= \
    STL_GRE_E2E_UL_LOCAL="$ul_local" STL_GRE_E2E_UL_PEER="$ul_peer" \
    STL_GRE_E2E_LINK_LOCAL="$link_local" STL_GRE_E2E_LINK_PEER="$link_peer" \
    STL_GRE_E2E_PORT=0 \
    "$workdir/gre-mpeer.test" -test.run '^TestGRENetnsE2E$' -test.v
}
traffic_pair() {
  local pair="$1"
  case "$pair" in
    ab)
      ip netns exec "$ns_a" ping -n -c 2 -W 2 -I 10.85.10.0 10.85.10.1 >/dev/null
      ip netns exec "$ns_b" ping -n -c 2 -W 2 -I 10.85.10.1 10.85.10.0 >/dev/null ;;
    ac)
      ip netns exec "$ns_a" ping -n -c 2 -W 2 -I 10.85.20.0 10.85.20.1 >/dev/null
      ip netns exec "$ns_c" ping -n -c 2 -W 2 -I 10.85.20.1 10.85.20.0 >/dev/null ;;
    *) return 2 ;;
  esac
  echo "GRE_${pair^^}_BIDIRECTIONAL=PASS"
}
owned_rule() {
  ip netns exec "$1" iptables -w 5 -S INPUT | grep -F -- "stl:$2:" || true
}
assert_rule_count() {
  local n
  n="$(owned_rule "$1" "$2" | wc -l)"
  if [[ "$n" != "$3" ]]; then
    echo "FAIL: expected $3 owned rules for $2; observed $n" >&2; exit 1
  fi
}
run_side a ab ensure
run_side b ab ensure
run_side a ac ensure
run_side c ac ensure
run_side a ab multi-list
run_side a ac status
run_side a ab status
run_side b ab multi-list
run_side c ac multi-list
run_side a ab reensure
run_side a ac reensure
run_side b ab reensure
run_side c ac reensure
traffic_pair ab
traffic_pair ac
run_side a ab diagnose
run_side b ab diagnose
run_side a ac diagnose
run_side c ac diagnose
assert_rule_count "$ns_a" "$ab_id" 1
assert_rule_count "$ns_a" "$ac_id" 1
assert_rule_count "$ns_b" "$ab_id" 1
assert_rule_count "$ns_c" "$ac_id" 1
ac_rule_a="$(owned_rule "$ns_a" "$ac_id")"
ac_rule_c="$(owned_rule "$ns_c" "$ac_id")"
echo "A_PERSISTED_TWO_DISTINCT_PEER_LINKS=PASS"
run_side a ab remove
run_side b ab remove
run_side a ac multi-survivor
run_side b ab multi-survivor
run_side c ac multi-survivor
assert_rule_count "$ns_a" "$ab_id" 0
assert_rule_count "$ns_b" "$ab_id" 0
[[ "$(owned_rule "$ns_a" "$ac_id")" == "$ac_rule_a" &&
   "$(owned_rule "$ns_c" "$ac_id")" == "$ac_rule_c" ]] || {
  echo "FAIL: removing A-B changed A-C firewall identity" >&2; exit 1;
}
run_side a ac reensure
run_side c ac reensure
run_side a ac status
run_side c ac status
traffic_pair ac
run_side a ac diagnose
run_side c ac diagnose
echo "REMOVE_AB_PRESERVES_AC_TRAFFIC_AND_OWNERSHIP=PASS"
run_side a ac remove
run_side c ac remove
run_side a ab list
run_side b ab list
run_side c ac list
for ns in "$ns_a" "$ns_b" "$ns_c"; do
  if ip -n "$ns" -d link show | grep -F "alias stl:lnk_"; then
    echo "FAIL: owned GRE interface survived remove" >&2; exit 1
  fi
  if ip netns exec "$ns" iptables -S INPUT | grep -F -- "stl:lnk_"; then
    echo "FAIL: owned firewall rule survived remove" >&2; exit 1
  fi
done
echo "GRE_MULTI_PEER_NATIVE_E2E=PASS"
