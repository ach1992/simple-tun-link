#!/usr/bin/env bash
# Explicitly privileged acceptance: execute only on an owner-approved,
# disposable Linux test VM. Never run on a shared host/control plane.
set -Eeuo pipefail
umask 077

if [[ "${STL_E2E_DISPOSABLE_HOST:-}" != "approved" ]]; then
  echo "REFUSED: requires explicit approved disposable host (STL_E2E_DISPOSABLE_HOST=approved)" >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo "REFUSED: network namespace acceptance requires root on the disposable host" >&2
  exit 2
fi
for tool in go ip ping iptables mktemp sha256sum git; do
  command -v "$tool" >/dev/null || { echo "Missing test prerequisite: $tool" >&2; exit 2; }
done

source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
test -f "$source_root/go.mod" || { echo "Source tree/go.mod not found" >&2; exit 2; }
cd "$source_root"
if [[ -n "$(git status --porcelain)" ]]; then
  echo "REFUSED: uncommitted/untracked source would invalidate recorded test SHA" >&2
  exit 2
fi

# Use only a fresh runner-owned directory and fresh namespaces.
workdir="$(mktemp -d /tmp/stl-gre-e2e.XXXXXXXX)"
suffix="${workdir##*.}"
ns_a="stlg${suffix}a"
ns_b="stlg${suffix}b"
created_a=0
created_b=0
host_default_before="$(ip -4 route show default)"

cleanup() {
  local status="$1"
  trap - EXIT INT TERM
  set +e
  if (( created_b )); then
    ip netns delete "$ns_b" || { echo "FAILED to delete owned namespace $ns_b" >&2; status=1; }
  fi
  if (( created_a )); then
    ip netns delete "$ns_a" || { echo "FAILED to delete owned namespace $ns_a" >&2; status=1; }
  fi
  if [[ "$(ip -4 route show default)" != "$host_default_before" ]]; then
    echo "HOST_DEFAULT_ROUTE_CHANGED: stop and investigate (never auto-restore)" >&2
    status=1
  fi
  if [[ "$workdir" == /tmp/stl-gre-e2e.* && -d "$workdir" ]]; then
    rm -rf -- "$workdir" || status=1
  fi
  echo "GRE_E2E_CLEANUP_EXIT=$status"
  exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ip netns list | awk '{ print $1 }' | grep -Fxe "$ns_a" -e "$ns_b" >/dev/null; then
  echo "REFUSED: test namespace name is already in use" >&2
  exit 2
fi
mkdir -m 0700 "$workdir/a" "$workdir/b"

printf 'TEST_SOURCE_SHA=%s\n' "$(git rev-parse HEAD)"
printf 'VERSIONS kernel=%s iproute=%s iptables=%s go=%s\n' \
  "$(uname -r)" "$(ip -Version)" "$(iptables --version)" "$(go version)"
echo "REQUIRE_ALL_MODES=native,fou,gue (unsupported capability is a failure, not a pass)"

# No module installation, modprobe, host firewall changes or external peers.
# GOTOOLCHAIN=local refuses an unexpected network toolchain download.
GOTOOLCHAIN=local go test -c -o "$workdir/gre-e2e.test" ./cmd/stl
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
ip netns exec "$ns_a" ping -n -c 1 -W 2 -I 192.0.2.10 192.0.2.11 >/dev/null
ip netns exec "$ns_b" ping -n -c 1 -W 2 -I 192.0.2.11 192.0.2.10 >/dev/null
echo "SYNTHETIC_UNDERLAY_BIDIRECTIONAL=PASS"

run_side() {
  local side="$1" action="$2"
  local ns local_ul peer_ul local_link peer_link state_root
  if [[ "$side" == a ]]; then
    ns="$ns_a"
    local_ul=192.0.2.10; peer_ul=192.0.2.11
    local_link="10.81.$octet.0/31"; peer_link="10.81.$octet.1/31"
    state_root="$workdir/a"
  else
    ns="$ns_b"
    local_ul=192.0.2.11; peer_ul=192.0.2.10
    local_link="10.81.$octet.1/31"; peer_link="10.81.$octet.0/31"
    state_root="$workdir/b"
  fi
  ip netns exec "$ns" env \
    STL_GRE_NETNS_E2E=1 \
    STL_GRE_E2E_ACTION="$action" \
    STL_GRE_E2E_STATE_ROOT="$state_root" \
    STL_GRE_E2E_ID="$link_id" \
    STL_GRE_E2E_ENCAP="$mode" \
    STL_GRE_E2E_KEY="$key" \
    STL_GRE_E2E_UL_LOCAL="$local_ul" \
    STL_GRE_E2E_UL_PEER="$peer_ul" \
    STL_GRE_E2E_LINK_LOCAL="$local_link" \
    STL_GRE_E2E_LINK_PEER="$peer_link" \
    STL_GRE_E2E_PORT="$port" \
    "$workdir/gre-e2e.test" -test.run '^TestGRENetnsE2E$' -test.v
}

traffic() {
  ip netns exec "$ns_a" ping -n -c 2 -W 2 -I "10.81.$octet.0" "10.81.$octet.1" >/dev/null
  ip netns exec "$ns_b" ping -n -c 2 -W 2 -I "10.81.$octet.1" "10.81.$octet.0" >/dev/null
  printf 'GRE_%s_BIDIRECTIONAL=PASS\n' "$mode"
}

# Three independent GRE links to the exact same A/B underlay pair: Native,
# FOU and GUE must remain address-/resource-isolated. Full cross-backend
# GRE + WireGuard coexistence and systemd restart remain later #12 gates.
select_mode() {
  mode=$1
  case "$mode" in
    native) link_id=lnk_11111111111111111111111111111111; octet=20; port=0; key="" ;;
    fou)    link_id=lnk_22222222222222222222222222222222; octet=30; port=33061; key=33061 ;;
    gue)    link_id=lnk_33333333333333333333333333333333; octet=40; port=33062; key=33062 ;;
    *) echo "invalid test mode" >&2; exit 2 ;;
  esac
}

for selected_mode in native fou gue; do
  select_mode "$selected_mode"
  echo "BEGIN_GRE_MODE=$mode"
  run_side a ensure
  run_side b ensure
  run_side a reensure
  run_side b reensure
  run_side a status
  run_side b status
  traffic
  run_side a diagnose
  run_side b diagnose
  echo "GRE_MODE_READY=$mode"
  if [[ "$mode" == native ]]; then
    # Same peer pair AND absent GRE key is ambiguous even if UDP encapsulation
    # differs. Reject before any FOU receive mapping/other kernel mutation.
    select_mode fou
    key=""
    run_side a conflict
    if [[ "$(ip netns exec "$ns_a" ip -json fou show)" != "[]" ]]; then
      echo "failed GRE request leaked an owned receive mapping" >&2
      exit 1
    fi
    select_mode native
    traffic
    echo "GRE_UNKEYED_RECEIVE_CONFLICT_REJECTED=PASS"
  fi
done

for selected_mode in native fou gue; do
  select_mode "$selected_mode"
  traffic
done
echo "GRE_SAME_UNDERLAY_MULTI_LINK=PASS"

# Extend the SAME disposable two-namespace topology with IPIP acceptance.
# This is a release-level cross-backend proof, not a parallel host networking
# harness. Linux IPIP endpoint-pair lookup forbids simultaneous IPIP modes
# with the same underlay pair, so IPIP modes run sequentially. The full GRE
# trio remains live and must survive every IPIP operation.
echo "REQUIRE_ALL_IPIP_MODES=native,fou,gue (unsupported capability is a failure, not a pass)"

run_ipip_side() {
  local side="$1" action="$2"
  local ns local_ul peer_ul local_link peer_link state_root
  if [[ "$side" == a ]]; then
    ns="$ns_a"
    local_ul=192.0.2.10; peer_ul=192.0.2.11
    local_link="10.82.$ipip_octet.0/31"; peer_link="10.82.$ipip_octet.1/31"
    state_root="$workdir/a"
  else
    ns="$ns_b"
    local_ul=192.0.2.11; peer_ul=192.0.2.10
    local_link="10.82.$ipip_octet.1/31"; peer_link="10.82.$ipip_octet.0/31"
    state_root="$workdir/b"
  fi
  ip netns exec "$ns" env \
    STL_IPIP_NETNS_E2E=1 \
    STL_IPIP_E2E_ACTION="$action" \
    STL_IPIP_E2E_STATE_ROOT="$state_root" \
    STL_IPIP_E2E_ID="$ipip_id" \
    STL_IPIP_E2E_ENCAP="$ipip_mode" \
    STL_IPIP_E2E_UL_LOCAL="$local_ul" \
    STL_IPIP_E2E_UL_PEER="$peer_ul" \
    STL_IPIP_E2E_LINK_LOCAL="$local_link" \
    STL_IPIP_E2E_LINK_PEER="$peer_link" \
    "$workdir/gre-e2e.test" -test.run '^TestIPIPNetnsE2E$' -test.v
}

select_ipip_mode() {
  ipip_mode="$1"
  case "$ipip_mode" in
    native) ipip_id=lnk_44444444444444444444444444444444; ipip_octet=50 ;;
    fou)    ipip_id=lnk_55555555555555555555555555555555; ipip_octet=60 ;;
    gue)    ipip_id=lnk_66666666666666666666666666666666; ipip_octet=70 ;;
    *) echo "invalid IPIP test mode" >&2; exit 2 ;;
  esac
}

ipip_traffic() {
  ip netns exec "$ns_a" ping -n -c 2 -W 2 -I "10.82.$ipip_octet.0" "10.82.$ipip_octet.1" >/dev/null
  ip netns exec "$ns_b" ping -n -c 2 -W 2 -I "10.82.$ipip_octet.1" "10.82.$ipip_octet.0" >/dev/null
  printf 'IPIP_%s_BIDIRECTIONAL=PASS\n' "$ipip_mode"
}

# Snapshot only exact STL-owned INPUT rules. Do not compare or mutate
# unrelated administrator rules. The comment format is defined by
# internal/linux/firewall.go: stl:<lnk_32hex>:<sha256_first_8_bytes>.
stl_owned_input_rules() {
  local ns="$1" listing line
  local marker='(^|[[:space:]])--comment[[:space:]]"?stl:lnk_[0-9a-f]{32}:[0-9a-f]{16}"?([[:space:]]|$)'
  listing="$(ip netns exec "$ns" iptables -w 5 -S INPUT)" || return 1
  while IFS= read -r line; do
    if [[ $line =~ $marker ]]; then
      printf '%s\n' "$line"
    fi
  done <<< "$listing" | LC_ALL=C sort
}

gre_owned_ids=(
  lnk_11111111111111111111111111111111
  lnk_22222222222222222222222222222222
  lnk_33333333333333333333333333333333
)

gre_only_input_rules() {
  local line id
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    for id in "${gre_owned_ids[@]}"; do
      if [[ $line == *"stl:${id}:"* ]]; then
        printf '%s\n' "$line"
        break
      fi
    done
  done <<< "$1" | LC_ALL=C sort
}

require_gre_firewall_baseline() {
  local ns="$1" owned id matches
  owned="$(stl_owned_input_rules "$ns")" || return 1
  [[ $(printf '%s\n' "$owned" | wc -l) -eq 3 ]] || {
    echo "FAIL: expected exactly three STL-owned GRE INPUT rules in $ns" >&2
    return 1
  }
  for id in "${gre_owned_ids[@]}"; do
    matches="$(grep -Fc -- "stl:${id}:" <<< "$owned" || true)"
    [[ $matches -eq 1 ]] || {
      echo "FAIL: GRE Link $id does not own exactly one INPUT rule in $ns" >&2
      return 1
    }
  done
  printf '%s\n' "$owned"
}

assert_gre_firewall_unchanged() {
  local ns all gre expected
  for ns in "$ns_a" "$ns_b"; do
    all="$(stl_owned_input_rules "$ns")" || return 1
    gre="$(gre_only_input_rules "$all")"
    if [[ $ns == "$ns_a" ]]; then
      expected="$gre_firewall_a"
    else
      expected="$gre_firewall_b"
    fi
    [[ $gre == "$expected" ]] || {
      echo "FAIL: IPIP operation changed a GRE-owned INPUT firewall rule in $ns" >&2
      return 1
    }
  done
}

assert_stl_firewall_rule_count() {
  local ns="$1" id="$2" expected="$3" all count
  all="$(stl_owned_input_rules "$ns")" || return 1
  count="$(grep -Fc -- "stl:${id}:" <<< "$all" || true)"
  [[ $count -eq $expected ]] || {
    echo "FAIL: expected $expected STL-owned INPUT rules for $id in $ns; found $count" >&2
    return 1
  }
}

# The baseline is established AFTER all three GRE modes have been created.
# It must contain exactly one real owned rule for each Link, on both sides.
gre_firewall_a="$(require_gre_firewall_baseline "$ns_a")" || exit 1
gre_firewall_b="$(require_gre_firewall_baseline "$ns_b")" || exit 1
gre_fou_a="$(ip netns exec "$ns_a" ip -json fou show)"
gre_fou_b="$(ip netns exec "$ns_b" ip -json fou show)"

# Optional release-level real cross-backend acceptance in the SAME source,
# namespace pair and state roots as GRE Native + FOU + GUE. This is an
# explicit opt-in, not a silent skipped part of the GRE/IPIP-only E2E.
if [[ -v STL_E2E_CROSS_WG && "$STL_E2E_CROSS_WG" == approved ]]; then
  command -v wg >/dev/null || { echo 'MISSING CROSS_WG PREREQUISITE=wg' >&2; exit 2; }
  wg_id=lnk_88888888888888888888888888888888
  run_cross_wg_side() {
    local side="$1" action="$2" ns root
    if [[ "$side" == a ]]; then
      ns="$ns_a"; root="$workdir/a"
    else
      ns="$ns_b"; root="$workdir/b"
    fi
    ip netns exec "$ns" env \
      STL_WG_NETNS_E2E=1 \
      STL_WG_CROSS_E2E=1 \
      STL_WG_E2E_ACTION="$action" \
      STL_WG_E2E_STATE_ROOT="$root" \
      "$workdir/gre-e2e.test" -test.run '^TestWireGuardNetnsE2E$' -test.v
  }
  run_cross_wg_side a create
  run_cross_wg_side b import
  run_cross_wg_side a resume
  assert_stl_firewall_rule_count "$ns_a" "$wg_id" 1
  assert_stl_firewall_rule_count "$ns_b" "$wg_id" 1
  ip netns exec "$ns_a" ping -n -c 3 -W 3 -I 10.83.10.0 10.83.10.1 >/dev/null
  ip netns exec "$ns_b" ping -n -c 3 -W 3 -I 10.83.10.1 10.83.10.0 >/dev/null
  echo 'CROSS_WG_BIDIRECTIONAL_ENCRYPTED=PASS'
  run_cross_wg_side a status
  run_cross_wg_side b status
  run_cross_wg_side a diagnose
  run_cross_wg_side b diagnose
  assert_gre_firewall_unchanged
  [[ "$(ip netns exec "$ns_a" ip -json fou show)" == "$gre_fou_a" &&
     "$(ip netns exec "$ns_b" ip -json fou show)" == "$gre_fou_b" ]] || {
    echo 'FAIL: WireGuard changed a GRE FOU/GUE receive mapping' >&2; exit 1;
  }
  for gre_mode in native fou gue; do
    select_mode "$gre_mode"; traffic
  done
  echo 'GRE_NATIVE_FOU_GUE_WG_SAME_PEER_CONCURRENT=PASS'
  run_cross_wg_side a remove
  run_cross_wg_side b remove
  assert_stl_firewall_rule_count "$ns_a" "$wg_id" 0
  assert_stl_firewall_rule_count "$ns_b" "$wg_id" 0
  assert_gre_firewall_unchanged
  run_cross_wg_side a retire
  run_cross_wg_side b retire
  run_cross_wg_side a list
  run_cross_wg_side b list
  for ns in "$ns_a" "$ns_b"; do
    if ip netns exec "$ns" wg show interfaces | grep -F 'stlwg8888888888'; then
      echo 'FAIL: removed WireGuard interface survived cross-backend test' >&2; exit 1
    fi
  done
  for gre_mode in native fou gue; do
    select_mode "$gre_mode"; traffic
  done
  echo 'CROSS_WG_REMOVE_RETIRES_ONLY_OWN_RESOURCES=PASS'
else
  echo 'GRE_IPIP_CROSS_WG=SKIP (set STL_E2E_CROSS_WG=approved)'
fi

for selected_ipip_mode in native fou gue; do
  select_ipip_mode "$selected_ipip_mode"
  echo "BEGIN_IPIP_MODE=$ipip_mode"
  run_ipip_side a ensure
  run_ipip_side b ensure
  # Verify IPIP owns a distinct INPUT rule while all GRE rules stay intact.
  assert_stl_firewall_rule_count "$ns_a" "$ipip_id" 1
  assert_stl_firewall_rule_count "$ns_b" "$ipip_id" 1
  assert_gre_firewall_unchanged
  run_ipip_side a reensure
  run_ipip_side b reensure
  run_ipip_side a status
  run_ipip_side b status
  ipip_traffic
  run_ipip_side a diagnose
  run_ipip_side b diagnose

  if [[ "$ipip_mode" == native ]]; then
    # A second IPIP mode with the same peer pair must be rejected before
    # installing a UDP receive mapping or changing the existing IPIP link.
    ipip_mode=fou; ipip_id=lnk_77777777777777777777777777777777; ipip_octet=99
    run_ipip_side a conflict
    assert_gre_firewall_unchanged
    # A rejected same-underlay Link has no right to an INPUT allow rule.
    assert_stl_firewall_rule_count "$ns_a" "$ipip_id" 0
    [[ "$(ip netns exec "$ns_a" ip -json fou show)" == "$gre_fou_a" ]] || {
      echo "IPIP endpoint conflict leaked a FOU mapping" >&2; exit 1;
    }
    select_ipip_mode native
    ipip_traffic
    echo "IPIP_SAME_UNDERLAY_SECOND_MODE_REJECTED=PASS"
  fi

  run_ipip_side a remove
  run_ipip_side b remove
  # Retire only selected IPIP INPUT rule; GRE ownership remains byte-identical.
  assert_stl_firewall_rule_count "$ns_a" "$ipip_id" 0
  assert_stl_firewall_rule_count "$ns_b" "$ipip_id" 0
  assert_gre_firewall_unchanged
  run_ipip_side a list
  run_ipip_side b list
  for ns in "$ns_a" "$ns_b"; do
    if ip -n "$ns" -d link show type ipip | grep -F 'alias stl:lnk_'; then
      echo "FAIL: owned IPIP interface survived removal in $ns" >&2
      exit 1
    fi
  done
  [[ "$(ip netns exec "$ns_a" ip -json fou show)" == "$gre_fou_a" &&
     "$(ip netns exec "$ns_b" ip -json fou show)" == "$gre_fou_b" ]] || {
    echo "FAIL: IPIP cleanup changed existing GRE FOU/GUE receive mappings" >&2; exit 1;
  }
  for gre_mode in native fou gue; do
    select_mode "$gre_mode"
    traffic
  done
  echo "IPIP_MODE_CLEAN_AND_GRE_SIBLINGS_HEALTHY=$selected_ipip_mode"
done
echo "IPIP_NATIVE_FOU_GUE_AND_GRE_COEXISTENCE=PASS"

select_mode fou
run_side a remove
run_side b remove
for selected_mode in native gue; do
  select_mode "$selected_mode"
  run_side a status
  run_side b status
  traffic
done
echo "GRE_SIBLING_TRAFFIC_SURVIVES_FOU_REMOVE=PASS"

for selected_mode in native gue; do
  select_mode "$selected_mode"
  run_side a remove
  run_side b remove
done

# Confirm no Link desired state, owned interface, FOU mapping or firewall rule
# remains inside either fresh namespace. Never inspect/remove foreign resources.
for side in a b; do
  mode=native; link_id=lnk_11111111111111111111111111111111; octet=20; port=0
  run_side "$side" list
done
for ns in "$ns_a" "$ns_b"; do
  if ip -n "$ns" -d link show | grep -F 'alias stl:lnk_'; then
    echo "FAIL: owned interface survived removal in $ns" >&2
    exit 1
  fi
  mappings="$(ip netns exec "$ns" ip -json fou show)"
  if [[ "$mappings" != "[]" ]]; then
    echo "FAIL: FOU/GUE mapping survived removal in $ns: $mappings" >&2
    exit 1
  fi
  if ip netns exec "$ns" iptables -S INPUT | grep -F 'stl:'; then
    echo "FAIL: owned firewall rule survived removal in $ns" >&2
    exit 1
  fi
done

echo "GRE_NATIVE_FOU_GUE_E2E=PASS"
echo "GRE_IPIP_DISPOSABLE_CROSS_BACKEND_E2E=PASS"
