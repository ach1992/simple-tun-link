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
