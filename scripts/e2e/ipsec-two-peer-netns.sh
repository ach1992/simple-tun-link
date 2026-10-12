#!/usr/bin/env bash
# Real IKEv2/ESP/NAT-T proof using two disposable peers; NEVER use on a host.
# Caller must create a container with --network none and network-namespace caps.
set -euo pipefail
umask 077
if [ "$STL_E2E_DISPOSABLE_HOST" != approved ] ||
   [ "$STL_IPSEC_ISOLATED" != approved ] ||
   [ "$(id -u)" -ne 0 ] ||
   [ ! -f /.dockerenv ] ||
   [ -n "$(ip -4 route show default)" ]; then
  echo "ERROR: disconnected disposable container with explicit authorization required" >&2
  exit 2
fi
case "$STL_IPSEC_CASE" in single|multi|mismatch|conflict|restart) ;; *) echo "invalid lab case" >&2; exit 2 ;; esac
case "$STL_IPSEC_ENCAP" in esp|nat-t) ;; *) echo "invalid encapsulation" >&2; exit 2 ;; esac

work=/run/stl-ipsec-proof
mkdir -m 0700 -p "$work"
cleanup() {
  for side in a b; do
    if [ -f "$work/$side.pid" ]; then
      kill "$(cat "$work/$side.pid")" 2>/dev/null || true
      wait "$(cat "$work/$side.pid")" 2>/dev/null || true
    fi
  done
  ip netns delete stl-ipsec-a 2>/dev/null || true
  ip netns delete stl-ipsec-b 2>/dev/null || true
  rm -f "$work/"*.secret "$work/"*.conf
}
trap cleanup EXIT
for suffix in a b; do
  head -c 32 /dev/urandom > "$work/$suffix.secret"
done
head -c 32 /dev/urandom > "$work/b-mismatch.secret"
ip netns add stl-ipsec-a
ip netns add stl-ipsec-b
ip link add v-stl-a type veth peer name v-stl-b
ip link set v-stl-a netns stl-ipsec-a
ip link set v-stl-b netns stl-ipsec-b
for side in a b; do ip -n stl-ipsec-$side link set lo up; done
ip -n stl-ipsec-a addr add 192.0.2.1/30 dev v-stl-a
ip -n stl-ipsec-b addr add 192.0.2.2/30 dev v-stl-b
ip -n stl-ipsec-a link set v-stl-a up
ip -n stl-ipsec-b link set v-stl-b up
ip netns exec stl-ipsec-a ping -n -q -c 1 -W 2 192.0.2.2 >/dev/null
echo "UNDERLAY_BIDIRECTIONAL_PRECONDITION=PASS"
for side in a b; do
  conf="$work/$side.conf"
  cat > "$conf" <<CONFIG
charon {
 install_routes = no
 install_virtual_ip = no
}
charon-systemd {
 install_routes = no
 install_virtual_ip = no
 journal {
  default = 1
  cfg = 1
 }
 plugins {
  vici {
   socket = unix:///run/stl-ipsec-proof/$side.vici
  }
 }
}
CONFIG
done
start_owned_peer() {
  local side=$1 count
  ip netns exec stl-ipsec-$side env STRONGSWAN_CONF="$work/$side.conf" /usr/sbin/charon-systemd > "$work/$side.log" 2>&1 &
  echo $! > "$work/$side.pid"
  for count in $(seq 1 100); do
    if [ -S "$work/$side.vici" ]; then break; fi
    sleep .1
  done
  if [ ! -S "$work/$side.vici" ] || ! kill -0 "$(cat "$work/$side.pid")" 2>/dev/null; then
    echo "ERROR: isolated strongSwan peer failed to start" >&2; exit 1
  fi
}
for side in a b; do start_owned_peer "$side"; done
echo "SEPARATE_STRONGSWAN_VICI_ENDPOINTS=2"

link_iface() { printf 'stlx%s' "$(printf '%011s' "$1" | tr ' ' "$1")"; }
link_addresses() {
  case "$1" in
    a) addr_a=10.251.88.0; addr_b=10.251.88.1 ;;
    b) addr_a=10.251.88.2; addr_b=10.251.88.3 ;;
    *) return 2 ;;
  esac
}
vici_op() {
  local operation=$1 side=$2 suffix=$3
  /usr/local/bin/stl-ipsec-probe "$operation" "$work/$side.vici" "$side" "$STL_IPSEC_ENCAP" "$suffix"
}
prepare_link() {
  local suffix=$1 id_hex ifid ifname side ipaddr
  id_hex=$(printf '%032s' "$suffix" | tr ' ' "$suffix")
  ifid=$(printf 'stl/ipsec/xfrm/v1/%s' "$id_hex" | sha256sum | cut -c1-8)
  ifid=$((16#$ifid))
  ifname=$(link_iface "$suffix")
  link_addresses "$suffix"
  for side in a b; do
    ipaddr=$addr_a; if [ "$side" = b ]; then ipaddr=$addr_b; fi
    ip -n stl-ipsec-$side link add "$ifname" type xfrm dev "v-stl-$side" if_id "$ifid"
    ip -n stl-ipsec-$side link set "$ifname" up
    ip -n stl-ipsec-$side addr add "$ipaddr/31" dev "$ifname"
  done
  for side in a b; do vici_op load "$side" "$suffix"; done
}
initiate_link() { vici_op initiate a "$1"; }
assert_no_plaintext_path() {
  local suffix=$1
  link_addresses "$suffix"
  if ip netns exec stl-ipsec-a ping -n -q -I "$addr_a" -c 1 -W 1 "$addr_b" >/dev/null 2>&1; then
    echo "ERROR: Link Address traffic passed without negotiated protection" >&2
    exit 1
  fi
  echo "LINK_${suffix}_NO_UNPROTECTED_TRAFFIC=PASS"
}
ping_link() {
  local suffix=$1
  link_addresses "$suffix"
  ip netns exec stl-ipsec-a ping -n -q -I "$addr_a" -c 3 -W 2 "$addr_b"
  ip netns exec stl-ipsec-b ping -n -q -I "$addr_b" -c 3 -W 2 "$addr_a"
  echo "BIDIRECTIONAL_LINK_$suffix=PASS"
}
reapply_link() {
  local suffix=$1 side
  for side in a b; do
    vici_op reapply "$side" "$suffix"
  done
  echo "NO_REPLACE_REAPPLY_LINK_$suffix=PASS"
}
remove_link() {
  local suffix=$1 side
  vici_op terminate a "$suffix"
  for side in a b; do
    vici_op unload "$side" "$suffix"
    vici_op assert-absent "$side" "$suffix"
    ip -n stl-ipsec-$side link delete "$(link_iface "$suffix")"
  done
  echo "SCOPED_REMOVE_LINK_$suffix=PASS"
}
check_sas() {
  local expected=$1 side actual
  for side in a b; do
    actual=$(ip -n stl-ipsec-$side xfrm state | grep -c 'proto esp' || true)
    [ "$actual" = "$expected" ] ||
      { echo "ERROR: unexpected ESP SA count on $side, wanted $expected got $actual" >&2; exit 1; }
  done
}
check_natt() {
  [ "$STL_IPSEC_ENCAP" != nat-t ] && return 0
  local side cnt
  for side in a b; do
    cnt=$(ip -n stl-ipsec-$side xfrm state | grep -c 'encap type espinudp' || true)
    if [ "$cnt" -lt 2 ]; then
      echo "ERROR: actual ESP-in-UDP XFRM encap missing on $side" >&2; exit 1
    fi
  done
  echo "REAL_NATT_XFRM_ENCAPSULATION=PASS"
}

prepare_link a
assert_no_plaintext_path a
initiate_link a
ping_link a
check_sas 2
check_natt
reapply_link a
ping_link a
case "$STL_IPSEC_CASE" in
  single)
    remove_link a
    check_sas 0
    echo "REAL_IPSEC_SINGLE_LIFECYCLE=PASS"
    ;;
  multi)
    prepare_link b
    assert_no_plaintext_path b
    initiate_link b
    ping_link b
    check_sas 4
    check_natt
    remove_link a
    check_sas 2
    ping_link b
    reapply_link b
    remove_link b
    check_sas 0
    echo "REAL_IPSEC_SIBLING_PRESERVATION=PASS"
    ;;
  conflict)
    # Existing matching object must not be overwritten by any load path,
    # even when it has canonical STL-looking names. Name != ownership.
    if vici_op load a a; then
      echo "ERROR: preexisting daemon object was silently replaced" >&2; exit 1
    fi
    vici_op check a a
    ping_link a
    remove_link a
    check_sas 0
    echo "REAL_IPSEC_EXISTING_VICI_OBJECT_REJECTION=PASS"
    ;;
  restart)
    for side in a b; do
      kill "$(cat "$work/$side.pid")"
      wait "$(cat "$work/$side.pid")" 2>/dev/null || true
      if [ -S "$work/$side.vici" ]; then
        echo "ERROR: owned daemon left an ambiguous stale VICI endpoint" >&2; exit 1
      fi
    done
    # Kernel interface identity and protected test credential survive process
    # death; daemon-only in-memory connection/PSK objects do not.
    for side in a b; do start_owned_peer "$side"; done
    for side in a b; do vici_op load "$side" a; done
    initiate_link a
    ping_link a
    check_sas 2
    remove_link a
    check_sas 0
    echo "REAL_IPSEC_DAEMON_RESTART_RESTORE=PASS"
    ;;
  mismatch)
    export STL_IPSEC_MISMATCH_LINK=b
    prepare_link b
    if vici_op initiate a b; then
      echo "ERROR: mismatched PSK unexpectedly established IKEv2" >&2; exit 1
    fi
    # A failed child negotiation must not tear down the healthy sibling.
    check_sas 2
    ping_link a
    for side in a b; do
      vici_op unload "$side" b
      vici_op assert-absent "$side" b
      ip -n stl-ipsec-$side link delete "$(link_iface b)"
    done
    check_sas 2
    remove_link a
    check_sas 0
    echo "REAL_IPSEC_CREDENTIAL_MISMATCH_ISOLATED=PASS"
    ;;
esac
echo "REAL_IPSEC_E2E=PASS case=$STL_IPSEC_CASE encapsulation=$STL_IPSEC_ENCAP"
