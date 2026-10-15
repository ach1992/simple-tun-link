#!/usr/bin/env bash
# REAL native systemd STL host + isolated peer IKEv2 acceptance.
# Invoke ONLY inside disposable, network-disconnected systemd Docker fixture.
set -euo pipefail
umask 077
if [ "${STL_E2E_DISPOSABLE_HOST:-}" != approved ] ||
   [ "${STL_IPSEC_ISOLATED:-}" != approved ] ||
   [ "${STL_IPSEC_SYSTEMD_FIXTURE:-}" != approved ] ||
   [ "$(id -u)" != 0 ] || [ ! -f /.dockerenv ] ||
   [ "$(ps -p 1 -o comm= | tr -d ' ')" != systemd ] ||
   [ -n "$(ip -4 route show default)" ]; then
  echo "ERROR: requires explicitly approved, disconnected PID1-systemd container" >&2
  exit 2
fi
case "${STL_IPSEC_ENCAP:-}" in esp|nat-t) ;; *)
  echo "ERROR: expected esp or nat-t encapsulation" >&2; exit 2 ;; esac
encap=$STL_IPSEC_ENCAP
work=/run/stl-ipsec-proof
mkdir -m 0700 -p "$work"
[ "$(stat -c %a "$work")" = 700 ] || { echo "ERROR: private fixture path unsafe" >&2; exit 2; }
[ "$(systemctl is-active simple-tun-link-ipsec.service)" = active ] ||
  { echo "ERROR: native STL unit unavailable" >&2; exit 2; }
[ "$(systemctl is-enabled strongswan.service)" = disabled ] ||
  { echo "ERROR: vendor strongSwan unit not explicitly disabled" >&2; exit 2; }
if ip netns list | grep -q '^stl-ipsec-native-b '; then
  echo "ERROR: fixture namespace already exists, no adoption" >&2; exit 2
fi
if ip link show v-stl-native >/dev/null 2>&1; then
  echo "ERROR: fixture underlay already exists, no adoption" >&2; exit 2
fi
for bin in /usr/local/bin/stl /usr/local/bin/stl-ipsec-cli-test /usr/local/bin/stl-ipsec-probe; do
  [ -x "$bin" ] || { echo "ERROR: fixture test binary missing" >&2; exit 2; }
done
cleanup() {
  if [ -f "$work/b.pid" ]; then
    kill "$(cat "$work/b.pid")" 2>/dev/null || true
    wait "$(cat "$work/b.pid")" 2>/dev/null || true
  fi
  ip netns delete stl-ipsec-native-b 2>/dev/null || true
  ip link delete v-stl-native 2>/dev/null || true
}
trap cleanup EXIT
ip netns add stl-ipsec-native-b
ip link add v-stl-native type veth peer name v-stl-peer
ip link set v-stl-peer netns stl-ipsec-native-b
ip addr add 192.0.2.1/30 dev v-stl-native
ip link set v-stl-native up
ip -n stl-ipsec-native-b addr add 192.0.2.2/30 dev v-stl-peer
ip -n stl-ipsec-native-b link set v-stl-peer up
ip -n stl-ipsec-native-b link set lo up
ip netns exec stl-ipsec-native-b ping -n -q -c 1 -W 2 192.0.2.1 >/dev/null
cat > "$work/b.conf" <<CONFIG
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
   socket = unix:///run/stl-ipsec-proof/b.vici
  }
 }
}
CONFIG
ip netns exec stl-ipsec-native-b env STRONGSWAN_CONF="$work/b.conf" /usr/sbin/charon-systemd >"$work/b.log" 2>&1 &
echo $! >"$work/b.pid"
for attempt in $(seq 1 100); do
  [ -S "$work/b.vici" ] && break
  sleep .1
done
if [ ! -S "$work/b.vici" ] || ! kill -0 "$(cat "$work/b.pid")" 2>/dev/null; then
  echo "ERROR: isolated second peer did not start" >&2; exit 1
fi
echo "DISPOSABLE_NATIVE_STL_SYSTEMD_PEER_READY=PASS"
doctor=$(/usr/local/bin/stl doctor ipsec --json)
echo "$doctor" | grep -q '"activation_allowed":true' ||
  { echo "ERROR: native-exclusive service was not admitted with unrelated netns peer" >&2; exit 1; }
echo "NATIVE_SYSTEMD_AFTER_PEER_ADMISSION=PASS"
link=lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if ! native_create_out=$(printf '{"schema_version":1,"link_id":"%s","underlay":{"local":"192.0.2.1","peer":"192.0.2.2"},"addresses":{"local":"10.251.88.0/31","peer":"10.251.88.1/31"},"encapsulation":"%s"}\n' "$link" "$encap" |
  /usr/local/bin/stl link create-ipsec --stdin --output "$work/a.cli-handoff" --json); then
  # The versioned CLI error contains no PSK or sensitive handoff URL.
  printf 'NATIVE_CREATE_PUBLIC_ERROR=%s\n' "$native_create_out" >&2
  echo "ERROR: native CLI sender create failed" >&2
  exit 1
fi
printf '%s\n' "$native_create_out" | grep -q '"changed":true' ||
  { echo "ERROR: native create response was not committed" >&2; exit 1; }
echo "NATIVE_SYSTEMD_STL_CREATE=PASS"
cli_b() {
 ip netns exec stl-ipsec-native-b env    STL_E2E_DISPOSABLE_HOST=approved STL_IPSEC_ISOLATED=approved    STL_IPSEC_CLI_FIXTURE=approved STL_IPSEC_CLI_OP="$1"    STL_IPSEC_CLI_SIDE=b STL_IPSEC_CLI_LINK=a STL_IPSEC_CLI_ENCAP="$encap"    /usr/local/bin/stl-ipsec-cli-test -test.run '^TestIPsecCanonicalCLIRealIsolatedE2E$' -test.v
}
cli_b import
if ip netns exec stl-ipsec-native-b ping -n -q -I 10.251.88.1 -c 1 -W 1 10.251.88.0 >/dev/null 2>&1; then
  echo "ERROR: protected Link Address transmitted before IKEv2" >&2; exit 1
fi
/usr/local/bin/stl link connect-ipsec "$link" --confirm "$link" --json |
  grep -q '"initiation":"accepted"' ||
    { echo "ERROR: native systemd IKEv2 connect did not complete" >&2; exit 1; }
ip netns exec stl-ipsec-native-b ping -n -q -I 10.251.88.1 -c 3 -W 2 10.251.88.0
ping -n -q -I 10.251.88.0 -c 3 -W 2 10.251.88.1
echo "NATIVE_SYSTEMD_ENCRYPTED_BIDIRECTIONAL_TRAFFIC=PASS"
for side in native b; do
  if [ "$side" = native ]; then observed=$(ip xfrm state); else observed=$(ip -n stl-ipsec-native-b xfrm state); fi
  count=$(printf '%s\n' "$observed" | grep -c 'proto esp' || true)
  [ "$count" = 2 ] || { echo "ERROR: expected two owned ESP SAs" >&2; exit 1; }
  if [ "$encap" = nat-t ]; then
    encapsulated=$(printf '%s\n' "$observed" | grep -c 'encap type espinudp' || true)
    [ "$encapsulated" -ge 2 ] || { echo "ERROR: native systemd kernel NAT-T is absent" >&2; exit 1; }
  fi
done
echo "NATIVE_SYSTEMD_KERNEL_ESP_${encap}=PASS"
/usr/local/bin/stl link status "$link" --json | grep -q '"security_association_present":true' ||
  { echo "ERROR: native CLI status did not see SA" >&2; exit 1; }
/usr/local/bin/stl link diagnose "$link" --json | grep -q '"packets_received":5' ||
  { echo "ERROR: native CLI diagnostic packet probes failed" >&2; exit 1; }
echo "NATIVE_SYSTEMD_STATUS_DIAGNOSE=PASS"
native_preflight() {
  env STL_IPSEC_PREFLIGHT_OPERATION="$1"     /usr/local/bin/stl-ipsec-cli-test     -test.run '^TestIsolatedNativeExclusiveOperationalPreflight$' -test.v
}
# Explicitly restart ONLY the fixture-owned, named STL unit; no vendor unit.
echo "NATIVE_SYSTEMD_RESTART_BEGIN=OBSERVED"
if ! systemctl restart simple-tun-link-ipsec.service; then
  echo "NATIVE_SYSTEMD_RESTART_TRANSITION=FAILED" >&2
  exit 1
fi
echo "NATIVE_SYSTEMD_RESTART_TRANSITION=PASS"
[ "$(systemctl is-active simple-tun-link-ipsec.service)" = active ] ||
  { echo "ERROR: STL-owned unit did not restart in disposable fixture" >&2; exit 1; }
/usr/local/bin/stl doctor ipsec --json | grep -q '"activation_allowed":true' ||
  { echo "ERROR: native admission failed after fresh STL unit restart" >&2; exit 1; }
native_preflight ensure
echo "NATIVE_SYSTEMD_RESTORE_BEGIN=OBSERVED"
/usr/local/bin/stl link restore --all >/dev/null ||
  { echo "ERROR: native STL state/PSK/VICI restore failed" >&2; exit 1; }
echo "NATIVE_SYSTEMD_RESTORE_COMMAND=PASS"
# Canonical RestoreAll reconnects a committed IPsec Link itself. Calling
# connect-ipsec again would turn this into a manual-connect test and could
# conceal a missing automatic reconnect.
if ! /usr/local/bin/stl link status "$link" --json | grep -q '"security_association_present":true'; then
  echo "ERROR: automatic IPsec SA restoration was not verified" >&2
  exit 1
fi
echo "NATIVE_SYSTEMD_AUTOMATIC_RECONNECT=PASS"
ping -n -q -I 10.251.88.0 -c 3 -W 2 10.251.88.1
ip netns exec stl-ipsec-native-b ping -n -q -I 10.251.88.1 -c 3 -W 2 10.251.88.0
echo "NATIVE_SYSTEMD_ACTUAL_UNIT_RESTART_RESTORE=PASS"
native_preflight remove
native_remove_out=$(/usr/local/bin/stl link remove "$link" --confirm "$link" --json) || {
  # STL's versioned failure envelope is deliberately secret-free.
  printf 'NATIVE_REMOVE_PUBLIC_ERROR=%s\n' "$native_remove_out" >&2
  echo "ERROR: native systemd scoped Remove failed" >&2
  exit 1
}
printf '%s\n' "$native_remove_out" | grep -q '"removed":true' ||
  { echo "ERROR: native systemd Remove response was not committed" >&2; exit 1; }
cli_b remove
# A successful Remove MUST durably retire both endpoint PSKs, including the
# encrypted key material on disk, not merely unload daemon memory.
test ! -e "/var/lib/simple-tun-link/credentials/$link.ipsecpsk" ||
  { echo "ERROR: native CLI left private IPsec key after Remove" >&2; exit 1; }
/usr/local/bin/stl link retire-ipsec "$link" --confirm "$link" --json |
  grep -q '"retired":true' ||
    { echo "ERROR: native idempotent retirement replay was not verified" >&2; exit 1; }
echo "NATIVE_SYSTEMD_PROTECTED_PSK_RETIREMENT=PASS"
if ip link show stlxaaaaaaaaaaa >/dev/null 2>&1 ||
   ip -n stl-ipsec-native-b link show stlxaaaaaaaaaaa >/dev/null 2>&1; then
   echo "ERROR: owned XFRM interface survived removal" >&2; exit 1
fi
if [ "$(ip xfrm state | grep -c 'proto esp' || true)" != 0 ] ||
   [ "$(ip -n stl-ipsec-native-b xfrm state | grep -c 'proto esp' || true)" != 0 ]; then
   echo "ERROR: owned ESP SA survived removal" >&2; exit 1
fi
echo "NATIVE_SYSTEMD_SCOPED_CLEANUP=PASS"
echo "NATIVE_SYSTEMD_REAL_IPSEC_E2E=PASS encapsulation=$encap"
