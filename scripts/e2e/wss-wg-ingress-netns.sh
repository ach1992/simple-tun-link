#!/usr/bin/env bash
# An explicitly opted-in, disposable, rootless user+network namespace proof
# for the NON-RUNNABLE WSS kernel-WG UDP ingress guard design.
# No host nft/iptables/interface/service or real STL State mutation.
set -Eeuo pipefail
umask 077

if [[ "${STL_WSS_UDP_GUARD_E2E:-}" != approved ]]; then
  echo 'REFUSED: explicitly approve an isolated WSS guard lab only' >&2
  exit 2
fi
for tool in unshare nsenter nft ip iptables python3 go mktemp; do
  command -v "$tool" >/dev/null || { echo "MISSING_PREREQUISITE=$tool" >&2; exit 2; }
done
source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
[[ -f "$source_root/go.mod" ]] || { echo 'REFUSED: source checkout missing' >&2; exit 2; }
wg_binary="${STL_WSS_UDP_GUARD_E2E_WG_BINARY:-wg}"
command -v "$wg_binary" >/dev/null || { echo 'MISSING_PREREQUISITE=wg' >&2; exit 2; }

# The parent performs NO network effect. Both the WG kernel interfaces and
# the foreign ACCEPT comparison live only inside the fresh child namespace.
if [[ "${1:-}" != --isolated ]]; then
  exec unshare --user --map-root-user --net /bin/bash "$0" --isolated
fi
[[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ]] || {
  echo 'REFUSED: network namespace did not change' >&2
  exit 2
}
[[ "$(id -u)" == 0 ]] || { echo 'REFUSED: user namespace did not map root' >&2; exit 2; }
testdir="$(mktemp -d /tmp/stl-wss-wg-ingress.XXXXXXXX)"
child=''
cleanup() {
  local code=$?
  trap - EXIT
  if [[ -n "$child" ]]; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  rm -f "$testdir/key" "$testdir/snapshot.json"
  rmdir "$testdir" 2>/dev/null || true
  exit "$code"
}
trap cleanup EXIT
ip link set lo up
unshare --net sleep 90 &
child=$!
ip link add wss-side type veth peer name wan-side
ip link set wan-side netns "$child"
ip addr add 198.18.52.1/30 dev wss-side
ip -6 addr add fd42:52::1/64 dev wss-side nodad
ip link set wss-side up
nsenter -t "$child" -n ip link set lo up
nsenter -t "$child" -n ip addr add 198.18.52.2/30 dev wan-side
nsenter -t "$child" -n ip -6 addr add fd42:52::2/64 dev wan-side nodad
nsenter -t "$child" -n ip link set wan-side up
ip link add stlwsslab type wireguard
"$wg_binary" genkey > "$testdir/key"
chmod 0600 "$testdir/key"
"$wg_binary" set stlwsslab private-key "$testdir/key" listen-port 51820
[[ "$("$wg_binary" show stlwsslab listen-port)" == 51820 ]] || {
  echo 'KERNEL_WIREGUARD_UDP_SOCKET_NOT_PROVEN' >&2
  exit 1
}
echo KERNEL_WG_LISTEN_PORT=51820

# Apply the exact batch validated by Go unit tests, solely in this isolated NS.
table=stlwss_09506b2028cc50fd
if nft list table inet "$table" >/dev/null 2>&1; then
  echo 'REFUSED: expected disposable guard table already exists' >&2
  exit 1
fi
nft -f "$source_root/internal/linux/testdata/wss_wg_ingress.nft"
nft -j list table inet "$table" > "$testdir/snapshot.json"
cd "$source_root"
STL_WSS_INGRESS_E2E_NFT_JSON="$testdir/snapshot.json" go test ./internal/linux -run '^TestWSSWGIngressVerifyIsolatedRuntimeSnapshot$' -count=1

# Prove a pre-existing ACCEPT in the conventional filter INPUT chain is not
# sufficient to bypass an earlier-priority guard DROP in a distinct nft chain.
iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT
python3 - <<'PY'
import socket
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'LOCAL4', ('127.0.0.1',51820))
socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto(b'LOCAL6', ('::1',51820))
PY
nft -j list table inet "$table" > "$testdir/snapshot.json"
python3 - "$testdir/snapshot.json" <<'PY'
import json,sys
snapshot=json.load(open(sys.argv[1]))
rules=[e['rule'] for e in snapshot['nftables'] if 'rule' in e]
assert len(rules)==1
counter=[x['counter'] for x in rules[0]['expr'] if 'counter' in x]
assert len(counter)==1
assert counter[0]['packets']==0, 'local UDP unexpectedly dropped by non-loopback filter'
print('LOCAL_LOOPBACK_IPV4_IPV6_NOT_DROPPED=PASS')
PY
nsenter -t "$child" -n python3 - <<'PY'
import socket,time
s4=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
for _ in range(3):
    s4.sendto(b'FOREIGN_IPV4',('198.18.52.1',51820))
    s6.sendto(b'FOREIGN_IPV6',('fd42:52::1',51820))
    time.sleep(.06)
PY
nft -j list table inet "$table" > "$testdir/snapshot.json"
STL_WSS_INGRESS_E2E_NFT_JSON="$testdir/snapshot.json" go test ./internal/linux -run '^TestWSSWGIngressVerifyIsolatedRuntimeSnapshot$' -count=1
python3 - "$testdir/snapshot.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
rules=[e['rule'] for e in d['nftables'] if 'rule' in e]
assert len(rules)==1
count=[e['counter'] for e in rules[0]['expr'] if 'counter' in e]
assert len(count)==1
packets=count[0]['packets']
print('WAN_IPV4_AND_IPV6_DENIAL_COUNT='+str(packets))
if packets<6:
    raise SystemExit('FAIL: foreign IPv4/IPv6 probes were not observed and dropped by owned guard')
PY
echo 'ISOLATED_REAL_KERNEL_WG_UDP_GUARD=PASS'
echo 'ISOLATED_GUARD_NFT_READBACK_AND_FOREIGN_ACCEPT_NEGATIVE=PASS'
