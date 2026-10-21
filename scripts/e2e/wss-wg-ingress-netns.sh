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
# The internal entrypoint is not a general-purpose namespace mutator.
# Attest one PRIVATE launcher-created fixture before any ip/nft/WG effect.
# This prevents an accidental direct --isolated call from changing an
# unrelated, pre-existing user/network namespace.
verify_fresh_namespace() {
  local fixture="$1" parent_user parent_net own_user own_net nonce uidmap
  [[ "$fixture" = /* && -d "$fixture" && ! -L "$fixture" && -O "$fixture" &&
     "$(stat -c '%a' "$fixture")" == 700 &&
     -f "$fixture/parent-namespaces" && ! -L "$fixture/parent-namespaces" &&
     -O "$fixture/parent-namespaces" &&
     "$(stat -c '%a' "$fixture/parent-namespaces")" == 600 &&
     -f "$fixture/namespace-guard" && ! -L "$fixture/namespace-guard" &&
     -O "$fixture/namespace-guard" &&
     "$(stat -c '%a' "$fixture/namespace-guard")" == 600 ]] || {
    echo 'REFUSED: no trusted private WSS namespace launcher fixture' >&2
    exit 2
  }
  nonce="$(cat "$fixture/namespace-guard")"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ &&
     "${STL_WSS_UDP_GUARD_NSGUARD:-}" == "$nonce" ]] || {
    echo 'REFUSED: WSS namespace launcher guard does not match' >&2
    exit 2
  }
  parent_user="$(sed -n '1p' "$fixture/parent-namespaces")"
  parent_net="$(sed -n '2p' "$fixture/parent-namespaces")"
  own_user="$(readlink /proc/self/ns/user)"
  own_net="$(readlink /proc/self/ns/net)"
  uidmap="$(awk 'NF == 3 { rows++; if ($1 == "0" && $3 == "1" && $2 ~ /^[0-9]+$/) mapped++ } END { print (rows == 1 && mapped == 1) ? "yes" : "no" }' /proc/self/uid_map)"
  [[ "$(id -u)" == 0 && "$uidmap" == yes &&
     -n "$parent_user" && -n "$parent_net" &&
     "$own_user" != "$parent_user" && "$own_net" != "$parent_net" &&
     "$own_net" != "$(readlink /proc/1/ns/net)" ]] || {
    echo 'REFUSED: WSS test is not in the launcher-created user/net namespace' >&2
    exit 2
  }
}

# The public entrypoint creates one disposable namespace itself. The
# internal entrypoint requires both matching private launcher evidence
# and distinct mapped-root user/network namespaces before inspecting hosts.
if (( $# == 0 )); then
  for tool in unshare nsenter nft ip iptables python3 go mktemp openssl cmp grep; do
    command -v "$tool" >/dev/null || { echo "MISSING_PREREQUISITE=$tool" >&2; exit 2; }
  done
  source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
  [[ -f "$source_root/go.mod" ]] || { echo 'REFUSED: source checkout missing' >&2; exit 2; }
  wg_binary="${STL_WSS_UDP_GUARD_E2E_WG_BINARY:-wg}"
  command -v "$wg_binary" >/dev/null || { echo 'MISSING_PREREQUISITE=wg' >&2; exit 2; }
  launcher_dir="$(mktemp -d "${TMPDIR:-/tmp}/stl-wss-wg-ingress-launch.XXXXXXXX")"
  trap 'rm -rf -- "$launcher_dir"' EXIT
  printf '%s\n%s\n' "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)" > "$launcher_dir/parent-namespaces"
  nonce="$(openssl rand -hex 16)"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || { echo 'REFUSED: invalid namespace nonce' >&2; exit 2; }
  printf '%s\n' "$nonce" > "$launcher_dir/namespace-guard"
  chmod 0600 "$launcher_dir/parent-namespaces" "$launcher_dir/namespace-guard"
  STL_WSS_UDP_GUARD_NSGUARD="$nonce" unshare --user --map-root-user --net /bin/bash "$0" --isolated "$launcher_dir"
  exit 0
fi
[[ "$#" == 2 && "$1" == --isolated ]] || {
  echo 'REFUSED: use the normal WSS UDP guard lab launcher' >&2
  exit 2
}
verify_fresh_namespace "$2"
for tool in nsenter nft ip iptables python3 go mktemp cmp grep; do
  command -v "$tool" >/dev/null || { echo "MISSING_PREREQUISITE=$tool" >&2; exit 2; }
done
source_root="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
[[ -f "$source_root/go.mod" ]] || { echo 'REFUSED: source checkout missing' >&2; exit 2; }
wg_binary="${STL_WSS_UDP_GUARD_E2E_WG_BINARY:-wg}"
command -v "$wg_binary" >/dev/null || { echo 'MISSING_PREREQUISITE=wg' >&2; exit 2; }
# The missing-guard/internal reentry proof happens entirely within the
# disposable child. It must refuse without any secondary host effects.
if env -u STL_WSS_UDP_GUARD_NSGUARD /bin/bash "$0" --isolated "$2" >/dev/null 2>&1; then
  echo 'FAIL: unauthenticated direct --isolated reentry succeeded' >&2
  exit 1
else
  code=$?
  [[ "$code" == 2 ]] || { echo 'FAIL: unexpected unauthenticated reentry outcome' >&2; exit 1; }
fi
echo 'UNAUTHENTICATED_ISOLATED_ENTRY_REFUSED=PASS'

testdir="$(mktemp -d /tmp/stl-wss-wg-ingress.XXXXXXXX)"
child=''
cleanup() {
  local code=$?
  trap - EXIT
  if [[ -n "$child" ]]; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  rm -f "$testdir/key" "$testdir/snapshot.json" "$testdir/before.json" "$testdir/after.json" "$testdir/collision.log"
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
batch="$source_root/internal/linux/testdata/wss_wg_ingress.nft"

# The collision boundary MUST be atomic: a separate preflight "list
# table" cannot prevent another actor creating it between reads/writes.
# These foreign-object fixtures are entirely inside this disposable netns.
# Prove the rendered CREATE transaction cannot alter either a foreign
# table with a different chain or one with the exact planned chain name.
collision_must_fail_without_mutation() {
  nft -j list table inet "$table" > "$testdir/before.json"
  if LC_ALL=C nft -f "$batch" > "$testdir/collision.log" 2>&1; then
    echo 'FAIL: nft batch adopted or modified a pre-existing table' >&2
    exit 1
  fi
  if ! grep -Fq 'File exists' "$testdir/collision.log"; then
    echo 'FAIL: nft batch failed for a reason other than exclusive-creation collision' >&2
    exit 1
  fi
  nft -j list table inet "$table" > "$testdir/after.json"
  cmp -s "$testdir/before.json" "$testdir/after.json" || {
    echo 'FAIL: rejected creation nevertheless changed a foreign nft table' >&2
    exit 1
  }
}
nft -f - <<EOF_FOREIGN
create table inet $table
add chain inet $table foreign
add rule inet $table foreign counter
EOF_FOREIGN
collision_must_fail_without_mutation
echo 'FOREIGN_TABLE_NO_MUTATION=PASS'
nft delete table inet "$table"
nft -f - <<EOF_FOREIGN
create table inet $table
create chain inet $table ingress { type filter hook input priority 0; policy accept; }
add rule inet $table ingress counter accept
EOF_FOREIGN
collision_must_fail_without_mutation
# Demonstrate that CREATE CHAIN itself is exclusive, not a permissive ADD
# variant, while the foreign table/chain remains unchanged.
nft -j list table inet "$table" > "$testdir/before.json"
if LC_ALL=C nft "create chain inet $table ingress { type filter hook input priority -250; policy accept; }" > "$testdir/collision.log" 2>&1; then
  echo 'FAIL: nft create chain silently adopted a foreign chain' >&2
  exit 1
fi
grep -Fq 'File exists' "$testdir/collision.log"
nft -j list table inet "$table" > "$testdir/after.json"
cmp -s "$testdir/before.json" "$testdir/after.json" || {
  echo 'FAIL: refused chain collision mutated foreign nft objects' >&2
  exit 1
}
echo 'FOREIGN_CHAIN_NO_MUTATION=PASS'
nft delete table inet "$table"

# Exercise a read-only WHOLE-ruleset coexistence preflight before the
# proposed owned guard exists. iptables-nft installs a conventional later
# priority INPUT ACCEPT; this alone must not be mistaken for a bypass.
iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT
nft -j list ruleset > "$testdir/snapshot.json"
STL_WSS_HOST_NFT_JSON="$testdir/snapshot.json" go test ./internal/linux -run '^TestWSSWGHostCoexistenceIsolatedNftReadback$' -count=1
echo 'NFT_CONVENTIONAL_INPUT_ACCEPT_OBSERVED=PASS'

# A separate, foreign pre-guard hook must be rejected without modifying it.
nft -f - <<'EOF_HOST_FOREIGN'
create table inet foreign_wss_pre
create chain inet foreign_wss_pre early { type filter hook input priority -300; policy accept; }
add rule inet foreign_wss_pre early udp dport 51820 counter accept
EOF_HOST_FOREIGN
nft -j list ruleset > "$testdir/snapshot.json"
STL_WSS_HOST_NFT_JSON="$testdir/snapshot.json" STL_WSS_HOST_EXPECT_REJECT=yes go test ./internal/linux -run '^TestWSSWGHostCoexistenceIsolatedNftReadback$' -count=1
echo 'NFT_FOREIGN_EARLY_INPUT_REJECTED=PASS'
nft delete table inet foreign_wss_pre
nft -j list ruleset > "$testdir/snapshot.json"
STL_WSS_HOST_NFT_JSON="$testdir/snapshot.json" go test ./internal/linux -run '^TestWSSWGHostCoexistenceIsolatedNftReadback$' -count=1
echo 'NFT_POST_FOREIGN_REMOVAL_RECOVERED=PASS'

# Only the following clean-state creation is accepted; all of the above
# collisions were deliberately refused before any test-owned guard exists.
nft -f "$batch"
nft -j list table inet "$table" > "$testdir/snapshot.json"
cd "$source_root"
STL_WSS_INGRESS_E2E_NFT_JSON="$testdir/snapshot.json" go test ./internal/linux -run '^TestWSSWGIngressVerifyIsolatedRuntimeSnapshot$' -count=1

# Prove the existing ACCEPT in the conventional filter INPUT chain is not
# sufficient to bypass an earlier-priority guard DROP in a distinct nft chain.
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
