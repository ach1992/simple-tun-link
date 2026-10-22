#!/usr/bin/env bash
# No physical host effects: parent user/net/mount NS is never shared.
set -euo pipefail
if [[ "${1:-}" == --nsroot ]]; then
  lab=/lab
else
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
  lab="$repo/.r1-lab"
fi
if [[ "${1:-}" != --inside && "${1:-}" != --nsroot ]]; then
  [[ $(id -u) != 0 ]] || { echo "Run as an unprivileged user (rootless network namespaces only)" >&2; exit 2; }
  for file in "$lab/bin/wstunnel" "$lab/bin/stl-lab" "$lab/bin/wg-extract/usr/bin/wg"               "$lab/bin/iptables-extract/usr/sbin/xtables-nft-multi" "$lab/bin/shims/systemctl"; do
    [[ -f $file || -L $file ]] || { echo "Missing isolated test prerequisite: $file" >&2; exit 2; }
  done
  [[ $(sha256sum "$lab/bin/wstunnel" | cut -d' ' -f1) == 6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49 ]] || { echo "Pinned test wstunnel digest mismatch" >&2; exit 2; }
  [[ $(uname -m) == x86_64 ]] || { echo "Current isolated E2E fixture supports amd64; do not claim ARM64 E2E" >&2; exit 2; }
  # Prevent use of the separately mapped --inside and --nsroot entrypoints
  # on the caller's real root/host namespaces. All witness files are 0700.
  umask 077
  printf '%s\n' "$(readlink /proc/self/ns/user)" > "$lab/host-user-ns-id"
  token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  printf '%s\n' "$token" > "$lab/namespace-guard"
  export STL_WSS_R1_TEST_GUARD="$token"
  cp -- "$repo/scripts/e2e/wss-managed-wireguard-r1.sh" "$lab/wss-real-e2e.sh"
  cp -- "$repo/scripts/e2e/wss-negative-probe.py" "$lab/wss-negative-probe.py"

  rm -rf -- "$lab/alpha-state" "$lab/beta-state" "$lab/alpha/runtime" "$lab/beta/runtime"
  mkdir -p "$lab/run-netns" "$lab/alpha" "$lab/beta"
  readlink /proc/self/ns/net > "$lab/host-ns-id"
  exec unshare -Urnmpf bash "$0" --inside
fi
# Treat internal entrypoints as UNTRUSTED. Before *any* mount/network
# effect, prove that this is the launcher-created root-mapped user+net NS.
# A direct --inside invocation from root must not alter the real host.
if [[ "${1:-}" == --inside || "${1:-}" == --nsroot ]]; then
  [[ -n "${STL_WSS_R1_TEST_GUARD:-}" && -f "$lab/namespace-guard" &&
     ! -L "$lab/namespace-guard" && -f "$lab/host-user-ns-id" &&
     -f "$lab/host-ns-id" ]] || {
       echo "R1 isolated namespace launcher evidence missing" >&2; exit 2;
     }
  [[ $(cat "$lab/namespace-guard") == "$STL_WSS_R1_TEST_GUARD" &&
     $(id -u) == 0 &&
     $(readlink /proc/self/ns/user) != $(cat "$lab/host-user-ns-id") &&
     $(readlink /proc/self/ns/net) != $(cat "$lab/host-ns-id") &&
     $(awk 'NF==3 && $1=="0" && $3=="1"{n++} END{print n+0}' /proc/self/uid_map) == 1 ]] || {
       echo "R1 internal entrypoint is not inside a fresh root-mapped user+net namespace" >&2; exit 2;
     }
fi
if [[ "${1:-}" == --inside ]]; then
  # Private synthetic root has the correct root-owned ancestors for the
  # exact same production executable/credential admission. Original /usr
  # and /etc mounts are visible below separate synthetic root-owned nodes.
  mount --make-rprivate /
  root="$lab/ns-root"
  mkdir -p "$root"
  mount -t tmpfs tmpfs "$root"
  for d in usr/bin usr/sbin usr/lib usr/lib64 etc proc sys dev tmp run var/lib usr/local lab; do
    mkdir -p "$root/$d"
  done
  ln -s usr/bin "$root/bin"
  ln -s usr/sbin "$root/sbin"
  ln -s usr/lib "$root/lib"
  ln -s usr/lib64 "$root/lib64"
  for d in usr/bin usr/sbin usr/lib usr/lib64 etc; do
    mount --bind "/$d" "$root/$d"
  done
  mount -t proc proc "$root/proc"
  mount -t sysfs sysfs "$root/sys"
  mount --rbind /dev "$root/dev"
  mount --bind "$lab" "$root/lab"
  chmod 01777 "$root/tmp"
  exec chroot "$root" /usr/bin/bash /lab/wss-real-e2e.sh --nsroot
fi
[[ -n "${STL_WSS_R1_TEST_GUARD:-}" && -f "$lab/namespace-guard" &&
   $(cat "$lab/namespace-guard") == "$STL_WSS_R1_TEST_GUARD" &&
   $(readlink /proc/self/ns/user) != $(cat "$lab/host-user-ns-id") ]] || {
  echo "Missing bounded rootless namespace witness" >&2; exit 2;
}
if [[ $(id -u) != 0 || $(readlink /proc/self/ns/net) == $(cat "$lab/host-ns-id") ]]; then
  echo "Isolated namespaces required" >&2; exit 2
fi
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
mount --bind "$lab/run-netns" /run/netns
mount -t tmpfs tmpfs /usr/local
mkdir -p /usr/local/libexec/stl /usr/local/bin
cp "$lab/bin/stl-lab" /usr/local/bin/stl-lab
chmod 0755 /usr/local/bin/stl-lab
cp "$lab/bin/wstunnel" /usr/local/libexec/stl/wstunnel
chmod 0755 /usr/local/libexec/stl/wstunnel
printf '%s  %s\n' 6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49 /usr/local/libexec/stl/wstunnel | sha256sum -c -
mount -t tmpfs tmpfs /var/lib
mkdir -m 0700 /var/lib/stl-r1-state
export PATH="$lab/bin/shims:$lab/bin/wg-extract/usr/bin:$lab/bin/iptables-extract/usr/sbin:$PATH"
export LD_LIBRARY_PATH="$lab/bin/iptables-extract/usr/lib/x86_64-linux-gnu"
ip netns add alpha
ip netns add beta
cleanup(){
 for side in alpha beta; do
    for f in "$lab/$side"/runtime/*.json; do
      [[ -f $f ]] || continue
      pid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$f")
      kill "$pid" 2>/dev/null || :
    done
 done
 ip netns delete alpha 2>/dev/null || :
 ip netns delete beta 2>/dev/null || :
}
trap cleanup EXIT
ip link add veth-alpha type veth peer name veth-beta
ip link set veth-alpha netns alpha
ip link set veth-beta netns beta
ip netns exec alpha ip link set lo up
ip netns exec beta ip link set lo up
ip netns exec alpha ip address add 198.51.100.21/24 dev veth-alpha
ip netns exec beta ip address add 198.51.100.22/24 dev veth-beta
ip netns exec alpha ip link set veth-alpha up
ip netns exec beta ip link set veth-beta up
for side in alpha beta; do
  mkdir -p "$lab/$side-state/handoff" "$lab/$side/runtime"
  chmod 0700 "$lab/$side-state" "$lab/$side-state/handoff" "$lab/$side/runtime"
done
echo "UNDERLAY:"
ip netns exec alpha ping -c 1 -W 2 198.51.100.22
printf '%s\n' '{"schema_version":1,"link_id":"lnk_0123456789abcdef0123456789abcdef","underlay":{"local":"198.51.100.21","peer":"198.51.100.22"},"addresses":{"local":"10.75.0.1/30","peer":"10.75.0.2/30"},"listen_port":51821,"peer_port":51822,"role":"listen","tcp_port":59443,"remote_forward_udp_port":53001,"local_keepalive":25,"peer_keepalive":25}' > "$lab/alpha/create.json"
invoke(){
  local side=$1; shift
  export STL_R1_SIDE_ROOT="$lab/$side"
  echo "STL $side $*" >&2
  local args_json
  args_json=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")
  export STL_E2E_ARGS="$args_json"
  ip netns exec "$side" unshare -m bash -c '
    mount --make-rprivate /
    mount --bind "$1" /var/lib/stl-r1-state
    exec /usr/local/bin/stl-lab -test.run ^TestWSSLabCLI$ -test.v=false
  ' _ "$lab/$side-state"
}
invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/receiver.json < "$lab/alpha/create.json"
test -f "$lab/alpha-state/handoff/receiver.json"
invoke beta link preview-wss --stdin --json < "$lab/alpha-state/handoff/receiver.json" | tee "$lab/beta/preview.json"
confirm=$(grep -m1 '^{' "$lab/beta/preview.json" | jq -r .confirmation_sha256)
invoke beta link import-wss --stdin --confirm "$confirm" < "$lab/alpha-state/handoff/receiver.json"
echo "INTERFACES:"
ip netns exec alpha ip -brief addr
ip netns exec beta ip -brief addr
echo "WG STATUS:"
ip netns exec alpha wg show
ip netns exec beta wg show
echo "WG UDP, WSS TCP sockets before traffic:"
ip netns exec beta ss -unp | head -25
ip netns exec alpha ss -lntp | head -20
echo "LINK ICMP:"
sleep 7
ip netns exec beta ping -I 10.75.0.2 -c 3 -W 3 10.75.0.1
ip netns exec alpha ping -I 10.75.0.1 -c 3 -W 3 10.75.0.2
echo "SUCCESS REAL ICMP WSS+WG"
echo "WSS KERNEL HANDSHAKE:"
ip netns exec alpha wg show stlwg0123456789 latest-handshakes
ip netns exec beta wg show stlwg0123456789 latest-handshakes
echo "WSS REAL TCP:"
ip netns exec alpha python3 -m http.server 39080 --bind 10.75.0.1 --directory /lab/alpha > "$lab/alpha/tcp.log" 2>&1 &
tcp_pid=$!
sleep 0.4
ip netns exec beta curl --fail --silent --show-error --interface 10.75.0.2 --max-time 8 \
  "http://10.75.0.1:39080/create.json" | jq -e '.schema_version==1 and .tcp_port==59443' >/dev/null
kill "$tcp_pid" 2>/dev/null || :
wait "$tcp_pid" 2>/dev/null || :
echo "SUCCESS REAL TCP FORWARDED VIA WSS WG"
echo "WSS REAL UDP:"
ip netns exec alpha python3 -u -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(12);s.bind(("10.75.0.1",39081));d,p=s.recvfrom(1024);s.sendto(d+b"/ack",p);s.close()' > "$lab/alpha/udp.log" 2>&1 &
udp_pid=$!
sleep 0.3
ip netns exec beta python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("10.75.0.2",0));s.settimeout(7);s.sendto(b"actual-udp",("10.75.0.1",39081));d,p=s.recvfrom(1024);assert d==b"actual-udp/ack",d;print("SUCCESS REAL UDP ACK FROM",p);s.close()'
wait "$udp_pid"
echo "WSS DIAGNOSTICS FROM STL:"
invoke alpha link diagnose-wss lnk_0123456789abcdef0123456789abcdef --json
invoke beta link diagnose-wss lnk_0123456789abcdef0123456789abcdef --json
echo "WSS NEGATIVE mTLS/BEARER/PATH:"
for rejected in no-mtls wrong-bearer wrong-path; do
  ip netns exec beta python3 /lab/wss-negative-probe.py "$rejected"
done
echo "DIRECT PUBLIC WIREGUARD UDP MUST BE REJECTED:"
guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
rule_packets(){
 ip netns exec alpha nft -j list table inet "$guard" | jq '[.nftables[]|.rule?.expr[]?.counter?.packets // empty] | add // 0'
}
before=$(rule_packets)
ip netns exec beta python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b"direct-public-udp",("198.51.100.21",51821));s.close()'
sleep 0.1
after=$(rule_packets)
echo "guard_before=$before guard_after=$after"
if (( after <= before )); then echo "direct UDP was not confirmed blocked" >&2; exit 1; fi
echo "SUCCESS PUBLIC WG UDP DROP VERIFIED"
echo "WSS RESTART AFTER CRASH:"
beta_service="$lab/beta/runtime/stl-wss-0123456789abcdef0123456789abcdef.service.json"
pid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$beta_service")
kill -9 "$pid"
sleep 0.3
jq -c '{"schema_version":3,"link":.links[0].desired}' "$lab/beta-state/state.json" > "$lab/beta/ensure.json"
invoke beta link ensure --stdin < "$lab/beta/ensure.json"
sleep 7
ip netns exec beta ping -I 10.75.0.2 -c 2 -W 3 10.75.0.1
echo "SUCCESS HELPER CRASH RECOVERED BY STL ENGINE"
echo "WSS SCOPED REMOVAL:"
id=lnk_0123456789abcdef0123456789abcdef
invoke beta link remove "$id" --confirm "$id"
invoke alpha link remove "$id" --confirm "$id"
if ip netns exec alpha ip link show stlwg0123456789 >/dev/null 2>&1 ||
  ip netns exec beta ip link show stlwg0123456789 >/dev/null 2>&1; then
   echo "FAILED WG interface cleanup" >&2; exit 1
fi
if ip netns exec alpha nft list table inet "$guard" >/dev/null 2>&1 ||
  ip netns exec beta nft list table inet "$guard" >/dev/null 2>&1; then
   echo "FAILED nft guard cleanup" >&2; exit 1
fi
# Consumed receipt is an idempotent READ-ONLY success when absent.
for side in alpha beta; do
  invoke "$side" link retire-wss "$id" --confirm "$id"
  invoke "$side" link retire-wss "$id" --confirm "$id"
done
# The receipt MUST NOT delete new files if a retired identity reappears.
reappeared="$lab/alpha-state/credentials/wss/$id"
mkdir -m 0700 "$reappeared"
printf 'do-not-delete\n' > "$reappeared/client-key.pem"
chmod 0600 "$reappeared/client-key.pem"
if invoke alpha link retire-wss "$id" --confirm "$id" > "$lab/alpha/retire-denied.log" 2>&1; then
  echo "FAIL: consumed WSS receipt deleted or accepted new private material" >&2
  exit 1
fi
[[ $(cat "$reappeared/client-key.pem") == do-not-delete ]] ||
  { echo "FAIL: consumed receipt touched reappeared private material" >&2; exit 1; }
echo "DENY_PASS retired-identity-material-preserved"
rm -- "$reappeared/client-key.pem"
rmdir -- "$reappeared"
for side in alpha beta; do
  remaining=$(find "$lab/$side-state/credentials" -type f | wc -l)
  [[ $remaining == 0 ]] || { echo "WSS private material remained on $side after canonical Remove" >&2; exit 1; }
  jq -e '.removal_receipts[0].backend=="wireguard-wss" and .removal_receipts[0].retired==true' "$lab/$side-state/state.json" >/dev/null || exit 1
done
echo "SUCCESS MANAGED WSS LINK CREATE, ICMP, TCP, UDP, DIRECT-UDP-DROP, CRASH-REPAIR, RETIRE SECRETS, AND REMOVE"
