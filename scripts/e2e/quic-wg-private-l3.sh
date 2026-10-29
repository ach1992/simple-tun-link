#!/usr/bin/env bash
# Opt-in ROOTLESS real kernel WireGuard private-L3 over official Hysteria QUIC.
# This is a disposable developer integration proof, NOT a managed STL Link,
# firewall ownership receipt, service lifecycle or physical-host acceptance.
set -Eeuo pipefail
umask 077

refuse() { echo "REFUSED: $1" >&2; exit 2; }
fail() { echo "FAIL: $1" >&2; exit 1; }

[[ "$#" == 2 || ("$#" == 1 && "$1" == --isolated) ]] || refuse "usage: STL_QUIC_WG_L3_E2E=approved $0 /absolute/official-hysteria /absolute/wg"
[[ "${STL_QUIC_WG_L3_E2E:-}" == approved ]] || refuse "explicit disposable QUIC L3 E2E opt-in missing"
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
[[ -f "$repo/go.mod" ]] || refuse "repository identity unavailable"
for tool in unshare nsenter nft ip ping go python3 readlink stat sha256sum awk grep; do
  command -v "$tool" >/dev/null || refuse "isolated-test prerequisite unavailable: $tool"
done

if [[ "$1" != --isolated ]]; then
  helper="$1"
  wg="$2"
  [[ "$helper" == /* && -f "$helper" && ! -L "$helper" && -x "$helper" &&
     "$wg" == /* && -f "$wg" && ! -L "$wg" && -x "$wg" ]] ||
    refuse "absolute regular helper and wg executable required"
  case "$(uname -m)" in
    x86_64) expected=907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691 ;;
    aarch64) expected=a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7 ;;
    *) refuse "no officially pinned Hysteria binary for this machine architecture" ;;
  esac
  actual=$(sha256sum -- "$helper" | cut -d' ' -f1)
  [[ "$actual" == "$expected" ]] || refuse "Hysteria v2.13.0 official SHA-256 mismatch"

  # After preflight and the official executable digest check, replace the
  # initial launcher with one exact-process supervisor. It owns both the
  # private fixture and a separate-session janitor that survives SIGKILL.
  # No privileged host/network effect occurs before the child namespace gate.
  exec python3 "$repo/scripts/e2e/quic-wg-private-l3-supervisor.py" \
    "$repo" "$helper" "$wg" "$repo/scripts/e2e/quic-wg-private-l3.sh"
fi

lab="$STL_QUIC_WG_L3_ROOT"
helper="$STL_QUIC_HYSTERIA_BIN"
wg="$STL_QUIC_WG_L3_WG_BINARY"
[[ "$lab" == /tmp/stl-quic-wg-l3.* && -d "$lab" && ! -L "$lab" &&
   "$(stat -c '%a' "$lab")" == 700 &&
   -f "$lab/parent-namespaces" && ! -L "$lab/parent-namespaces" &&
   -f "$lab/nonce" && ! -L "$lab/nonce" &&
   "$(stat -c '%a' "$lab/nonce")" == 600 &&
   "$(cat "$lab/nonce")" == "${STL_QUIC_WG_L3_NONCE:-}" ]] ||
  refuse "private launcher-owned namespace fixture missing"
parent_user=$(sed -n '1p' "$lab/parent-namespaces")
parent_net=$(sed -n '2p' "$lab/parent-namespaces")
parent_pid=$(sed -n '3p' "$lab/parent-namespaces")
[[ "$parent_pid" == "${STL_QUIC_PARENT_PIDNS:-}" && "$parent_pid" == pid:* ]] ||
  refuse "disposable parent PID namespace identity unavailable"
current_user=$(readlink /proc/self/ns/user)
current_net=$(readlink /proc/self/ns/net)
mapped_root=$(awk 'NF==3 { n++; if ($1==0 && $3==1 && $2 ~ /^[0-9]+$/) ok++ } END { print (n==1 && ok==1) ? "yes" : "no" }' /proc/self/uid_map)
[[ "$(id -u)" == 0 && "$mapped_root" == yes &&
   "$current_user" != "$parent_user" && "$current_net" != "$parent_net" &&
   "$$" -eq 1 && "$(readlink /proc/self/ns/pid)" != "$parent_pid" &&
   "$(readlink /proc/1/ns/pid)" == "$(readlink /proc/self/ns/pid)" &&
   "$(readlink /proc/1/ns/net)" == "$current_net" ]] ||
  refuse "not the PID-1 controller of the disposable user/network namespace"

# Verify that a re-entry lacking the parent-owned guard cannot perform
# even one native network operation inside the already disposable namespace.
if env -u STL_QUIC_WG_L3_NONCE bash "$0" --isolated >/dev/null 2>&1; then
  fail "untrusted isolated launcher reentry was admitted"
else
  code=$?
  [[ "$code" == 2 ]] || fail "untrusted launcher reentry did not fail closed"
fi
echo "UNAUTHORIZED_QUIC_WG_LAB_REENTRY=BLOCKED"

# No kernel mutation before the above fail-closed namespace gate.
server=''
client=''
sibling=''
app_server=''
cleanup_child() {
  local code=$?
  trap - EXIT TERM
  # This shell has already proved it is PID 1 in the dedicated disposable
  # PID namespace. Its exit is the authoritative kernel teardown of every
  # helper, echo and sibling worker, even after an uncatchable SIGKILL.
  # Do not signal numeric child PIDs after they might have been reaped.
  # The exact-pidfd outer supervisor bounds the PID-1 termination path.
  exit "$code"
}
trap cleanup_child EXIT
# PID namespace init must explicitly respond to TERM. SIGKILL is handled
# by kernel PID-1 teardown and the unshare/parent-death supervision chain.
trap 'exit 143' TERM

if [[ "${STL_QUIC_WG_L3_FAULT:-}" == setup-fail ]]; then
  fail "injected isolated setup failure before native network effects"
fi

# Protected credentials/configs were already staged and re-attested
# by their normal production verifier under the original user identity.
# The child can only consume these test-owned private files.

unshare --net sleep 180 &
sibling=$!
for n in $(seq 1 60); do
  current_child=$(readlink "/proc/$sibling/ns/net" 2>/dev/null || true)
  [[ -n "$current_child" && "$current_child" != "$current_net" ]] && break
  sleep 0.05
done
[[ -n "$current_child" && "$current_child" != "$current_net" ]] ||
  fail "disposable sibling namespace unavailable"

ip link set lo up
nsenter -t "$sibling" -n -- ip link set lo up
ip link add stlqva type veth peer name stlqvb
ip link set stlqvb netns "$sibling"
ip addr add 172.31.247.1/30 dev stlqva
ip link set stlqva up
nsenter -t "$sibling" -n -- ip addr add 172.31.247.2/30 dev stlqvb
nsenter -t "$sibling" -n -- ip link set stlqvb up
ping -n -c 2 -W 1 172.31.247.2 > "$lab/underlay-ping.log" 2>&1 ||
  fail "isolated veth physical underlay failed"

# Both kernel WG listeners bind all interfaces. Each endpoint needs an
# independently nonced source-generated nft guard, with strict readback.
# This is only test-owned and never grants original resource ownership.
guard_endpoint() {
  local role=$1 phase=$2
  local port='' physical='' table=''
  local -a in_role_ns=()
  if [[ "$role" == server ]]; then
    port=51820
    physical=172.31.247.2
    in_role_ns=(nsenter -t "$sibling" -n --)
  elif [[ "$role" == client ]]; then
    port=51821
    physical=172.31.247.1
  else
    fail "invalid disposable guard role"
  fi
  local batch="$lab/guard-$role.nft"
  table=$(awk 'NR==1 && $1=="create" && $2=="table" && $3=="inet" { print $4 }' "$batch")
  [[ "$table" =~ ^stlquic_[a-f0-9]{16}$ ]] ||
    fail "invalid source-generated nft guard for role"
  if [[ "$phase" == install ]]; then
    "${in_role_ns[@]}" nft -f "$batch" ||
      fail "disposable role-specific QUIC guard CREATE failed"
    if ! env STL_QUIC_WG_L3_GUARD_CHECK=approved STL_QUIC_WG_L3_GUARD_ROLE="$role" \
       "${in_role_ns[@]}" "$lab/quic-test" -test.run '^TestPinnedHysteriaKernelWGGuardReadback$' \
       -test.v > "$lab/guard-$role-check.log" 2>&1; then
      grep -E 'real_wg_l3_e2e_test.go:|^--- FAIL:|^FAIL' "$lab/guard-$role-check.log" | head -8 || true
      fail "disposable role-specific nft guard strict readback failed"
    fi
    return 0
  fi
  [[ "$phase" == probe ]] || fail "invalid disposable ingress guard phase"
  if [[ "$role" == server ]]; then
    printf 'stl-server-guard-probe' > "/dev/udp/$physical/$port" ||
      fail "disposable physical server WG-port probe could not be sent"
  else
    nsenter -t "$sibling" -n -- bash -c \
      'printf "stl-client-guard-probe" > /dev/udp/172.31.247.1/51821' ||
      fail "disposable physical client WG-port probe could not be sent"
  fi
  "${in_role_ns[@]}" nft -a list chain inet "$table" ingress > "$lab/guard-$role-counter.txt"
  grep -Eq 'counter packets [1-9][0-9]* bytes [1-9][0-9]* drop' "$lab/guard-$role-counter.txt" ||
    fail "physical WG UDP did not hit the role-specific guard drop counter"
}

# Source-generated nft CREATE and strict readback MUST precede even the
# first actual kernel WireGuard listener socket/effect in this lab.
guard_endpoint server install
guard_endpoint client install
echo "QUIC_WG_GUARDS_VERIFIED_BEFORE_WG_ACTIVATION=PASS"

# Genuine Linux kernel WireGuard devices, NOT a userspace fake.
ip link add stlqwga type wireguard
nsenter -t "$sibling" -n -- ip link add stlqwgb type wireguard
"$wg" genkey > "$lab/client.key"
"$wg" pubkey < "$lab/client.key" > "$lab/client.pub"
"$wg" genkey > "$lab/server.key"
"$wg" pubkey < "$lab/server.key" > "$lab/server.pub"
chmod 0600 "$lab/client.key" "$lab/server.key" "$lab/client.pub" "$lab/server.pub"
"$wg" set stlqwga private-key "$lab/client.key" listen-port 51821 \
  peer "$(cat "$lab/server.pub")" allowed-ips 10.247.0.2/32 \
  endpoint 127.0.0.1:52211 persistent-keepalive 1
nsenter -t "$sibling" -n -- "$wg" set stlqwgb \
  private-key "$lab/server.key" listen-port 51820 \
  peer "$(cat "$lab/client.pub")" allowed-ips 10.247.0.1/32
ip address add 10.247.0.1/30 dev stlqwga
nsenter -t "$sibling" -n -- ip address add 10.247.0.2/30 dev stlqwgb
ip link set stlqwga up
nsenter -t "$sibling" -n -- ip link set stlqwgb up

guard_endpoint server probe
guard_endpoint client probe
echo "QUIC_WG_BOTH_PHYSICAL_UDP_GUARDS=PASS"

link=lnk_b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
server_conf="$lab/server/credentials/quic/$link/helper.json"
client_conf="$lab/client/credentials/quic/$link/helper.json"
[[ -f "$server_conf" && -f "$client_conf" ]] || fail "protected config missing"
nsenter -t "$sibling" -n -- "$helper" --disable-update-check --log-level info -c "$server_conf" server \
  > "$lab/server.log" 2>&1 &
server=$!
sleep 0.25
kill -0 "$server" 2>/dev/null || fail "official QUIC listener did not start"
start_client() {
  "$helper" --disable-update-check --log-level info -c "$client_conf" client \
    > "$lab/client.log" 2>&1 &
  client=$!
  for n in $(seq 1 100); do
    if grep -Fq 'UDP forwarding listening' "$lab/client.log"; then
      kill -0 "$client" || fail "QUIC dialer exited after local forwarder startup"
      return
    fi
    kill -0 "$client" 2>/dev/null || fail "official QUIC dialer exited before authenticated readiness"
    sleep 0.1
  done
  fail "QUIC dialer did not reach authenticated forwarding readiness"
}
start_client
grep -Fq 'client connected' "$lab/server.log" || fail "server mTLS/bearer admission was not observed"

# Fault modes are admitted only after the disposable PID-1, nonce, owner
# and namespace gates, and only after both real helpers have started.
if [[ -n "${STL_QUIC_WG_L3_FAULT:-}" ]]; then
  echo "QUIC_L3_FAULT_READY PIDNS=$(readlink /proc/self/ns/pid) NETNS=$(readlink /proc/self/ns/net) SIBLINGNS=$(readlink /proc/$sibling/ns/net)"
fi
case "${STL_QUIC_WG_L3_FAULT:-}" in
  after-helper-fail) fail "injected failure with live QUIC helpers" ;;
  child-term)
    kill -TERM "$$"
    fail "isolated PID-1 TERM handler failed"
    ;;
  child-kill)
    kill -KILL "$$"
    fail "isolated PID-1 uncatchable termination failed"
    ;;
  supervisor-hold)
    sleep 90
    fail "abnormal supervisor test did not interrupt the lab"
    ;;
esac

# The private ICMP echo must traverse the kernel WG peer, its UDP datagrams
# locally redirected by the Hysteria client, encrypted QUIC on the veth,
# and server Hysteria restricted UDP ACL to kernel WG inside sibling netns.
try_private_ping() {
  local dir=$1
  for n in $(seq 1 25); do
    if [[ "$dir" == outbound ]]; then
      ping -n -c 3 -W 1 10.247.0.2 > "$lab/private-out.log" 2>&1 && return 0
    else
      nsenter -t "$sibling" -n -- ping -n -c 3 -W 1 10.247.0.1 > "$lab/private-in.log" 2>&1 && return 0
    fi
    sleep 0.2
  done
  return 1
}
start_private_echo() {
  # Application sockets bind to the private kernel WG address, NOT veth.
  nsenter -t "$sibling" -n -- python3 -u - > "$lab/echo.log" 2>&1 <<'PY' &
import socketserver
import threading
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)
tcp = socketserver.ThreadingTCPServer(("10.247.0.2", 35001), TCP)
udp = socketserver.ThreadingUDPServer(("10.247.0.2", 35002), UDP)
threading.Thread(target=tcp.serve_forever, daemon=True).start()
threading.Thread(target=udp.serve_forever, daemon=True).start()
print("PRIVATE_ECHO_READY", flush=True)
threading.Event().wait()
PY
  app_server=$!
  for n in $(seq 1 80); do
    if grep -Fxq PRIVATE_ECHO_READY "$lab/echo.log"; then
      kill -0 "$app_server" || fail "private TCP/UDP echo server exited"
      return
    fi
    kill -0 "$app_server" 2>/dev/null || fail "private TCP/UDP echo server failed"
    sleep 0.05
  done
  fail "private TCP/UDP echo server readiness unavailable"
}
verify_private_app() {
  python3 - <<'PY' > "$lab/private-app-result.log" 2>&1
import os
import socket
host = "10.247.0.2"
message = os.urandom(65536)
with socket.create_connection((host, 35001), timeout=6.0) as conn:
    conn.settimeout(6.0)
    conn.sendall(message)
    conn.shutdown(socket.SHUT_WR)
    received = bytearray()
    while len(received) < len(message):
        part = conn.recv(4096)
        if not part:
            raise SystemExit("private TCP echo truncated")
        received.extend(part)
    if received != message:
        raise SystemExit("private TCP echo corrupted")
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
    conn.settimeout(5.0)
    for _ in range(16):
        message = os.urandom(1200)
        conn.sendto(message, (host, 35002))
        received, peer = conn.recvfrom(1500)
        if peer != (host, 35002) or received != message:
            raise SystemExit("private UDP echo corrupted")
print("PRIVATE_L3_TCP_UDP=PASS")
PY
}

start_private_echo
try_private_ping outbound || fail "real kernel WG private-IP forward over QUIC failed"
try_private_ping inbound || fail "real kernel WG reciprocal private-IP traffic failed"
verify_private_app || fail "real private-IP TCP/UDP application traffic over QUIC failed"
echo "REAL_QUIC_WG_PRIVATE_L3_ICMP_TCP_UDP=PASS"

handshake=$("$wg" show stlqwga latest-handshakes | awk 'NF==2 {print $2}')
[[ "$handshake" =~ ^[0-9]+$ && "$handshake" -gt 0 ]] ||
  fail "private-IP exchange lacks authenticated kernel WG handshake"
read -r rx tx < <("$wg" show stlqwga transfer | awk 'NF==3 {print $2, $3}')
[[ "$rx" =~ ^[0-9]+$ && "$tx" =~ ^[0-9]+$ && "$rx" -gt 0 && "$tx" -gt 0 ]] ||
  fail "native WG has no bilateral encrypted packet counters"
echo "REAL_QUIC_WG_NATIVE_L3_BILATERAL=PASS"

# Control: without its QUIC helper, the exact WG peer remains configured
# but cannot exchange packets across the disposable physical veth.
kill "$client"
wait "$client" 2>/dev/null || true
client=''
if ping -n -c 2 -W 1 10.247.0.2 > "$lab/disabled-quic.log" 2>&1; then
  fail "kernel WG bypassed the stopped QUIC carrier"
fi
echo "WITHOUT_QUIC_CARRIER_PRIVATE_L3=BLOCKED"

# Fresh official helper process restores identical existing kernel WG
# identity without changing keys or reconfiguring either link.
start_client
try_private_ping outbound || fail "same WG private L3 did not resume after helper restart"
try_private_ping inbound || fail "reciprocal private L3 did not resume after helper restart"
verify_private_app || fail "private TCP/UDP did not resume with the same WG identity"
echo "REAL_QUIC_HELPER_RESTART_WITH_SAME_WG_IDENTITY=PASS"
