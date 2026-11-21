#!/usr/bin/env bash
# Privileged, explicitly opt-in isolated Spoof Carrier raw-path test.
# Usage: sudo scripts/tests/spoof-netns.sh /absolute/path/to/rawprobe [/absolute/path/to/noiseprobe [--tun]]
# Build the test-only helper as an ordinary worker:
#   go build -o /tmp/stl262-rawprobe ./internal/carrier/spoof/testdata
# This private lab can check raw UDP, Noise and ephemeral TUN traffic.
# It does NOT claim production Engine/Restore or real WAN acceptance.
set -Eeuo pipefail

probe="${1:-}"
noise_probe="${2:-}"
tun_mode="${3:-}"
if [[ ! -x "$probe" || "$probe" != /* ]]; then
  echo "Provide an existing absolute executable rawprobe path" >&2
  exit 2
fi
if [[ -n "$noise_probe" && ( "$noise_probe" != /* || ! -x "$noise_probe" ) ]]; then
  echo "Optional Noise test helper must be an existing absolute executable" >&2
  exit 2
fi
if [[ -n "$tun_mode" && ( "$tun_mode" != "--tun" || -z "$noise_probe" ) ]]; then
  echo "Optional TUN validation requires a Noise helper and explicit --tun" >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo "This test needs isolated network-namespace root privileges" >&2
  exit 2
fi
for tool in ip nft grep mktemp ping python3; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 2; }
done

namespace_a="stlspA$$"
namespace_b="stlspB$$"
device_a="stlspEthA"
device_b="stlspEthB"
scratch="$(mktemp -d -t stl-spoof-netns.XXXXXXXX)"
recvpid=''
tun_a_pid=''
tun_b_pid=''
tcp_server_pid=''
udp_server_pid=''
created_a=0
created_b=0
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$recvpid" ]]; then
    kill "$recvpid" >/dev/null 2>&1 || true
    wait "$recvpid" >/dev/null 2>&1 || true
  fi
  for pid in "$tun_a_pid" "$tun_b_pid" "$tcp_server_pid" "$udp_server_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" >/dev/null 2>&1 || true; wait "$pid" >/dev/null 2>&1 || true; fi
  done
  if ((created_a)); then ip netns del "$namespace_a" >/dev/null 2>&1 || true; fi
  if ((created_b)); then ip netns del "$namespace_b" >/dev/null 2>&1 || true; fi
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT

if ip netns list | grep -Eq "^(${namespace_a}|${namespace_b})\b"; then
  echo "Test namespace collision; no mutation attempted" >&2
  exit 1
fi
ip netns add "$namespace_a"
created_a=1
ip netns add "$namespace_b"
created_b=1
ip link add "$device_a" type veth peer name "$device_b"
ip link set "$device_a" netns "$namespace_a"
ip link set "$device_b" netns "$namespace_b"
ip -n "$namespace_a" address add 10.77.0.1/30 dev "$device_a"
ip -n "$namespace_b" address add 10.77.0.2/30 dev "$device_b"
ip -n "$namespace_a" link set lo up
ip -n "$namespace_b" link set lo up
ip -n "$namespace_a" link set "$device_a" up
ip -n "$namespace_b" link set "$device_b" up
ip -n "$namespace_a" route add default via 10.77.0.2
ip -n "$namespace_b" route add default via 10.77.0.1

# Filter rules exist ONLY inside these disposable network namespaces.
ip netns exec "$namespace_b" nft add table ip stlspoof
ip netns exec "$namespace_b" nft 'add chain ip stlspoof input { type filter hook input priority 0; policy accept; }'
ip netns exec "$namespace_b" nft add rule ip stlspoof input ip saddr 10.77.0.1 udp dport 42002 drop
ip netns exec "$namespace_b" nft add rule ip stlspoof input ip saddr 198.18.0.99 udp dport 42002 drop
ip netns exec "$namespace_a" nft add table ip stlspoof
ip netns exec "$namespace_a" nft 'add chain ip stlspoof input { type filter hook input priority 0; policy accept; }'
ip netns exec "$namespace_a" nft add rule ip stlspoof input ip saddr 10.77.0.2 udp dport 42001 drop
printf '198.18.0.11\n198.18.0.99\n' > "$scratch/a-sources.txt"
printf '198.18.0.12\n' > "$scratch/b-sources.txt"

receive() {
  local ns="$1" bind="$2" logfile="$3"
  ip netns exec "$ns" "$probe" -mode recv -bind "$bind" > "$logfile" 2>&1 &
  recvpid=$!
  sleep 0.25
}
assert_received() {
  local want="$1" logfile="$2"
  wait "$recvpid"
  recvpid=''
  grep -Fq "$want" "$logfile" || {
    echo "Expected $want, actual $(cat "$logfile")" >&2
    return 1
  }
}
assert_not_received() {
  local logfile="$1"
  if wait "$recvpid"; then
    recvpid=''
    echo "Unexpected packet delivery: $(cat "$logfile")" >&2
    return 1
  fi
  recvpid=''
}

receive "$namespace_b" 10.77.0.2:42002 "$scratch/ordinary.log"
ip netns exec "$namespace_a" "$probe" -mode ordinary-send -peer 10.77.0.2:42002
assert_not_received "$scratch/ordinary.log"
echo "PASS: unmodified-source UDP blocked by receiver namespace firewall"

receive "$namespace_b" 10.77.0.2:42002 "$scratch/selected-a.log"
ip netns exec "$namespace_a" "$probe" -mode send -peer 10.77.0.2:42002 -source 198.18.0.11 -sources "$scratch/a-sources.txt" -device "$device_a"
assert_received "from=198.18.0.11:32001" "$scratch/selected-a.log"
echo "PASS: A->B selected outer Source actually delivered"

receive "$namespace_b" 10.77.0.2:42002 "$scratch/denied-a.log"
ip netns exec "$namespace_a" "$probe" -mode send -peer 10.77.0.2:42002 -source 198.18.0.99 -sources "$scratch/a-sources.txt" -device "$device_a"
assert_not_received "$scratch/denied-a.log"
echo "PASS: source 198.18.0.99 was dropped by the TEST firewall despite successful local send"

receive "$namespace_a" 10.77.0.1:42001 "$scratch/selected-b.log"
ip netns exec "$namespace_b" "$probe" -mode send -peer 10.77.0.1:42001 -source 198.18.0.12 -sources "$scratch/b-sources.txt" -device "$device_b"
assert_received "from=198.18.0.12:32001" "$scratch/selected-b.log"
echo "PASS: B->A different Source actually delivered through TEST firewall"
if [[ -n "$noise_probe" ]]; then
  "$noise_probe" -mode create -root "$scratch/a-state" -setup "$scratch/offline-setup.txt"
  ip netns exec "$namespace_a" "$noise_probe" -mode creator \
    -root "$scratch/a-state" -setup "$scratch/offline-setup.txt" \
    -sources "$scratch/a-sources.txt" -source 198.18.0.11 -device "$device_a" \
    > "$scratch/noise-a.log" 2>&1 &
  recvpid=$!
  sleep 0.25
  ip netns exec "$namespace_b" "$noise_probe" -mode recipient \
    -root "$scratch/b-state" -setup "$scratch/offline-setup.txt" \
    -sources "$scratch/b-sources.txt" -source 198.18.0.12 -device "$device_b" \
    > "$scratch/noise-b.log" 2>&1 || {
      cat "$scratch/noise-b.log" "$scratch/noise-a.log" >&2
      exit 1
    }
  if ! wait "$recvpid"; then
    cat "$scratch/noise-a.log" "$scratch/noise-b.log" >&2
    exit 1
  fi
  recvpid=''
  grep -Fq 'PASS: A authenticated B and decrypted B->A packet' "$scratch/noise-a.log"
  grep -Fq 'PASS: B authenticated A and decrypted A->B packet' "$scratch/noise-b.log"
  echo "PASS: Noise XKpsk0 completed over asymmetric spoof path with one offline code"
  echo "PASS: bilateral encrypted/authenticated application payloads (NOT TUN IP traffic)"
fi
if [[ "$tun_mode" == "--tun" ]]; then
  ip netns exec "$namespace_a" "$noise_probe" -mode creator-tun \
    -root "$scratch/a-state" -setup "$scratch/offline-setup.txt" \
    -sources "$scratch/a-sources.txt" -source 198.18.0.11 -device "$device_a" \
    > "$scratch/tun-a.log" 2>&1 &
  tun_a_pid=$!
  sleep 0.2
  ip netns exec "$namespace_b" "$noise_probe" -mode recipient-tun \
    -root "$scratch/b-state" -setup "$scratch/offline-setup.txt" \
    -sources "$scratch/b-sources.txt" -source 198.18.0.12 -device "$device_b" \
    > "$scratch/tun-b.log" 2>&1 &
  tun_b_pid=$!
  ready=0
  for ((i=0;i<60;i++)); do
    if grep -Fq 'READY: creator private TUN' "$scratch/tun-a.log" &&
       grep -Fq 'READY: recipient private TUN' "$scratch/tun-b.log"; then
      ready=1
      break
    fi
    if ! kill -0 "$tun_a_pid" 2>/dev/null || ! kill -0 "$tun_b_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if (( !ready )); then
    echo "FAILED: peers did not create authenticated TUN" >&2
    cat "$scratch/tun-a.log" "$scratch/tun-b.log" >&2
    exit 1
  fi
  # A successful handshake or TUN creation is deliberately not considered
  # CONNECTED until real independent application packets can cross the path.
  ip netns exec "$namespace_a" ping -n -c 3 -W 2 -I 10.89.0.0 10.89.0.1 || {
    echo "DIAG: A TUN source log:" >&2
    cat "$scratch/tun-a.log" >&2
    echo "DIAG: B TUN source log:" >&2
    cat "$scratch/tun-b.log" >&2
    echo "DIAG: A private route:" >&2
    ip -n "$namespace_a" -4 route show >&2
    echo "DIAG: B private route:" >&2
    ip -n "$namespace_b" -4 route show >&2
    exit 1
  }
  ip netns exec "$namespace_b" ping -n -c 3 -W 2 -I 10.89.0.1 10.89.0.0
  echo "PASS: bilateral ICMP over actual encrypted Spoof TUNs"

  # Two independent application TCP transfers with hash-checked integrity.
  for direction in ab ba; do
    if [[ "$direction" == "ab" ]]; then
      server="$namespace_b"; client="$namespace_a"
      bind_ip="10.89.0.1"; client_ip="10.89.0.0"
    else
      server="$namespace_a"; client="$namespace_b"
      bind_ip="10.89.0.0"; client_ip="10.89.0.1"
    fi
    ip netns exec "$server" python3 -u -c '
import socket,sys
s=socket.socket()
s.settimeout(6)
s.bind((sys.argv[1],22091))
s.listen(1)
c,_=s.accept()
d=bytearray()
while True:
    p=c.recv(65536)
    if not p:break
    d.extend(p)
c.sendall(bytes(d)[::-1])
c.close()
s.close()
print("TCP receiver bytes="+str(len(d)))
' "$bind_ip" > "$scratch/tcp-$direction.log" 2>&1 &
    tcp_server_pid=$!
    sleep 0.15
    ip netns exec "$client" python3 -u -c '
import socket,sys,hashlib
payload=(b"stl262-actual-private-tcp"*4000)
s=socket.socket()
s.settimeout(8)
s.bind((sys.argv[2],0))
s.connect((sys.argv[1],22091))
s.sendall(payload)
s.shutdown(socket.SHUT_WR)
d=bytearray()
while True:
    p=s.recv(65536)
    if not p:break
    d.extend(p)
s.close()
assert bytes(d)==payload[::-1]
print("PASS: TCP payload SHA256="+hashlib.sha256(d).hexdigest()+" bytes="+str(len(d)))
' "$bind_ip" "$client_ip"
    wait "$tcp_server_pid"
    tcp_server_pid=''
    cat "$scratch/tcp-$direction.log"
  done
  echo "PASS: bilateral private TCP application integrity"

  # Two independent UDP private datagram exchanges.
  for direction in ab ba; do
    if [[ "$direction" == "ab" ]]; then
      server="$namespace_b"; client="$namespace_a"
      bind_ip="10.89.0.1"; client_ip="10.89.0.0"
    else
      server="$namespace_a"; client="$namespace_b"
      bind_ip="10.89.0.0"; client_ip="10.89.0.1"
    fi
    ip netns exec "$server" python3 -u -c '
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(6)
s.bind((sys.argv[1],22092))
for i in range(10):
    d,addr=s.recvfrom(4096)
    s.sendto(d[::-1],addr)
print("UDP receiver echoed 10 datagrams")
' "$bind_ip" > "$scratch/udp-$direction.log" 2>&1 &
    udp_server_pid=$!
    sleep 0.15
    ip netns exec "$client" python3 -u -c '
import socket,sys,hashlib
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(5)
s.bind((sys.argv[2],0))
for i in range(10):
    d=(str(i).encode()+b":stl262-private-udp:"*80)
    s.sendto(d,(sys.argv[1],22092))
    r,addr=s.recvfrom(4096)
    assert r==d[::-1],(i,addr)
s.close()
print("PASS: 10 private UDP datagrams with verified payload")
' "$bind_ip" "$client_ip"
    wait "$udp_server_pid"
    udp_server_pid=''
    cat "$scratch/udp-$direction.log"
  done
  echo "PASS: bilateral private UDP application integrity"
fi
echo "PASS: tests completed, exact task-owned network namespaces will be removed"
