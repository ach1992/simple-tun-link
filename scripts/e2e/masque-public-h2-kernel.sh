#!/usr/bin/env bash
# Real, opt-in two-peer MASQUE kernel test. No host network/systemd effects.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
if [[ $# -eq 0 ]]; then
  [[ $(id -u) != 0 && $(printenv STL_MASQUE_PUBLIC_TLS_E2E || :) == approved ]] || {
    echo "Run as non-root with STL_MASQUE_PUBLIC_TLS_E2E=approved" >&2; exit 2;
  }
  root="$repo/.r1-lab"
  if [[ ! -e $root && ! -L $root ]]; then
    (umask 077; mkdir -- "$root")
  fi
  [[ -d $root && ! -L $root && $(stat -c %u -- "$root") == "$(id -u)" ]] || {
    echo "The disposable MASQUE fixture parent has unexpected ownership/type" >&2; exit 2;
  }
  lab=$(mktemp -d "$root/masque-public.XXXXXXXX")
  cleanup_outer() {
    [[ -d $lab && ! -L $lab && $(stat -c %u -- "$lab") == "$(id -u)" ]] || return 1
    if findmnt -rn -o TARGET | grep -F -- "$lab" >/dev/null; then
      echo "Lab mount still exists; preserving $lab for reconciliation" >&2
      return 1
    fi
    rm -rf -- "$lab"
    rmdir -- "$root" 2>/dev/null || :
  }
  trap cleanup_outer EXIT
  chmod 0700 "$lab"
  go build -o "$lab/stl" ./cmd/stl
  go test -tags stl_e2e_lab -c -o "$lab/stl-stage" ./cmd/stl
  readlink /proc/self/ns/user > "$lab/host-user-ns"
  readlink /proc/self/ns/net > "$lab/host-net-ns"
  STL_MASQUE_LAB_GUARD=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  export STL_MASQUE_LAB_GUARD
  printf '%s' "$STL_MASQUE_LAB_GUARD" > "$lab/guard"
  unshare -Urnmpf --kill-child /usr/bin/bash "$0" --inside "$lab"
  exit 0
fi

[[ $# -eq 2 && $1 == --inside ]] || { echo "Bad internal test entrypoint" >&2; exit 2; }
lab=$2
[[ -d $lab && ! -L $lab && -f $lab/guard &&
  -n "$(printenv STL_MASQUE_LAB_GUARD || :)" &&
  "$(cat "$lab/guard")" == "$STL_MASQUE_LAB_GUARD" &&
  $(id -u) == 0 &&
  "$(readlink /proc/self/ns/user)" != "$(cat "$lab/host-user-ns")" &&
  "$(readlink /proc/self/ns/net)" != "$(cat "$lab/host-net-ns")" &&
  "$(awk 'NF==3 && $1=="0" && $3=="1"{n++} END{print n+0}' /proc/self/uid_map)" == 1 ]] || {
  echo "Refusing to execute outside fresh rootless user and network namespaces" >&2; exit 2;
}
listener_pid= dialer_pid= http_pid= udp_pid=
cleanup_inner() {
  for pid in "$dialer_pid" "$listener_pid" "$http_pid" "$udp_pid"; do
    if [[ -n $pid ]]; then
      kill "$pid" 2>/dev/null || :
      wait "$pid" 2>/dev/null || :
    fi
  done
  ip netns delete alpha 2>/dev/null || :
  ip netns delete beta 2>/dev/null || :
}
trap cleanup_inner EXIT
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
ip netns add alpha
ip netns add beta
ip link add veth-alpha type veth peer name veth-beta
ip link set veth-alpha netns alpha
ip link set veth-beta netns beta
ip netns exec alpha ip link set lo up
ip netns exec beta ip link set lo up
ip netns exec alpha ip addr add 198.51.100.21/24 dev veth-alpha
ip netns exec beta ip addr add 198.51.100.22/24 dev veth-beta
ip netns exec alpha ip link set veth-alpha up
ip netns exec beta ip link set veth-beta up
ip netns exec alpha ping -q -c 1 -W 2 198.51.100.22 >/dev/null
echo 'PASS: isolated real kernel underlay'

export STL_MASQUE_LAB_ROOT="$lab"
"$lab/stl-stage" -test.run '^TestMASQUEKernelLabStage$' -test.v=false > "$lab/stage.log" 2>&1 || {
  cat "$lab/stage.log" >&2; exit 1;
}
id=lnk_0123456789abcdef0123456789abcdef
cfg_a="$lab/alpha-state/masque/$id/agent.json"
cfg_b="$lab/beta-state/masque/$id/agent.json"
ca="$lab/beta-state/masque/$id/server-ca.pem"
[[ -f $cfg_a && -f $cfg_b && -f $ca ]] || {
  echo "Original protected peer material missing" >&2; exit 1;
}

ip netns exec alpha "$lab/stl" masque-helper listen --config "$cfg_a" > "$lab/listener.log" 2>&1 &
listener_pid=$!
ip netns exec beta "$lab/stl" masque-helper dial --config "$cfg_b" > "$lab/dialer.log" 2>&1 &
dialer_pid=$!
private_works() {
  ip netns exec alpha ping -q -c 2 -W 2 10.252.97.2 >/dev/null 2>&1 &&
  ip netns exec beta ping -q -c 2 -W 2 10.252.97.1 >/dev/null 2>&1
}
ready=0
for attempt in $(seq 1 15); do
  if private_works; then ready=1; break; fi
  sleep 0.2
done
if [[ $ready != 1 ]]; then
  echo 'Bilateral native TUN traffic did not establish' >&2
  tail -30 "$lab/listener.log" "$lab/dialer.log" >&2
  exit 1
fi
echo 'PASS: native MASQUE public TLS TUN and bilateral private ICMP'

# Stock curl negotiates H2 with no client certificate on the same listener.
meta=$(ip netns exec beta curl --noproxy '*' --http2 -sS --max-time 5 \
  --cacert "$ca" --output "$lab/get.txt" --write-out '%{http_code}:%{http_version}' \
  https://198.51.100.21:59443/)
[[ $meta == 200:2 && $(cat "$lab/get.txt") == 'STL MASQUE HTTP/2 endpoint' ]] || {
  echo "Anonymous first-party H2 GET failed: $meta" >&2; exit 1;
}
meta=$(ip netns exec beta curl --noproxy '*' --http2 --head -sS --max-time 5 \
  --cacert "$ca" --output "$lab/head.txt" --write-out '%{http_code}:%{http_version}' \
  https://198.51.100.21:59443/)
[[ $meta == 200:2 ]] || { echo "Anonymous first-party H2 HEAD failed: $meta" >&2; exit 1; }
echo 'PASS: genuine HTTP/2 GET/HEAD without client certificate'

ip netns exec alpha python3 -m http.server 38812 --bind 10.252.97.1 > "$lab/tcp.log" 2>&1 &
http_pid=$!
tcp_ok=0
for attempt in $(seq 1 15); do
  if ip netns exec beta curl --noproxy '*' -fsS --max-time 3 \
       http://10.252.97.1:38812/ > "$lab/tcp-response.txt" 2>"$lab/tcp-error.log"; then
    tcp_ok=1; break
  fi
  sleep 0.15
done
[[ $tcp_ok == 1 ]] || { cat "$lab/tcp-error.log" >&2; exit 1; }
grep -q '<!DOCTYPE HTML>' "$lab/tcp-response.txt" || {
  echo "Private TCP application response missing" >&2; exit 1;
}
echo 'PASS: private TCP HTTP application transfer'

ip netns exec beta python3 -u -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("10.252.97.2",38921))
s.settimeout(5)
data,peer=s.recvfrom(4096)
assert data==b"masque-udp-test"
s.sendto(b"masque-udp-ack",peer)
' > "$lab/udp.log" 2>&1 &
udp_pid=$!
sleep 0.15
ip netns exec alpha python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(5)
s.bind(("10.252.97.1",0))
s.sendto(b"masque-udp-test",("10.252.97.2",38921))
assert s.recv(4096)==b"masque-udp-ack"
'
wait "$udp_pid"
udp_pid=
echo 'PASS: private UDP request/ack over native MASQUE TUN'

kill -9 "$dialer_pid" 2>/dev/null || :
wait "$dialer_pid" 2>/dev/null || :
dialer_pid=
ip netns exec beta "$lab/stl" masque-helper dial --config "$cfg_b" > "$lab/dialer-restart.log" 2>&1 &
dialer_pid=$!
ready=0
for attempt in $(seq 1 15); do
  if private_works; then ready=1; break; fi
  sleep 0.2
done
[[ $ready == 1 ]] || { tail -30 "$lab/dialer-restart.log" >&2; exit 1; }
echo 'PASS: same protected helper identity restart and bilateral recovery'

# This source-built helper lab does not exercise PID1 systemd or actual
# canonical Engine Create/Import; Engine tests separately cover State/Remove.
kill "$dialer_pid" "$listener_pid" 2>/dev/null || :
wait "$dialer_pid" "$listener_pid" 2>/dev/null || :
dialer_pid= listener_pid=
for attempt in $(seq 1 15); do
  if ! ip netns exec alpha ip link show stlm0123456789a >/dev/null 2>&1 &&
     ! ip netns exec beta ip link show stlm0123456789a >/dev/null 2>&1; then
    echo 'PASS: exact owned TUNs retire when both helpers stop'
    exit 0
  fi
  sleep 0.2
done
echo 'TUN survived helper exit unexpectedly' >&2
exit 1
