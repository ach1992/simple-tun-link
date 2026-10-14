#!/usr/bin/env bash
# Privileged real TCP data-socket device-bind evidence, entirely inside a
# fresh, --network none disposable Docker guest on native AMD64/ARM64.
# Never execute on an agent, production machine, or external WAN peer.
set -Eeuo pipefail
umask 077

if [[ ${STL_E2E_DISPOSABLE_HOST:-} != approved ||
      ${STL_E2E_THROUGHPUT_BIND:-} != approved || $EUID -ne 0 ]]; then
  echo 'REFUSED: explicit disposable-container throughput acceptance required' >&2
  exit 2
fi
for tool in ip iperf3 strace python3 timeout mktemp ss; do
  command -v "$tool" >/dev/null || { echo "THROUGHPUT_BIND_PREREQUISITE_MISSING=$tool" >&2; exit 2; }
done
[[ -z "$(ip -4 route show default)" ]] || {
  echo 'REFUSED: throughput guest must not have a default or external route' >&2
  exit 2
}
# Older iperf3 3.10 could bind only the CONTROL TCP socket. Do not accept
# native evidence from a version that predates the 3.11 data socket fix.
version="$(iperf3 --version 2>/dev/null | head -n 1)"
if [[ ! $version =~ ^iperf\ 3\.([0-9]+)(\.[0-9]+)?\  ]]; then
  echo 'REFUSED: unknown disposable iperf3 version' >&2
  exit 2
fi
minor="${BASH_REMATCH[1]}"
if (( 10#$minor < 11 )); then
  echo 'REFUSED: disposable proof requires iperf3 3.11+ TCP data-socket binding' >&2
  exit 2
fi
printf 'THROUGHPUT_BIND_IPERF_VERSION=%s\n' "$version"

temp="$(mktemp -d /tmp/stl-throughput-proof.XXXXXXXX)"
suffix="${temp##*.}"
ns_a="stlt${suffix}a"
ns_b="stlt${suffix}b"
created_a=0
created_b=0
server_pid=''
host_default_before="$(ip -4 route show default)"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if [[ $server_pid =~ ^[0-9]+$ ]]; then
    # Only the PID created by this script, never a discovered daemon.
    if kill -0 "$server_pid" 2>/dev/null; then
      kill "$server_pid" 2>/dev/null || rc=1
    fi
    wait "$server_pid" 2>/dev/null || true
  fi
  if ((created_b)); then
    ip netns del "$ns_b" || rc=1
  fi
  if ((created_a)); then
    ip netns del "$ns_a" || rc=1
  fi
  [[ "$(ip -4 route show default)" == "$host_default_before" ]] || {
    echo 'REFUSED: disposable guest host route changed' >&2
    rc=1
  }
  if [[ $temp == /tmp/stl-throughput-proof.* && -d $temp ]]; then
    rm -rf -- "$temp" || rc=1
  fi
  echo "THROUGHPUT_BIND_DISPOSABLE_CLEANUP_EXIT=$rc"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ip netns list | awk '{print $1}' | grep -Fxe "$ns_a" -e "$ns_b" >/dev/null; then
  echo 'REFUSED: namespace identity collision' >&2
  exit 2
fi

ip netns add "$ns_a"
created_a=1
ip netns add "$ns_b"
created_b=1

# Intended isolated Link analogue: stltdataa <-> stltdatab.
# Deliberate second decoy path: stltdecoya <-> stltdecoyb.
# Neither namespace has a default route or physical interface.
ip -n "$ns_a" link add stltdataa type veth peer name stltdatab
ip -n "$ns_a" link set stltdatab netns "$ns_b"
ip -n "$ns_a" link add stltdecoya type veth peer name stltdecoyb
ip -n "$ns_a" link set stltdecoyb netns "$ns_b"
ip -n "$ns_a" addr add 10.90.19.1/30 dev stltdataa
ip -n "$ns_b" addr add 10.90.19.2/30 dev stltdatab
ip -n "$ns_a" addr add 10.90.20.1/30 dev stltdecoya
ip -n "$ns_b" addr add 10.90.20.2/30 dev stltdecoyb
for ns in "$ns_a" "$ns_b"; do ip -n "$ns" link set lo up; done
ip -n "$ns_a" link set stltdataa up
ip -n "$ns_b" link set stltdatab up
ip -n "$ns_a" link set stltdecoya up
ip -n "$ns_b" link set stltdecoyb up
ip -n "$ns_a" -4 route get 10.90.19.2 | grep -F 'dev stltdataa' >/dev/null
ip -n "$ns_a" -4 route get 10.90.20.2 | grep -F 'dev stltdecoya' >/dev/null

ip -n "$ns_a" -j -s link show dev stltdataa > "$temp/intended_before.json"
ip -n "$ns_a" -j -s link show dev stltdecoya > "$temp/decoy_before.json"

# Peer listener exists only by explicit test authorization and only at the
# synthetic private Link Address; the test cannot reach an external peer.
ip netns exec "$ns_b" iperf3 --server --bind 10.90.19.2   --port 5201 --one-off --json > "$temp/server.json" 2> "$temp/server.err" &
server_pid=$!
listening=0
for _ in $(seq 1 50); do
  if ip netns exec "$ns_b" ss -Hltn 'sport = :5201' | grep -F '10.90.19.2' >/dev/null; then
    listening=1
    break
  fi
  sleep 0.1
done
((listening)) || { echo 'THROUGHPUT_BIND_SERVER_UNAVAILABLE' >&2; exit 1; }

# Exactly the same client argv contract used by the STL command after
# exact-owner/route/explicit-consent checks. strace observes *both* TCP
# control and DATA socket calls rather than relying on iperf3 exit alone.
timeout --signal=TERM 15s ip netns exec "$ns_a"   strace -f -qq -s 100 -e trace=setsockopt,connect   -o "$temp/client.trace"   iperf3 --client 10.90.19.2     --bind 10.90.19.1 --bind-dev stltdataa     --port 5201 --time 2 --connect-timeout 2000 --json     > "$temp/client.json" 2> "$temp/client.err"
wait "$server_pid"
server_pid=''
ip -n "$ns_a" -j -s link show dev stltdataa > "$temp/intended_after.json"
ip -n "$ns_a" -j -s link show dev stltdecoya > "$temp/decoy_after.json"

python3 - "$temp" <<'PY'
import json, pathlib, re, sys
base=pathlib.Path(sys.argv[1])
trace=(base/"client.trace").read_text()
# iperf3 TCP client opens a CONTROL socket and then an independent DATA
# socket, both to the exact peer TCP/5201. Require two DISTINCT socket FDs
# used in both a successful SO_BINDTODEVICE and a TCP connect to that peer.
bound=set(re.findall(
    r'setsockopt\((\d+), SOL_SOCKET, SO_BINDTODEVICE, "stltdataa[^"]*", \d+\)\s*=\s*0',
    trace))
connected=set(re.findall(
    r'connect\((\d+), \{sa_family=AF_INET, sin_port=htons\(5201\), '
    r'sin_addr=inet_addr\("10\.90\.19\.2"\)\}, \d+\)\s*=\s*'
    r'(?:0|-1 EINPROGRESS)',
    trace))
if len(bound & connected) < 2:
    raise SystemExit("FAILED: TCP CONTROL and DATA sockets were not both SO_BINDTODEVICE bound")

def transmitted(path):
    rows=json.loads((base/path).read_text())
    if len(rows)!=1:
        raise SystemExit("FAILED: ambiguous namespace interface statistics")
    stats=rows[0].get("stats64") or rows[0].get("stats")
    if not stats or "tx" not in stats:
        raise SystemExit("FAILED: kernel interface counters absent")
    return int(stats["tx"]["bytes"])
intended=transmitted("intended_after.json")-transmitted("intended_before.json")
decoy=transmitted("decoy_after.json")-transmitted("decoy_before.json")
data=json.loads((base/"client.json").read_text())
sent=data.get("end",{}).get("sum_sent",{}).get("bytes",0)
received=data.get("end",{}).get("sum_received",{}).get("bytes",0)
if min(intended,sent,received) < 2*1024*1024 or decoy >= 8192:
    raise SystemExit(f"FAILED: data escaped intended device or throughput incomplete: intended={intended} decoy={decoy} sent={sent} received={received}")
print("THROUGHPUT_TCP_CONTROL_AND_DATA_DEVICE_BOUND=PASS")
print(f"THROUGHPUT_INTENDED_TX_BYTES={intended}")
print(f"THROUGHPUT_DECOY_TX_BYTES={decoy}")
print("THROUGHPUT_DATA_PATH_LOCAL_NETNS=PASS")
PY
