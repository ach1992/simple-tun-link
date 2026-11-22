#!/usr/bin/env bash
# Isolated task-owned KVM VM acceptance for Spoof Issue 262. No public egress.
set -euo pipefail
umask 077
project=stl262-spoof-private
A=stl262-native-a
B=stl262-native-b
code=/root/stl/spoof/stl262-vm-matrix.code
handoff=/srv/ai-workspace/stl262-native-qa/matrix-private.code
id=''
guest() { local host=$1; shift; incus exec "$host" --project "$project" -- "$@" < /dev/null; }
cleanup_one() {
  local rc=0
  if [[ -n "$id" ]]; then
    for host in "$B" "$A"; do
      if ! guest "$host" /usr/local/bin/stl link remove "$id" --confirm "$id" --json; then rc=1; echo "ERR_LINK_REMOVE $host $id" >&2; fi
    done
  fi
  id=''
  for host in "$A" "$B"; do
    guest "$host" /bin/rm -f "$code" || rc=1
  done
  rm -f "$handoff"
  return "$rc"
}
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  cleanup_one || status=1
  echo "VM_MATRIX_CLEANUP_EXIT $status"
  exit "$status"
}
trap cleanup EXIT
payload() {
  local proto=$1 sender=$2 receiver=$3 src=$4 dst=$5 port=$6 pid
  guest "$receiver" timeout 50 /usr/local/bin/stl262-traffic -mode server -protocol "$proto" -local "$dst" -peer "$src" -port "$port" -connections 1 -bytes 262144 -datagrams 16 &
  pid=$!
  sleep 0.55
  if ! guest "$sender" timeout 45 /usr/local/bin/stl262-traffic -mode client -protocol "$proto" -local "$src" -peer "$dst" -port "$port" -connections 1 -bytes 262144 -datagrams 16; then
    wait "$pid" || true
    return 1
  fi
  wait "$pid"
}
for profile in udp icmp tcp gre ipip proto58 proto58-echo l2tpv3; do
  echo "VM_PROFILE_START $profile"
  id=''
  test ! -e "$handoff"
  for host in "$A" "$B"; do
    guest "$host" test ! -e "$code"
  done
  out=$(guest "$A" /usr/local/bin/stl link create-spoof \
    --creator 10.246.62.165:48401 --recipient 10.246.62.245:48402 \
    --creator-private 10.245.108.1 --recipient-private 10.245.108.2 \
    --outer "$profile" --sources /root/stl/spoof/sources.txt \
    --output "$code" --discovery-pps 24 --background-pps 8 --json)
  id=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["link_id"])')
  incus file pull "$A$code" "$handoff" --project "$project" >/dev/null 2>&1 < /dev/null
  chmod 0600 "$handoff"
  incus file push "$handoff" "$B$code" --project "$project" --uid 0 --gid 0 --mode 0600 >/dev/null 2>&1 < /dev/null
  guest "$B" /usr/local/bin/stl link import-spoof --setup "$code" --sources /root/stl/spoof/sources.txt --discovery-pps 24 --background-pps 8 --json
  valid=0
  for attempt in $(seq 1 45); do
    sa=$(guest "$A" /usr/local/bin/stl link spoof-status "$id" --json)
    sb=$(guest "$B" /usr/local/bin/stl link spoof-status "$id" --json)
    if printf '%s\n%s\n' "$sa" "$sb" | python3 -c '
import json,sys
rs=[json.loads(s)["runtime"] for s in sys.stdin]
profile=sys.argv[1]
sys.exit(0 if len(rs)==2 and all(x.get("state")=="CONNECTED" and x.get("authenticated") and x.get("bilateral_confirmed") and x.get("selected_profile")==profile for x in rs) else 1)' "$profile"; then valid=1; break; fi
    sleep 1
  done
  if (( valid==0 )); then echo "VM_PROFILE_AUTH_FAILED $profile" >&2; exit 1; fi
  guest "$A" ping -q -c 2 -W 2 10.245.108.2 | grep 'packets transmitted'
  guest "$B" ping -q -c 2 -W 2 10.245.108.1 | grep 'packets transmitted'
  payload tcp "$A" "$B" 10.245.108.1 10.245.108.2 55461
  payload udp "$A" "$B" 10.245.108.1 10.245.108.2 55462
  payload tcp "$B" "$A" 10.245.108.2 10.245.108.1 55463
  payload udp "$B" "$A" 10.245.108.2 10.245.108.1 55464
  echo "VM_PROFILE_ENCRYPTED_L3_PASS $profile $id"
  cleanup_one
  echo "VM_PROFILE_EXACT_CLEANUP_PASS $profile"
  for host in "$A" "$B"; do
    guest "$host" /bin/sh -c 'test "$( /usr/local/bin/stl link list --json | python3 -c "import sys,json; print(len(json.load(sys.stdin)[\"links\"]))" )" -eq 1'
  done
done
echo ALL_EIGHT_PROFILES_NATIVE_VM_ENCRYPTED_ICMP_TCP_UDP_BIDIRECTIONAL_PASS
