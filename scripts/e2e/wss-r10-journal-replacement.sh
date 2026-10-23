#!/usr/bin/env bash
# Sourced exclusively by the authenticated disposable R1 nsroot harness,
# after a real kernel WG creation with a pre-commit SIGKILL left the ORIGINAL
# WSS guard, WG and fsynced initial crash journal on alpha.
[[ -n "${STL_WSS_R1_TEST_GUARD:-}" && $(id -u) == 0 &&
   $(readlink /proc/self/ns/user) != "$(cat "$lab/host-user-ns-id")" &&
   $(readlink /proc/self/ns/net) != "$(cat "$lab/host-ns-id")" ]] ||
  { echo "R10 requires authenticated disposable user/network namespaces" >&2; exit 2; }
old=lnk_0123456789abcdef0123456789abcdef
next=lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')
jq -e --arg old "$old" '(.links|length)==0 and
  (.wss_crash_operations|length)==1 and
  .wss_crash_operations[0].intent.id==$old and
  .wss_crash_operations[0].operation=="ensure" and
  .wss_crash_operations[0].had_committed_link==false and
  (.wss_crash_operations[0].nonce|length)==32 and
  ([.wss_crash_operations[0].resources[]|select(.kind=="firewall" and .key=="wss/nft/"+$old)]|length)==1' \
  "$lab/alpha-state/state.json" >/dev/null
original_journal=$(jq -Sc --arg old "$old" '.wss_crash_operations[]|select(.intent.id==$old)' "$lab/alpha-state/state.json")
test -n "$original_journal"
ip netns exec alpha wg show stlwg0123456789 listen-port | grep -qx 51821
ip netns exec alpha nft -j list table inet "$guard" >/dev/null
test -d "$lab/alpha-state/credentials/wss/$old"
test -f "$lab/alpha-state/credentials/$old.wgkey"
echo "R10_REAL_INITIAL_WG_CRASH_WITH_PROTECTED_JOURNAL_AND_GUARD"

# One new independently issued WSS peer pair. This is NOT old journal
# reconciliation or name-based adoption: the original remains quarantined.
jq --arg id "$next" '.link_id=$id |
    .addresses.local="10.76.0.1/30" | .addresses.peer="10.76.0.2/30" |
    .listen_port=51831 | .peer_port=51832 |
    .tcp_port=59445 | .remote_forward_udp_port=53031' \
  "$lab/alpha/create.json" > "$lab/alpha/new-create.json"
invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/new-receiver.json \
  < "$lab/alpha/new-create.json" > "$lab/alpha/new-created.log"
invoke beta link preview-wss --stdin --json < "$lab/alpha-state/handoff/new-receiver.json" \
  > "$lab/beta/new-preview.json"
confirm=$(grep -m1 '^{' "$lab/beta/new-preview.json" | jq -r .confirmation_sha256)
[[ "$confirm" =~ ^[0-9a-f]{64}$ ]]
invoke beta link import-wss --stdin --confirm "$confirm" \
  < "$lab/alpha-state/handoff/new-receiver.json" > "$lab/beta/new-imported.log"
jq -e --arg id "$next" '(.links|length)==1 and
 ([.links[]|select(.desired.id==$id)]|length)==1 and
 ([.wss_crash_operations[]?|select(.intent.id==$id)]|length)==0' "$lab/alpha-state/state.json" >/dev/null

sleep 7
ip netns exec beta ping -I 10.76.0.2 -c 2 -W 3 10.76.0.1 >/dev/null
ip netns exec alpha ping -I 10.76.0.1 -c 2 -W 3 10.76.0.2 >/dev/null
ip netns exec alpha python3 -u -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(12);s.bind(("10.76.0.1",39182));d,p=s.recvfrom(1024);s.sendto(d+b"/ack",p);s.close()' > "$lab/alpha/new-udp.log" 2>&1 &
udp_pid=$!
sleep 0.3
ip netns exec beta python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("10.76.0.2",0));s.settimeout(8);s.sendto(b"fresh-journal",("10.76.0.1",39182));d,p=s.recvfrom(1024);assert d==b"fresh-journal/ack"'
wait "$udp_pid"
echo "R10_REAL_NEW_WSS_ICMP_AND_UDP_WITH_OLD_GUARD_AND_JOURNAL"

# The ORIGINAL has no committed Link, and must not be falsely marked
# superseded, adopted, repaired or retired by the new healthy pair.
if invoke alpha link supersede-wss "$old" --replacement "$next" --confirm "$old" \
  --json > "$lab/alpha/uncommitted-supersede-denied.log" 2>&1; then
  echo "R10 invented supersession of an uncommitted original" >&2; exit 1
fi
jq -c '{"schema_version":3,"link":.wss_crash_operations[0].intent}' \
  "$lab/alpha-state/state.json" > "$lab/alpha/old-retry.json"
if invoke alpha link ensure --stdin < "$lab/alpha/old-retry.json" \
  > "$lab/alpha/old-retry-denied.log" 2>&1; then
  echo "R10 replayed original with indeterminate host effects" >&2; exit 1
fi
if invoke alpha link retire-wss "$old" --confirm "$old" \
  > "$lab/alpha/old-retire-denied.log" 2>&1; then
  echo "R10 retired unproven original WSS credentials" >&2; exit 1
fi
[[ $(jq -Sc --arg old "$old" '.wss_crash_operations[]|select(.intent.id==$old)' "$lab/alpha-state/state.json") == "$original_journal" ]]
ip netns exec alpha wg show stlwg0123456789 listen-port | grep -qx 51821
ip netns exec alpha nft -j list table inet "$guard" >/dev/null
test -d "$lab/alpha-state/credentials/wss/$old"
test -f "$lab/alpha-state/credentials/$old.wgkey"
jq -e '(.removal_receipts//[]|length)==0' "$lab/alpha-state/state.json" >/dev/null
ip netns exec beta ping -I 10.76.0.2 -c 2 -W 3 10.76.0.1 >/dev/null
echo "R10_PASS_UNCOMMITTED_REAL_KERNEL_CRASH_ALLOWS_DISJOINT_NEW_WSS_PAIR"
