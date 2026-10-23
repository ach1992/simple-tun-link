#!/usr/bin/env bash
# Sourced ONLY by the verified rootless WSS R1 nsroot harness, after the
# ORIGINAL pair was genuinely committed on both isolated peers.
# This is a disposable acceptance fixture, not an operator recovery command.
[[ -n "${STL_WSS_R1_TEST_GUARD:-}" && $(id -u) == 0 &&
   $(readlink /proc/self/ns/user) != "$(cat "$lab/host-user-ns-id")" &&
   $(readlink /proc/self/ns/net) != "$(cat "$lab/host-ns-id")" ]] ||
  { echo "R9 requires the authenticated disposable user/network namespace" >&2; exit 2; }
mode=${STL_WSS_R9_REPLACEMENT_TEST:-}
case "$mode" in success|fail-apply) ;; *) echo "invalid R9 mode" >&2; exit 2;; esac
old=lnk_0123456789abcdef0123456789abcdef
next=lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
guard=$(python3 -c 'import hashlib;print("stlwss_"+hashlib.sha256(b"lnk_0123456789abcdef0123456789abcdef").hexdigest()[:16])')

# A healthy unrelated STL-managed WSS Link must continue to carry actual
# private-IP traffic through failure and supersession of the old original.
jq '.link_id="lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
    .addresses.local="10.77.0.1/30" | .addresses.peer="10.77.0.2/30" |
    .listen_port=51841 | .peer_port=51842 |
    .tcp_port=59449 | .remote_forward_udp_port=53041' \
  "$lab/alpha/create.json" > "$lab/alpha/sibling-create.json"
invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/sibling.json \
  < "$lab/alpha/sibling-create.json" > "$lab/alpha/sibling-created.log"
invoke beta link preview-wss --stdin --json < "$lab/alpha-state/handoff/sibling.json" \
  > "$lab/beta/sibling-preview.json"
sibling_confirm=$(grep -m1 '^{' "$lab/beta/sibling-preview.json" | jq -r .confirmation_sha256)
[[ "$sibling_confirm" =~ ^[0-9a-f]{64}$ ]]
invoke beta link import-wss --stdin --confirm "$sibling_confirm" \
  < "$lab/alpha-state/handoff/sibling.json" > "$lab/beta/sibling-imported.log"
sleep 7
ip netns exec alpha ping -I 10.77.0.1 -c 2 -W 3 10.77.0.2 >/dev/null
ip netns exec beta ping -I 10.77.0.2 -c 2 -W 3 10.77.0.1 >/dev/null
echo "R9_REAL_UNRELATED_MANAGED_WSS_SIBLING_TRAFFIC"

# Preserve real original State, its issued TLS/private keys, nft guard and
# ORIGINAL kernel WG in a new namespace, DOWN and invisible from alpha.
original_a=$(jq -c --arg id "$old" '.links[]|select(.desired.id==$id)' "$lab/alpha-state/state.json")
original_b=$(jq -c --arg id "$old" '.links[]|select(.desired.id==$id)' "$lab/beta-state/state.json")
test -n "$original_a" && test -n "$original_b"
jq -e --arg id "$old" '(.links|length)==2 and (.wss_crash_operations//[]|length)==0 and
  (.removal_receipts//[]|length)==0 and
  ([.links[]|select(.desired.id==$id)|.owned_resources[]|select(.kind=="udp-listen-port" and .key=="51821")]|length)==1' "$lab/alpha-state/state.json" >/dev/null
ip netns add gamma
ip netns exec gamma ip link set lo up
ip -n alpha link set stlwg0123456789 netns gamma
[[ -z "$(ip netns exec alpha wg show interfaces | grep -F stlwg0123456789)" ]]
ip netns exec gamma wg show interfaces | grep -qx stlwg0123456789
ip -n gamma link show stlwg0123456789 | grep -q 'state DOWN'
if ip netns exec alpha ss -H -u -l -n | grep -Fq ':51821'; then
  echo "R9 moved-DOWN old WG retained a misleading visible socket" >&2; exit 1
fi
ip netns exec alpha nft -j list table inet "$guard" >/dev/null
test -d "$lab/alpha-state/credentials/wss/$old"
test -f "$lab/alpha-state/credentials/$old.wgkey"
echo "R9_REAL_HIDDEN_DOWN_ORIGINAL_PRESERVED"

for side in alpha beta; do
  jq -c --arg id "$old" '{"schema_version":3,"link":(.links[]|select(.desired.id==$id)|.desired)}' \
    "$lab/$side-state/state.json" > "$lab/$side/old-ensure.json"
done
if invoke alpha link ensure --stdin < "$lab/alpha/old-ensure.json" > "$lab/alpha/old-hidden-ensure-denied.log" 2>&1; then
  echo "R9 recreated locally hidden original" >&2; exit 1
fi
if invoke alpha link remove "$old" --confirm "$old" > "$lab/alpha/old-hidden-remove-denied.log" 2>&1; then
  echo "R9 removed original without kernel extinction" >&2; exit 1
fi

# A disjoint new identity is not free to claim the old UDP listener even
# though the old device and socket disappeared from alpha's inventory.
jq '.link_id="lnk_cccccccccccccccccccccccccccccccc" |
    .addresses.local="10.78.0.1/30" | .addresses.peer="10.78.0.2/30" |
    .listen_port=51821 | .peer_port=51832 |
    .tcp_port=59447 | .remote_forward_udp_port=53033' \
  "$lab/alpha/create.json" > "$lab/alpha/reuse-old-port.json"
if invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/reused.json \
  < "$lab/alpha/reuse-old-port.json" > "$lab/alpha/reused-port-denied.log" 2>&1; then
  echo "R9 replaced old reservation using a different identity" >&2; exit 1
fi
jq -e '(.links|length)==2 and
       ([.links[]|select(.desired.id=="lnk_cccccccccccccccccccccccccccccccc")]|length)==0' \
  "$lab/alpha-state/state.json" >/dev/null
echo "R9_OLD_UDP_RESERVATION_DENIED"

# Use the same public create/preview/import contract as any operator,
# including freshly issued mTLS CA, leaf keys and distinct WSS bearer.
jq --arg id "$next" '.link_id=$id |
    .addresses.local="10.76.0.1/30" | .addresses.peer="10.76.0.2/30" |
    .listen_port=51831 | .peer_port=51832 |
    .tcp_port=59445 | .remote_forward_udp_port=53031' \
  "$lab/alpha/create.json" > "$lab/alpha/new-create.json"

if [[ "$mode" == fail-apply ]]; then
  # The real systemd-run shim starts the NEW helper, then reports failure:
  # kernel WG, nft and helper all exist, but Engine cannot commit success.
  export STL_WSS_R2_AMBIGUOUS_TEST=helper-error
  if invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/new-receiver.json \
    < "$lab/alpha/new-create.json" > "$lab/alpha/new-apply-failed.log" 2>&1; then
    echo "R9 fault-injected new host Apply unexpectedly succeeded" >&2; exit 1
  fi
  unset STL_WSS_R2_AMBIGUOUS_TEST
  jq -e --arg id "$next" '(.links|length)==2 and
    ([.links[]|select(.desired.id==$id)]|length)==0 and
    ([.wss_crash_operations[]|select(.intent.id==$id and .operation=="ensure")]|length)==1' \
    "$lab/alpha-state/state.json" >/dev/null
  ip netns exec alpha wg show interfaces | tr "[:space:]" "\n" | grep -qx stlwgaaaaaaaaaa
  test -f "$lab/alpha/runtime/stl-wss-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service.json"
  if invoke alpha link supersede-wss "$old" --replacement "$next" --confirm "$old" \
    --json > "$lab/alpha/new-failed-supersede-denied.log" 2>&1; then
    echo "R9 failed new Apply authorized supersession" >&2; exit 1
  fi
  [[ $(jq -c --arg id "$old" '.links[]|select(.desired.id==$id)' "$lab/alpha-state/state.json") == "$original_a" ]]
  ip netns exec gamma wg show interfaces | grep -qx stlwg0123456789
  ip netns exec alpha nft -j list table inet "$guard" >/dev/null
  test -d "$lab/alpha-state/credentials/wss/$old"
  ip netns exec alpha ping -I 10.77.0.1 -c 2 -W 2 10.77.0.2 >/dev/null
  echo "R9_PASS_FAILED_NEW_REAL_APPLY_CANNOT_SUPERSEDE_OLD"
  exit 0
fi

invoke alpha link create-wss --stdin --output /var/lib/stl-r1-state/handoff/new-receiver.json \
  < "$lab/alpha/new-create.json" > "$lab/alpha/new-created.log"
invoke beta link preview-wss --stdin --json < "$lab/alpha-state/handoff/new-receiver.json" \
  > "$lab/beta/new-preview.json"
confirm=$(grep -m1 '^{' "$lab/beta/new-preview.json" | jq -r .confirmation_sha256)
[[ "$confirm" =~ ^[0-9a-f]{64}$ ]]
invoke beta link import-wss --stdin --confirm "$confirm" \
  < "$lab/alpha-state/handoff/new-receiver.json" > "$lab/beta/new-imported.log"
jq -e --arg id "$next" '([.links[]|select(.desired.id==$id)]|length)==1 and
       ([.wss_crash_operations[]?|select(.intent.id==$id)]|length)==0' "$lab/alpha-state/state.json" >/dev/null
jq -e --arg id "$next" '([.links[]|select(.desired.id==$id)]|length)==1' "$lab/beta-state/state.json" >/dev/null

# Require actual bidirectional new private-IP kernel traffic, not local
# Ensure, helper-active status or mere WireGuard key configuration.
sleep 7
ip netns exec beta ping -I 10.76.0.2 -c 3 -W 3 10.76.0.1 >/dev/null
ip netns exec alpha ping -I 10.76.0.1 -c 3 -W 3 10.76.0.2 >/dev/null
ip netns exec alpha python3 -u -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(12);s.bind(("10.76.0.1",39181));d,p=s.recvfrom(1024);s.sendto(d+b"/ack",p);s.close()' > "$lab/alpha/new-udp.log" 2>&1 &
udp_pid=$!
sleep 0.3
ip netns exec beta python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("10.76.0.2",0));s.settimeout(8);s.sendto(b"fresh-wss",("10.76.0.1",39181));d,p=s.recvfrom(1024);assert d==b"fresh-wss/ack"'
wait "$udp_pid"
echo "R9_NEW_REAL_BILATERAL_WSS_PRIVATE_IP_TRAFFIC"

for side in alpha beta; do
  invoke "$side" link supersede-wss "$old" --replacement "$next" --confirm "$old" --json \
    > "$lab/$side/superseded-result.json"
  grep -m1 '^{' "$lab/$side/superseded-result.json" | jq -e --arg old "$old" --arg next "$next" '.schema_version==1 and
    .outcome=="quarantined_old" and .changed==true and
    .old_link_id==$old and .replacement_link_id==$next and
    .old_restore_blocked==true and
    .host_mutated==false and .original_deletion_proven==false and
    .replacement_traffic_verified==false and .reboot_performed==false' \
    >/dev/null
  if invoke "$side" link status "$old" --json > "$lab/$side/old-status-denied.json" 2>&1; then
    echo "R9 old WSS reported operational after supersession" >&2; exit 1
  fi
  grep -Fq 'wss_original_superseded' "$lab/$side/old-status-denied.json"
  invoke "$side" link list --json > "$lab/$side/link-list.json"
  grep -m1 '^{' "$lab/$side/link-list.json" | jq -e --arg old "$old" --arg next "$next" '([.links[]|select(.id==$old and
      .disposition=="quarantined_old" and .superseded_by==$next)]|length)==1' \
    >/dev/null
done

for side in alpha beta; do
  if invoke "$side" link ensure --stdin < "$lab/$side/old-ensure.json" > "$lab/$side/old-resurrect-denied.log" 2>&1; then
    echo "R9 superseded original could be re-ensured" >&2; exit 1
  fi
  grep -Fq 'wss_original_superseded' "$lab/$side/old-resurrect-denied.log"
  # RestoreAll must skip the old but safely re-ensure both healthy siblings.
  invoke "$side" link restore --all > "$lab/$side/restore-healthy.log"
  ip netns exec "$side" wg show interfaces | tr "[:space:]" "\n" | grep -qx stlwgaaaaaaaaaa
done
if invoke alpha link retire-wss "$old" --confirm "$old" > "$lab/alpha/old-retire-denied.log" 2>&1; then
  echo "R9 old credentials retired without exact kernel deletion receipt" >&2; exit 1
fi
[[ $(jq -c --arg id "$old" '.links[]|select(.desired.id==$id)|del(.wss_superseded_by)' "$lab/alpha-state/state.json") == "$original_a" ]]
[[ $(jq -c --arg id "$old" '.links[]|select(.desired.id==$id)|del(.wss_superseded_by)' "$lab/beta-state/state.json") == "$original_b" ]]
jq -e --arg old "$old" --arg next "$next" '(.links|length)==3 and
   ([.links[]|select(.desired.id==$old and .wss_superseded_by==$next)]|length)==1 and
   (.wss_crash_operations//[]|length)==0 and (.removal_receipts//[]|length)==0' "$lab/alpha-state/state.json" >/dev/null
ip netns exec gamma wg show interfaces | grep -qx stlwg0123456789
ip netns exec alpha nft -j list table inet "$guard" >/dev/null
test -d "$lab/alpha-state/credentials/wss/$old"
test -f "$lab/alpha-state/credentials/$old.wgkey"
ip netns exec beta ping -I 10.76.0.2 -c 2 -W 3 10.76.0.1 >/dev/null
ip netns exec alpha ping -I 10.77.0.1 -c 2 -W 2 10.77.0.2 >/dev/null
ip netns exec beta ping -I 10.77.0.2 -c 2 -W 2 10.77.0.1 >/dev/null
echo "R9_PASS_REAL_KERNEL_NO_REBOOT_REPLACEMENT_HIDDEN_DOWN_OLD_PROTECTED"
