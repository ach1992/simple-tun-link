#!/usr/bin/env bash
# Owned isolated Incus acceptance only. Intentionally *never* touches the
# stable STL executable or previous four persistent Spoof Links.
set -euo pipefail
umask 077
a=stl-spoof-262-smart-a
b=stl-spoof-262-smart-b
binary=/usr/local/bin/stl
a_ip=10.244.62.221
b_ip=10.244.62.222
a_alt=10.244.62.223
b_alt=10.244.62.224
code=/root/stl/spoof/stl262-smart-test.code
handoff=/tmp/stl262-smart-test-handoff.code
id=''
addresses_a=()
addresses_b=()
routes_a=()
routes_b=()
mtu_limit=${MTU_LIMIT:-}
private_mtu=${PRIVATE_MTU:-auto}
manage_ingress=${MANAGE_INGRESS:-0}
simulate_block=${SIMULATE_BLOCK:-1}
reboot_peer=${REBOOT_PEER:-0}
rotate_source=${ROTATE_SOURCE:-0}
sources_changed=0
firewall_a=()
firewall_b=()
managed_flags=()
if [[ "$manage_ingress" == 1 ]]; then managed_flags=(--device eth0 --manage-ingress);fi
clean() {
    local original=$?
    trap - EXIT
    if ((sources_changed));then
        incus exec "$a" -- /bin/sh -c 'printf "198.18.0.11\n198.18.0.99\n" > /root/stl/spoof/sources.next; chmod 0600 /root/stl/spoof/sources.next; mv -f /root/stl/spoof/sources.next /root/stl/spoof/sources.txt' || echo "WARN failed Source restore A" >&2
    fi
    if [[ -n "$id" ]]; then
      incus exec "$b" -- "$binary" link remove "$id" --confirm "$id" --json >/dev/null || echo "WARN cleanup B $id" >&2
      incus exec "$a" -- "$binary" link remove "$id" --confirm "$id" --json >/dev/null || echo "WARN cleanup A $id" >&2
    fi
    if [[ "$manage_ingress" == 1 && -n "$id" ]]; then
      for h in "$a" "$b"; do
        if incus exec "$h" -- iptables -S INPUT | grep -F "stl:spoof:$id:";then
          echo "WARN OWNED_FIREWALL_RULES_REMAIN_AFTER_LINK_REMOVE $h $id" >&2
        else
          echo "LINK_OWNED_FIREWALL_ABSENT_AFTER_REMOVE $h"
        fi
      done
    fi
    for address in "${firewall_a[@]}"; do incus exec "$a" -- iptables -D INPUT -d "$address/32" -j DROP || echo "WARN cleanup A firewall $address" >&2;done
    for address in "${firewall_b[@]}"; do incus exec "$b" -- iptables -D INPUT -d "$address/32" -j DROP || echo "WARN cleanup B firewall $address" >&2;done
    for peer in "${routes_a[@]}"; do if [[ -n "$(incus exec "$a" -- ip route show "$peer/32")" ]];then incus exec "$a" -- ip route del "$peer/32" dev eth0 || echo "WARN cleanup route A:$peer" >&2;fi;done
    for peer in "${routes_b[@]}"; do if [[ -n "$(incus exec "$b" -- ip route show "$peer/32")" ]];then incus exec "$b" -- ip route del "$peer/32" dev eth0 || echo "WARN cleanup route B:$peer" >&2;fi;done
    for ip in "${addresses_a[@]}"; do incus exec "$a" -- ip addr del "$ip/24" dev eth0 || echo "WARN cleanup addr A:$ip" >&2; done
    for ip in "${addresses_b[@]}"; do incus exec "$b" -- ip addr del "$ip/24" dev eth0 || echo "WARN cleanup addr B:$ip" >&2; done
    incus exec "$a" -- rm -f "$code" || true
    incus exec "$b" -- rm -f "$code" || true
    rm -f "$handoff"
    echo "LAB_CLEANUP_EXIT_CODE $original"
    exit "$original"
}
trap clean EXIT
for guest in "$a" "$b"; do
    incus exec "$guest" -- test -x "$binary"
    incus exec "$guest" -- test ! -e "$code"
done
test ! -e "$handoff"
for address in "$a_ip" "$a_alt"; do
    incus exec "$a" -- /bin/sh -c "! ip -4 addr show dev eth0 | grep -q '$address/'"
    incus exec "$a" -- ip addr add "$address/24" dev eth0
    addresses_a+=("$address")
done
for address in "$b_ip" "$b_alt"; do
    incus exec "$b" -- /bin/sh -c "! ip -4 addr show dev eth0 | grep -q '$address/'"
    incus exec "$b" -- ip addr add "$address/24" dev eth0
    addresses_b+=("$address")
done
echo "LAB_OWNED_REAL_IPS_READY"
if [[ "$manage_ingress" == 1 && "$simulate_block" == 1 ]];then
    for address in "$a_ip" "$a_alt"; do
       incus exec "$a" -- iptables -I INPUT 1 -d "$address/32" -j DROP
       firewall_a+=("$address")
    done
    for address in "$b_ip" "$b_alt"; do
       incus exec "$b" -- iptables -I INPUT 1 -d "$address/32" -j DROP
       firewall_b+=("$address")
    done
    if incus exec "$a" -- ping -q -c 1 -W 1 "$b_alt" >/dev/null 2>&1;then
        echo "FAIL: unmanaged direct underlay unexpectedly reachable through test DROP" >&2
        exit 1
    fi
    if incus exec "$b" -- ping -q -c 1 -W 1 "$a_alt" >/dev/null 2>&1;then
        echo "FAIL: unmanaged direct return underlay unexpectedly reachable through test DROP" >&2
        exit 1
    fi
    echo "TEST_OWNED_DEFAULT_DROP_VERIFIED_BOTH_WAYS"
fi
if [[ -n "$mtu_limit" ]]; then
  [[ "$mtu_limit" =~ ^[0-9]+$ ]] && ((mtu_limit>=576 && mtu_limit<=1500))
  for peer in "$b_ip" "$b_alt"; do
    [[ -z "$(incus exec "$a" -- ip route show "$peer/32")" ]]
    incus exec "$a" -- ip route add "$peer/32" dev eth0 mtu "$mtu_limit"
    routes_a+=("$peer")
  done
  for peer in "$a_ip" "$a_alt"; do
    [[ -z "$(incus exec "$b" -- ip route show "$peer/32")" ]]
    incus exec "$b" -- ip route add "$peer/32" dev eth0 mtu "$mtu_limit"
    routes_b+=("$peer")
  done
  echo "TASK_ONLY_REMOTE_HOST_ROUTES_MTU $mtu_limit"
fi

out=$(incus exec "$a" -- "$binary" link create-spoof \
    --creator "$a_ip:48001" --recipient "$b_ip:48002" \
    --creator-alts "$a_alt:48011" --recipient-alts "$b_alt:48012" \
    --creator-private 10.245.100.1 --recipient-private 10.245.100.2 \
    --outer auto --mtu "$private_mtu" --discovery-pps 48 --background-pps 16 "${managed_flags[@]}" \
    --sources /root/stl/spoof/sources.txt --output "$code" --json)
id=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["link_id"])')
echo "LINK_CREATED_PENDING $id"
incus file pull "$a$code" "$handoff" >/dev/null 2>&1
chmod 0600 "$handoff"
incus file push --mode 0600 "$handoff" "$b$code" >/dev/null 2>&1
incus exec "$b" -- chown 0:0 "$code"
incus exec "$b" -- "$binary" link import-spoof \
    --setup "$code" --mtu "$private_mtu" --discovery-pps 48 --background-pps 16 "${managed_flags[@]}" \
    --sources /root/stl/spoof/sources.txt --json
echo "LINK_IMPORTED"
if [[ "$manage_ingress" == 1 ]];then
    expected=0
    if [[ "$simulate_block" == 1 ]];then expected=14;fi
    for h in "$a" "$b";do
        count=$(incus exec "$h" -- iptables -S INPUT | grep -Fc "stl:spoof:$id:" || true)
        if ((count!=expected));then echo "FAIL expected $expected owned auto ingress rules on $h got $count" >&2;exit 1;fi
        echo "LINK_OWNED_FIREWALL_RULES_VERIFIED $h count=$count"
    done
fi

verify_auto_mtu() {
    local sa sb
    for attempt in $(seq 1 75); do
        sa=$(incus exec "$a" -- "$binary" link spoof-status "$id" --json)
        sb=$(incus exec "$b" -- "$binary" link spoof-status "$id" --json)
        if printf '%s\n%s\n' "$sa" "$sb" | python3 -c '
import json,sys
states=[json.loads(line)["runtime"] for line in sys.stdin if line.strip()]
ok=len(states)==2 and all(
 x.get("state")=="CONNECTED"
 and x.get("mtu_status")=="VERIFIED_DF_DELIVERY"
 and 576 <= x.get("verified_mtu",0) <= 1100
 and x.get("verified_mtu")==x.get("tunnel_mtu")
 for x in states)
sys.exit(0 if ok else 1)';then
            echo "VERIFIED_AUTO_MTU A=$(printf '%s' "$sa" | python3 -c 'import json,sys;print(json.load(sys.stdin)["runtime"]["verified_mtu"])') B=$(printf '%s' "$sb" | python3 -c 'import json,sys;print(json.load(sys.stdin)["runtime"]["verified_mtu"])')"
            return 0
        fi
        sleep 1
    done
    echo "AUTO_MTU_NOT_VERIFIED_A $(printf '%s' "$sa" | python3 -c 'import json,sys;print(json.load(sys.stdin)["runtime"])')"
    echo "AUTO_MTU_NOT_VERIFIED_B $(printf '%s' "$sb" | python3 -c 'import json,sys;print(json.load(sys.stdin)["runtime"])')"
    return 1
}

check_payload() {
    local protocol=$1 sender=$2 receiver=$3 source_ip=$4 target_ip=$5 port=$6
    local amount=( -connections 2 -bytes 262144 -datagrams 20 )
    incus exec "$receiver" -- timeout 50 /usr/local/bin/stl262-traffic -mode server -protocol "$protocol" \
        -local "$target_ip" -peer "$source_ip" -port "$port" "${amount[@]}" &
    local receiver_pid=$!
    sleep 0.25
    if ! incus exec "$sender" -- timeout 45 /usr/local/bin/stl262-traffic -mode client -protocol "$protocol" \
        -local "$source_ip" -peer "$target_ip" -port "$port" "${amount[@]}";then
        wait "$receiver_pid" || true
        return 1
    fi
    wait "$receiver_pid"
    echo "PRIVATE_PAYLOAD_OK $protocol $sender->$receiver port=$port"
}

check_connected() {
    local desired_a=${1:-} desired_b=${2:-}
    local sa sb
    for attempt in $(seq 1 55); do
        sa=$(incus exec "$a" -- "$binary" link spoof-status "$id" --json)
        sb=$(incus exec "$b" -- "$binary" link spoof-status "$id" --json)
        if printf '%s\n%s\n' "$sa" "$sb" | python3 -c '
import json,sys
states=[json.loads(line)["runtime"] for line in sys.stdin if line.strip()]
ok=len(states)==2 and all(x.get("state")=="CONNECTED" and x.get("bilateral_confirmed") and x.get("authenticated") for x in states)
if ok and sys.argv[1]:
    ok=states[0].get("selected_destination")==sys.argv[1]
if ok and sys.argv[2]:
    ok=states[1].get("selected_destination")==sys.argv[2]
sys.exit(0 if ok else 1)' "$desired_a" "$desired_b";then
            echo "CONNECTED_BILATERAL A=$(printf '%s' "$sa" | python3 -c 'import sys,json; r=json.load(sys.stdin)["runtime"];print(r.get("selected_source"),r.get("selected_profile"),r.get("selected_destination"),"learned",r.get("recent_working_paths"),"probes",r.get("scanned_probes"))') B=$(printf '%s' "$sb" | python3 -c 'import sys,json; r=json.load(sys.stdin)["runtime"];print(r.get("selected_source"),r.get("selected_profile"),r.get("selected_destination"),"learned",r.get("recent_working_paths"),"probes",r.get("scanned_probes"))')"
            return 0
        fi
        sleep 1
    done
    echo "FAILED_EXPECTED_A $desired_a B $desired_b"
    echo "STATUS_A $(printf '%s' "$sa" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)["runtime"]))')"
    echo "STATUS_B $(printf '%s' "$sb" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin)["runtime"]))')"
    return 1
}

check_connected
incus exec "$a" -- ping -q -c 2 -W 2 10.245.100.2
incus exec "$b" -- ping -q -c 2 -W 2 10.245.100.1
echo "INITIAL_PRIVATE_ICMP_BOTH_OK"
if [[ -n "$mtu_limit" && "$private_mtu" == "auto" ]];then verify_auto_mtu;fi
# Drop only test-owned primary endpoint IPs. The four existing Links use
# 10.244.62.207/198 and are completely unaffected.
incus exec "$a" -- ip addr del "$a_ip/24" dev eth0
addresses_a=("$a_alt")
incus exec "$b" -- ip addr del "$b_ip/24" dev eth0
addresses_b=("$b_alt")
echo "TASK_ONLY_PRIMARY_DESTINATIONS_REMOVED"
check_connected "$b_alt:48012" "$a_alt:48011"
incus exec "$a" -- ping -q -c 3 -W 2 10.245.100.2
incus exec "$b" -- ping -q -c 3 -W 2 10.245.100.1
echo "ALT_DESTINATION_BILATERAL_PRIVATE_OK"
if [[ -n "$mtu_limit" && "$private_mtu" == "auto" ]];then verify_auto_mtu;fi
check_payload tcp "$a" "$b" 10.245.100.1 10.245.100.2 55311
check_payload udp "$a" "$b" 10.245.100.1 10.245.100.2 55312
check_payload tcp "$b" "$a" 10.245.100.2 10.245.100.1 55311
check_payload udp "$b" "$a" 10.245.100.2 10.245.100.1 55312
echo "PRIVATE_TCP_UDP_BIDIRECTIONAL_OK"
if [[ "$rotate_source" == 1 ]];then
    prior=$(incus exec "$a" -- "$binary" link spoof-status "$id" --json | python3 -c 'import sys,json;print(json.load(sys.stdin)["runtime"]["selected_source"])')
    if [[ "$prior" == 198.18.0.11 ]];then other=198.18.0.99;else other=198.18.0.11;fi
    incus exec "$a" -- /bin/sh -c "printf '%s\n' '$other' > /root/stl/spoof/sources.next;chmod 0600 /root/stl/spoof/sources.next;mv -f /root/stl/spoof/sources.next /root/stl/spoof/sources.txt"
    sources_changed=1
    after=''
    for attempt in $(seq 1 60);do
       check_connected "$b_alt:48012" "$a_alt:48011" >/dev/null 2>&1 || true
       after=$(incus exec "$a" -- "$binary" link spoof-status "$id" --json | python3 -c 'import sys,json;r=json.load(sys.stdin)["runtime"];print(r.get("selected_source","") if r.get("state")=="CONNECTED" else "")')
       if [[ "$after" == "$other" ]];then break;fi
       sleep 1
    done
    if [[ "$after" != "$other" ]];then echo "SOURCE_ROTATION_FAILED $prior->$other observed=$after" >&2;exit 1;fi
    incus exec "$a" -- ping -q -c 2 -W 2 10.245.100.2
    echo "SOURCE_CHANGED_SAME_LINK_AND_RECONNECTED old=$prior new=$other"
    incus exec "$a" -- /bin/sh -c 'printf "198.18.0.11\n198.18.0.99\n" > /root/stl/spoof/sources.next; chmod 0600 /root/stl/spoof/sources.next; mv -f /root/stl/spoof/sources.next /root/stl/spoof/sources.txt'
    sources_changed=0
fi
if [[ "$reboot_peer" == 1 ]];then
   incus restart "$b"
   echo "TASK_OWNED_PEER_REBOOTED"
   incus exec "$b" -- ip addr add "$b_alt/24" dev eth0
   incus exec "$b" -- "$binary" link restore --all
   check_connected "$b_alt:48012" "$a_alt:48011"
   incus exec "$a" -- ping -q -c 3 -W 2 10.245.100.2
   incus exec "$b" -- ping -q -c 3 -W 2 10.245.100.1
   echo "REBOOT_RESTORED_SAME_LINK_AND_HISTORY"
fi
