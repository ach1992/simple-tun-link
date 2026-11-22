#!/usr/bin/env bash
# Optional isolated QA only. Run as privileged operator on the private
# task-owned Incus host; it never targets public endpoints or other guests.
set -euo pipefail
umask 077 # confidential original Setup Code is staged only in root-only files

a=stl-spoof-262-a
b=stl-spoof-262-b
a_real=10.244.62.207
b_real=10.244.62.198
a_inner=10.245.88.1
b_inner=10.245.88.2
a_ep=42401
b_ep=42402
code_path=/root/stl/spoof/stl262-matrix.code
host_handoff=/tmp/stl262-spoof-matrix-handoff.code
current_id=''
clean() {
    if [[ -n "$current_id" ]]; then
        for node in "$b" "$a"; do
            incus exec "$node" -- /usr/local/bin/stl link remove "$current_id" --confirm "$current_id" --json ||
                printf 'WARN: cleanup of %s on %s needs diagnosis\n' "$current_id" "$node" >&2
        done
    fi
    for node in "$a" "$b"; do
        incus exec "$node" -- rm -f "$code_path"
    done
    rm -f "$host_handoff"
}
trap clean EXIT

for node in "$a" "$b"; do
    incus exec "$node" -- test -x /usr/local/bin/stl262-traffic
done

# A verified payload transfer in both directions goes beyond "socket opened"
# or "private Ping worked": it exercises actual encrypted TUN TCP/UDP data.
check_payload() {
    local protocol=$1 sender=$2 receiver=$3 source_ip=$4 target_ip=$5 port=$6
    local amount=( -connections 2 -bytes 524288 -datagrams 50 )
    incus exec "$receiver" -- timeout 50 /usr/local/bin/stl262-traffic \
        -mode server -protocol "$protocol" -local "$target_ip" \
        -peer "$source_ip" -port "$port" "${amount[@]}" &
    local receiver_pid=$!
    sleep 0.35
    if ! incus exec "$sender" -- timeout 45 /usr/local/bin/stl262-traffic \
        -mode client -protocol "$protocol" -local "$source_ip" \
        -peer "$target_ip" -port "$port" "${amount[@]}"; then
        wait "$receiver_pid" || true
        return 1
    fi
    wait "$receiver_pid"
    printf 'PAYLOAD_OK %s %s->%s port=%d\n' "$protocol" "$sender" "$receiver" "$port"
}

for profile in udp icmp tcp gre ipip proto58 proto58-echo l2tpv3; do
    printf 'PROFILE_START %s\n' "$profile"
    current_id=''
    test ! -e "$host_handoff"
    for node in "$a" "$b"; do
        incus exec "$node" -- test ! -e "$code_path"
    done

    output=$(incus exec "$a" -- /usr/local/bin/stl link create-spoof \
        --creator "${a_real}:${a_ep}" --recipient "${b_real}:${b_ep}" \
        --creator-private "$a_inner" --recipient-private "$b_inner" \
        --outer "$profile" --sources /root/stl/spoof/sources.txt \
        --output "$code_path" --json)
    current_id=$(printf '%s' "$output" | python3 -c 'import json,sys;print(json.load(sys.stdin)["link_id"])')
    incus file pull "$a$code_path" "$host_handoff" >/dev/null
    chmod 0600 "$host_handoff"
    incus file push --mode 0600 "$host_handoff" "$b$code_path" >/dev/null
    incus exec "$b" -- chown 0:0 "$code_path"
    incus exec "$b" -- /usr/local/bin/stl link import-spoof \
        --setup "$code_path" --sources /root/stl/spoof/sources.txt --json

    ok=0
    for attempt in $(seq 1 35); do
        sa=$(incus exec "$a" -- /usr/local/bin/stl link spoof-status "$current_id" --json)
        sb=$(incus exec "$b" -- /usr/local/bin/stl link spoof-status "$current_id" --json)
        if printf '%s\n%s\n' "$sa" "$sb" | python3 -c '
import json,sys
states=[json.loads(line)["runtime"] for line in sys.stdin if line.strip()]
sys.exit(0 if len(states)==2 and all(
 x.get("state")=="CONNECTED" and x.get("selected_profile")==sys.argv[1]
 and x.get("bilateral_confirmed") for x in states
) else 1)' "$profile"; then
            ok=1
            break
        fi
        sleep 1
    done
    if ((ok==0));then
        printf 'PROFILE_FAILED %s; A=%s; B=%s\n' "$profile" "$sa" "$sb" >&2
        exit 1
    fi
    incus exec "$a" -- ping -q -c 2 -W 2 "$b_inner"
    incus exec "$b" -- ping -q -c 2 -W 2 "$a_inner"
    check_payload tcp "$a" "$b" "$a_inner" "$b_inner" 55311
    check_payload udp "$a" "$b" "$a_inner" "$b_inner" 55312
    check_payload tcp "$b" "$a" "$b_inner" "$a_inner" 55311
    check_payload udp "$b" "$a" "$b_inner" "$a_inner" 55312
    echo "PROFILE_OK_FULL_L3 $profile $current_id"
    clean
    current_id=''
done
echo ALL_RAW_PROFILES_AUTHENTICATED_ICMP_TCP_UDP_BIDIRECTIONAL_OK
