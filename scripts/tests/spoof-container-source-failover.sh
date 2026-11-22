#!/usr/bin/env bash
# Isolated two-container acceptance: one previously reachable SOURCE ceases
# to deliver without disappearing from the user's file; the SAME Link should
# independently rediscover another source, without re-pairing.
set -euo pipefail
a=stl-spoof-262-a
b=stl-spoof-262-b
[[ "$(incus info "$a" | awk '/^Type:/{print $2}')" == container ]] || exit 1
[[ "$(incus info "$b" | awk '/^Type:/{print $2}')" == container ]] || exit 1
bp=$(incus info "$b" | awk '/^PID:/{print $2}')
[[ "$bp" =~ ^[0-9]+$ ]] || exit 1
cleanup() { nsenter -t "$bp" -n -- nft delete table ip stl262_source_failover 2>/dev/null || true; }
trap cleanup EXIT
if nsenter -t "$bp" -n -- nft list table ip stl262_source_failover >/dev/null 2>&1;then
 echo 'test-only nft table already exists; refusing adoption' >&2
 exit 1
fi
incus exec "$a" -- sh -c 'printf "198.18.0.11\n198.18.0.99\n" > /root/stl/spoof/sources.txt; chmod 0600 /root/stl/spoof/sources.txt'
sleep 5
nsenter -t "$bp" -n -- nft add table ip stl262_source_failover
nsenter -t "$bp" -n -- nft 'add chain ip stl262_source_failover input { type filter hook input priority -150; policy accept; }'
nsenter -t "$bp" -n -- nft add rule ip stl262_source_failover input iifname eth0 ip saddr 198.18.0.11 drop
printf 'Source .11 packets are now Drop on B only; .99 still crosses this lab bridge. No real host filtering changed.\n'
sleep 27
udp='lnk_7857849bbaf2a3eac73974e7c6ab8011'
icmp='lnk_e2da95c1350006922208d2e938a69a52'
for id in "$udp" "$icmp";do
 echo "A $id"
 incus exec "$a" -- /usr/local/bin/stl link spoof-status "$id" --json |
   python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"],x.get("selected_source"),x["source_candidates"]);assert x["bilateral_confirmed"] and x["selected_source"]=="198.18.0.99" and x["source_candidates"]==2'
 echo "B $id"
 incus exec "$b" -- /usr/local/bin/stl link spoof-status "$id" --json |
   python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"],x.get("selected_source"),x["source_candidates"]);assert x["bilateral_confirmed"]'
done
incus exec "$a" -- ping -n -c 2 -W 2 10.245.62.2
incus exec "$b" -- ping -n -c 2 -W 2 10.245.64.1
printf 'PASS: both independently managed Links recovered from upstream Source failure without file deletion or new Setup Code\n'
