#!/usr/bin/env bash
# Task-owned isolated container network namespaces only.
# Complete intentional loss of BOTH Spoof outer profiles (only the exact lab
# UDP port and ICMP type). Must not destroy committed Links; removal of this
# test's scoped rules must restore both profiles without a new offline Code.
set -euo pipefail
a=stl-spoof-262-a
b=stl-spoof-262-b
for name in "$a" "$b"; do
  [[ "$(incus info "$name" | awk '/^Type:/{print $2}')" == container ]] ||
    { echo "refusing non-container $name" >&2; exit 1; }
done
ap=$(incus info "$a" | awk '/^PID:/{print $2}')
bp=$(incus info "$b" | awk '/^PID:/{print $2}')
[[ "$ap" =~ ^[0-9]+$ && "$bp" =~ ^[0-9]+$ ]] || exit 1
cleanup(){
  nsenter -t "$ap" -n -- nft delete table ip stl262_full_outage 2>/dev/null || true
  nsenter -t "$bp" -n -- nft delete table ip stl262_full_outage 2>/dev/null || true
}
trap cleanup EXIT
for pid in "$ap" "$bp"; do
  if nsenter -t "$pid" -n -- nft list table ip stl262_full_outage >/dev/null 2>&1;then
    echo 'refusing existing table with same name' >&2
    exit 1
  fi
done
for pid in "$ap" "$bp";do
  nsenter -t "$pid" -n -- nft add table ip stl262_full_outage
  nsenter -t "$pid" -n -- nft 'add chain ip stl262_full_outage pre { type filter hook prerouting priority -300; policy accept; }'
  nsenter -t "$pid" -n -- nft add rule ip stl262_full_outage pre iifname eth0 ip protocol icmp counter drop
done
nsenter -t "$ap" -n -- nft add rule ip stl262_full_outage pre iifname eth0 udp dport 42001 counter drop
nsenter -t "$bp" -n -- nft add rule ip stl262_full_outage pre iifname eth0 udp dport 42002 counter drop
echo 'TEST: private-lab outer UDP ports 42001/42002 + all outer ICMP now Drop on BOTH A/B'
sleep 21
for pair in "stl-spoof-262-a lnk_7857849bbaf2a3eac73974e7c6ab8011" "stl-spoof-262-b lnk_7857849bbaf2a3eac73974e7c6ab8011" "stl-spoof-262-a lnk_e2da95c1350006922208d2e938a69a52" "stl-spoof-262-b lnk_e2da95c1350006922208d2e938a69a52";do
  read -r guest link <<< "$pair"
  echo "OUTAGE $guest $link"
  incus exec "$guest" -- /usr/local/bin/stl link spoof-status "$link" --json |
    python3 -c 'import json,sys;s=json.load(sys.stdin);r=s["runtime"];print("ready",s["managed_helper_ready"],"status",r["state"]);assert s["managed_helper_ready"] and not r["bilateral_confirmed"]'
done
for pid in "$ap" "$bp";do
  nsenter -t "$pid" -n -- nft list chain ip stl262_full_outage pre
done
cleanup
echo 'TEST: rules removed. Original durable managed Links must reconnect without Setup Code'
sleep 22
for pair in "stl-spoof-262-a lnk_7857849bbaf2a3eac73974e7c6ab8011" "stl-spoof-262-b lnk_7857849bbaf2a3eac73974e7c6ab8011" "stl-spoof-262-a lnk_e2da95c1350006922208d2e938a69a52" "stl-spoof-262-b lnk_e2da95c1350006922208d2e938a69a52";do
  read -r guest link <<< "$pair"
  echo "RECOVERED $guest $link"
  incus exec "$guest" -- /usr/local/bin/stl link spoof-status "$link" --json |
    python3 -c 'import json,sys;r=json.load(sys.stdin)["runtime"];print(r["state"]);assert r["authenticated"] and r["bilateral_confirmed"]'
done
incus exec "$a" -- ping -n -c 2 -W 2 10.245.62.2
incus exec "$b" -- ping -n -c 2 -W 2 10.245.64.1
echo 'PASS: complete outer paths loss then UDP+ICMP Link self-recovery with no re-pair'
