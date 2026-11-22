#!/usr/bin/env bash
# Test-only: proof of independent UDP Spoof Link while the ICMP profile's
# outer unsolicited Echo Replies are blocked. Scoped to task-owned container netns.
set -euo pipefail
a=stl-spoof-262-a
b=stl-spoof-262-b
for name in "$a" "$b"; do
  [[ "$(incus info "$name" | awk '/^Type:/{print $2}')" == container ]] ||
    { printf 'not a task-owned isolated container: %s\n' "$name" >&2; exit 1; }
done
ap=$(incus info "$a" | awk '/^PID:/{print $2}')
bp=$(incus info "$b" | awk '/^PID:/{print $2}')
[[ "$ap" =~ ^[0-9]+$ && "$bp" =~ ^[0-9]+$ ]] || exit 1
cleanup() {
  nsenter -t "$ap" -n -- nft delete table ip stl262_udp_only 2>/dev/null || true
  nsenter -t "$bp" -n -- nft delete table ip stl262_udp_only 2>/dev/null || true
}
trap cleanup EXIT
for pid in "$ap" "$bp"; do
  if nsenter -t "$pid" -n -- nft list table ip stl262_udp_only >/dev/null 2>&1; then
    printf 'foreign lab nft table already exists; refusing adoption\n' >&2
    exit 1
  fi
done
for pid in "$ap" "$bp"; do
  nsenter -t "$pid" -n -- nft add table ip stl262_udp_only
  nsenter -t "$pid" -n -- nft 'add chain ip stl262_udp_only pre { type filter hook prerouting priority -300; policy accept; }'
  nsenter -t "$pid" -n -- nft add rule ip stl262_udp_only pre iifname eth0 ip protocol icmp counter drop
done
printf 'TASK-OWNED NETNS: IPv4 ICMP blocked at eth0 PREROUTING (pre socket); UDP ports untouched.\n'
sleep 19
for pid in "$ap" "$bp"; do
  nsenter -t "$pid" -n -- nft list chain ip stl262_udp_only pre
done
udp='lnk_7857849bbaf2a3eac73974e7c6ab8011'
icmp='lnk_e2da95c1350006922208d2e938a69a52'
for name in "$a" "$b"; do
  printf '%s ICMP Link: ' "$name"
  incus exec "$name" -- /usr/local/bin/stl link spoof-status "$icmp" --json |
    python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"]);assert not x["bilateral_confirmed"]'
  printf '%s UDP Link: ' "$name"
  incus exec "$name" -- /usr/local/bin/stl link spoof-status "$udp" --json |
    python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"]);assert x["bilateral_confirmed"] and x["authenticated"]'
done
incus exec "$b" -- ping -n -c 2 -W 2 10.245.62.1
printf 'PASS: UDP encrypted Link survived selective ICMP outer Drop\n'
