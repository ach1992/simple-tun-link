#!/usr/bin/env bash
# Test-only, container network-namespaces ONLY. Filter just the original
# lab Spoof UDP Link's two receive ports to prove an independent ICMP Link.
# All tables are private to task-owned Incus container netns, never host netns.
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
  nsenter -t "$ap" -n -- nft delete table ip stl262_icmp_only 2>/dev/null || true
  nsenter -t "$bp" -n -- nft delete table ip stl262_icmp_only 2>/dev/null || true
}
trap cleanup EXIT
for pid in "$ap" "$bp"; do
  if nsenter -t "$pid" -n -- nft list table ip stl262_icmp_only >/dev/null 2>&1; then
    printf 'lab nft table already exists, refusing adoption\n' >&2
    exit 1
  fi
done
for pid in "$ap" "$bp"; do
  nsenter -t "$pid" -n -- nft add table ip stl262_icmp_only
  nsenter -t "$pid" -n -- nft 'add chain ip stl262_icmp_only input { type filter hook input priority -150; policy accept; }'
done
nsenter -t "$ap" -n -- nft add rule ip stl262_icmp_only input udp dport 42001 drop
nsenter -t "$bp" -n -- nft add rule ip stl262_icmp_only input udp dport 42002 drop
printf 'TASK-OWNED NETNS: only UDP receiver ports 42001 and 42002 dropped. ICMP route and other services untouched.\n'
sleep 18

first='lnk_7857849bbaf2a3eac73974e7c6ab8011'
icmp='lnk_e2da95c1350006922208d2e938a69a52'
printf 'UDP A: '
incus exec "$a" -- /usr/local/bin/stl link spoof-status "$first" --json | python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"]);assert not x["bilateral_confirmed"]'
printf 'UDP B: '
incus exec "$b" -- /usr/local/bin/stl link spoof-status "$first" --json | python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"]);assert not x["bilateral_confirmed"]'
for name in "$a" "$b"; do
  printf '%s ICMP: ' "$name"
  incus exec "$name" -- /usr/local/bin/stl link spoof-status "$icmp" --json |
    python3 -c 'import json,sys;x=json.load(sys.stdin)["runtime"];print(x["state"]);assert x["bilateral_confirmed"] and x["authenticated"]'
done
incus exec "$a" -- ping -n -c 3 -W 2 10.245.64.2
printf 'PASS: only ICMP-based encrypted Link survived selective UDP-port Drop\n'
