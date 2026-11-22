#!/usr/bin/env bash
# Owned per-container eth0-only egress fault injection; never host netns.
# Test actual TCP integrity on BOTH independently managed outer UDP and
# outer ICMP Links under delay, packet drop and reordering. Private UDP
# retains ordinary best-effort semantics; previous no-loss UDP tests verify
# payload delivery, this fault test does not falsely promise retransmission.
set -euo pipefail
a=stl-spoof-262-a
b=stl-spoof-262-b
for name in "$a" "$b";do
  [[ "$(incus info "$name" | awk '/^Type:/{print $2}')" == container ]] || exit 1
done
ap=$(incus info "$a" | awk '/^PID:/{print $2}')
bp=$(incus info "$b" | awk '/^PID:/{print $2}')
[[ "$ap" =~ ^[0-9]+$ && "$bp" =~ ^[0-9]+$ ]] || exit 1
for pid in "$ap" "$bp";do
  nsenter -t "$pid" -n -- tc qdisc show dev eth0 |
    grep -q '^qdisc noqueue 0: root' ||
    { echo "refuse replacing foreign qdisc on guest PID $pid" >&2; exit 1; }
done
done_a=false
done_b=false
cleanup(){
 if [[ "$done_a" == true ]];then nsenter -t "$ap" -n -- tc qdisc del dev eth0 root 2>/dev/null || true; fi
 if [[ "$done_b" == true ]];then nsenter -t "$bp" -n -- tc qdisc del dev eth0 root 2>/dev/null || true; fi
}
trap cleanup EXIT
for guest in "$a" "$b";do
  incus exec "$guest" -- test -x /usr/local/bin/stl262-traffic ||
    { echo "missing task-owned traffic verifier on $guest" >&2; exit 1; }
done
nsenter -t "$ap" -n -- tc qdisc add dev eth0 root netem delay 12ms 3ms loss 1% reorder 4% 30%
done_a=true
nsenter -t "$bp" -n -- tc qdisc add dev eth0 root netem delay 12ms 3ms loss 1% reorder 4% 30%
done_b=true
echo 'TEST: lab-only netem both directions 12ms+3ms jitter, 1% loss, 4% reorder. Other kernel qdiscs untouched.'
for guest in "$a" "$b";do
 incus exec "$guest" -- tc qdisc show dev eth0
done
# Existing test helper produces random private TCP payloads and has receiver
# verify a SHA-256 digest, then sender independently checks returned digest.
incus exec "$b" -- sh -c 'nohup timeout 55s /usr/local/bin/stl262-traffic --mode server --protocol tcp --local 10.245.62.2 --port 55301 --connections 2 > /tmp/stl262-netem-udp-b.log 2>&1 < /dev/null &'
incus exec "$a" -- /usr/local/bin/stl262-traffic --mode client --protocol tcp --local 10.245.62.1 --peer 10.245.62.2 --port 55301 --connections 2 --bytes 2097152
incus exec "$b" -- cat /tmp/stl262-netem-udp-b.log
incus exec "$a" -- sh -c 'nohup timeout 55s /usr/local/bin/stl262-traffic --mode server --protocol tcp --local 10.245.64.1 --port 55302 --connections 2 > /tmp/stl262-netem-icmp-a.log 2>&1 < /dev/null &'
incus exec "$b" -- /usr/local/bin/stl262-traffic --mode client --protocol tcp --local 10.245.64.2 --peer 10.245.64.1 --port 55302 --connections 2 --bytes 2097152
incus exec "$a" -- cat /tmp/stl262-netem-icmp-a.log
for pid in "$ap" "$bp";do
 nsenter -t "$pid" -n -- tc -s qdisc show dev eth0
done
cleanup
done_a=false
done_b=false
for pid in "$ap" "$bp";do
  nsenter -t "$pid" -n -- tc qdisc show dev eth0 |
    grep -q '^qdisc noqueue 0: root' ||
    { echo 'task-owned netem cleanup could not be verified' >&2; exit 1; }
done
incus exec "$a" -- rm -f -- /tmp/stl262-netem-icmp-a.log
incus exec "$b" -- rm -f -- /tmp/stl262-netem-udp-b.log
echo 'PASS: TCP inside BOTH encrypted outer profiles is integrity-checked under netem jitter/loss/reorder; exact lab qdiscs and output logs removed'
