#!/usr/bin/env bash
# Disposable GitHub-hosted Linux only. Never run against a managed field Link.
# Proves real-systemd extended execution-flag readback and deadline behavior.
set -euo pipefail

: "${GITHUB_RUN_ID:?Only allowed on an ephemeral GitHub Actions runner}"
: "${GITHUB_RUN_ATTEMPT:?Missing GitHub Actions run identity}"
test -x /usr/bin/ping
test ! -e /sys/class/net/stlwg0123456789
command -v tc >/dev/null
command -v ip >/dev/null

unit="stl-wss-probe-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.service"
ns="stl-wss-probe-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
snapshot="$(mktemp -t stl-wss-disposable-show.XXXXXXXX)"
cleanup() {
  sudo systemctl stop "$unit" >/dev/null 2>&1 || :
  sudo ip netns del "$ns" >/dev/null 2>&1 || :
  rm -f "$snapshot"
}
trap cleanup EXIT

# The canonical managed Link interface is intentionally absent; this probe
# must fail, be ignored and leave the service active across a restart.
sudo systemd-run --unit="${unit%.service}" --collect \
  --description='STL disposable post-start policy acceptance' \
  --property=Type=exec \
  --property=Restart=on-failure \
  --property=RestartSec=2s \
  --property=NoNewPrivileges=yes \
  --property=PrivateTmp=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property='ExecStartPost=-/usr/bin/ping -q -n -I stlwg0123456789 -s 8 -c 8 -i 0.25 -W 1 -w 3 10.99.1.2' \
  /usr/bin/sleep 90

verify_unit() {
  local legacy extended main
  legacy="$(sudo systemctl show "$unit" -p ExecStartPost --value)"
  extended="$(sudo systemctl show "$unit" -p ExecStartPostEx --value)"
  main="$(sudo systemctl show "$unit" -p ExecStartEx --value)"
  test "$(sudo systemctl show "$unit" -p ActiveState --value)" = active
  # Exact legacy and extended forms with only fail-ignored post-start flags.
  grep -Fq 'argv[]=/usr/bin/ping -q -n -I stlwg0123456789 -s 8 -c 8 -i 0.25 -W 1 -w 3 10.99.1.2 ; ignore_errors=yes ;' <<< "$legacy"
  grep -Fq 'argv[]=/usr/bin/ping -q -n -I stlwg0123456789 -s 8 -c 8 -i 0.25 -W 1 -w 3 10.99.1.2 ; flags=ignore-failure ;' <<< "$extended"
  grep -Fq 'argv[]=/usr/bin/sleep 90 ; flags= ;' <<< "$main"
  # Reject additional flags even if the legacy property would hide them.
  if grep -Eq 'fully-privileged|no-env-expand|no-setuid|ambient|via-shell' <<< "$extended"; then
    echo 'Unexpected privileged post-start execution' >&2
    exit 1
  fi
  if grep -Eq 'fully-privileged|no-env-expand|no-setuid|ambient|via-shell' <<< "$main"; then
    echo 'Unexpected privileged main execution' >&2
    exit 1
  fi
}
verify_unit
sudo systemctl restart "$unit"
verify_unit

# Verify every unsupported executable lifecycle hook is absent on a real
# disposable transient unit; systemd 249 omits unknown newer properties.
# Include both legacy and extended forms and never inspect a field host.
foreign_hooks='ExecCondition,ExecConditionEx,ExecStartPre,ExecStartPreEx,ExecReload,ExecReloadEx,ExecReloadPost,ExecReloadPostEx,ExecStop,ExecStopEx,ExecStopPost,ExecStopPostEx'
IFS=',' read -ra hooks <<< "$foreign_hooks"
for hook in "${hooks[@]}"; do
  observed="$(sudo systemctl show "$unit" --property="$hook" --value)"
  if [ -n "$observed" ]; then
    echo "Unexpected lifecycle hook: $hook" >&2
    exit 1
  fi
done
sudo systemctl show "$unit" --no-pager \
  --property="LoadState,ActiveState,Description,Transient,ExecStart,ExecStartEx,ExecStartPost,ExecStartPostEx,Environment,Type,Restart,RestartUSec,NoNewPrivileges,PrivateTmp,ProtectSystem,ProtectHome,CollectMode,${foreign_hooks}" > "$snapshot"
# The Go test uses the production parser and exact command/flag verifiers
# against the actual saved systemctl output from each disposable runner.
STL_WSS_DISPOSABLE_UNIT_READBACK="$snapshot" \
  go test ./internal/carrier/wss -run '^TestWSSDisposableSystemdUnitReadback$' -count=1

# Exercise the same ping arguments under safe interfaces and measure true
# wall-clock time. These probes never target the real field private Link.
python3 - <<'PY'
import subprocess
import time

base = ['/usr/bin/ping', '-q', '-n', '-s', '8', '-c', '8', '-i', '0.25', '-W', '1', '-w', '3']
def check(label, interface, target, success, max_time=3.8):
    start = time.monotonic()
    result = subprocess.run(base + ['-I', interface, target],
                            capture_output=True, text=True, timeout=4.3)
    elapsed = time.monotonic() - start
    if (result.returncode == 0) != success or elapsed > max_time:
        raise SystemExit(f'{label}: rc={result.returncode}, elapsed={elapsed:.3f}s')
    print(f'{label}: rc={result.returncode}, elapsed={elapsed:.3f}s')

check('NO_INTERFACE_FAST_FAILURE', 'stlwg0123456789', '10.99.1.2', False, 2.0)
check('LOOPBACK_EIGHT_REPLIES', 'lo', '127.0.0.1', True)
PY

# Isolated namespace only: dummy unresolved neighbor exercises the full
# timeout without contacting an external address. Netem introduces late /
# partial local responses. No host firewall, real interface or route changes.
sudo ip netns add "$ns"
sudo ip -n "$ns" link set lo up
sudo ip -n "$ns" link add wg-probe-dummy type dummy
sudo ip -n "$ns" addr add 10.177.88.1/30 dev wg-probe-dummy
sudo ip -n "$ns" link set wg-probe-dummy up
sudo ip netns exec "$ns" python3 - <<'PY'
import subprocess
import time

args = ['/usr/bin/ping', '-q', '-n', '-I', 'wg-probe-dummy', '-s', '8',
        '-c', '8', '-i', '0.25', '-W', '1', '-w', '3', '10.177.88.2']
start = time.monotonic()
result = subprocess.run(args, capture_output=True, text=True, timeout=4.3)
elapsed = time.monotonic() - start
if result.returncode == 0 or not (1.5 <= elapsed <= 3.8):
    raise SystemExit(f'UNREACHABLE_BOUNDED: rc={result.returncode}, elapsed={elapsed:.3f}s')
print(f'UNREACHABLE_BOUNDED: rc={result.returncode}, elapsed={elapsed:.3f}s')
PY
sudo ip netns exec "$ns" tc qdisc add dev lo root netem delay 400ms loss 25%
sudo ip netns exec "$ns" python3 - <<'PY'
import subprocess
import time

args = ['/usr/bin/ping', '-q', '-n', '-I', 'lo', '-s', '8',
        '-c', '8', '-i', '0.25', '-W', '1', '-w', '3', '127.0.0.1']
start = time.monotonic()
result = subprocess.run(args, capture_output=True, text=True, timeout=4.3)
elapsed = time.monotonic() - start
if result.returncode not in (0, 1) or not (0.7 <= elapsed <= 3.8):
    raise SystemExit(f'DELAYED_PARTIAL_BOUNDED: rc={result.returncode}, elapsed={elapsed:.3f}s')
print(f'DELAYED_PARTIAL_BOUNDED: rc={result.returncode}, elapsed={elapsed:.3f}s')
PY

echo 'DISPOSABLE_SYSTEMD_EXEC_FLAGS_AND_PING_DEADLINE=PASS'
