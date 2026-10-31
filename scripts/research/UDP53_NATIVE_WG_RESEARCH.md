# Direct UDP53 + native WireGuard research fixture

This opt-in fixture investigates one fixed public UDP flow around native kernel
WireGuard. It is research tooling, **not an STL Carrier, installer, managed Link,
production deployment or reachability guarantee**. This document records no WAN
success. Actual outcomes belong in [#125](https://github.com/ach1992/simple-tun-link/issues/125).

The controlling outcome is [#142, acceptance revision 2](https://github.com/ach1992/simple-tun-link/issues/142#issuecomment-6530229786)
and the [selected direct UDP53 continuation](https://github.com/ach1992/simple-tun-link/issues/142#issuecomment-6530028424).
Public establishment must be tested separately in each orientation. Private
traffic initiated from both endpoints over a single established Carrier does not
prove that either endpoint can establish the public transport.

Preserve [PROJECT-SPEC](../../docs/PROJECT-SPEC.md),
[ARCHITECTURE](../../docs/ARCHITECTURE.md) and
[SECURITY](../../docs/SECURITY.md). This research branch does not add a supported
backend or authorize integration, publication, automatic failover or a new TUN engine.

## Original U53-R2 source identities and responsibilities

The following hashes belong **only** to the original archived research fixture
`research/udp53-native-wg-proof@6c00e9e77b206941da132ef8e415ce16441b6c30`.
The successor recovery branch adds a strictly local fault mode and a new test;
**do not assume these original hashes describe the changed successor files**.
Recompute and review the exact active source before a test or transfer.

| File | SHA-256 | Responsibility |
| --- | --- | --- |
| `udp53_wg_adapter.py` | `f579993da61327c42477edb47ac291737fb387b594364a8f953f4bb1608ef978` | One immutable public UDP tuple, unchanged WG datagram forwarding and bounded observations |
| `udp53_fixture.py` | `e25017cb13028aead5425f78406e1861b8b9e1cdf9cd4129350c9c6aa954a268` | Owned namespace, native WG, task-private keys, public identity receipts and guarded teardown |
| `udp53_apps.py` | `77ad751883e2d87cab1a67f96752d7f6fecc51f0ed6b5f9439a4bd04daf6fb64` | Bounded private TCP/UDP traffic with independent integrity and partial-result receipts |

The adapter opens, binds and connects its public socket **before** entering the
fixture namespace. That same descriptor carries the optional introduction and
subsequent WG datagrams. Its second socket is confined to the namespace's exact
loopback WG endpoint. WG itself is created inside this namespace; no WG interface
is created in the host namespace and then moved.

The dialer can send one lazy DNS-looking introduction when its first inner WG
datagram arrives, followed by a bounded settling interval. The listener neither
introduces nor forwards early inner packets before observing an outer WG-shaped
candidate. Structural checks are not authentication: DNS replies, `READY`,
`candidate_seen`, `first_outer_rx_s` and process exit zero do not prove peer identity.
Only native WG and the independent private traffic receipts establish the relevant
security and data claims. The adapter never learns a new destination from traffic.

## Scope and admission

Use only the current authorized pair: IRPT-101 (`irpt-101`, `193.111.235.101`)
and DE-Hamed-Test (`de-hamed-test`, `91.107.246.220`). Refresh their identities,
current jobs, actual addresses and resource vacancy before effects. TR01-Test is
retired and excluded. Historical results are not current host observations.

Requirements are Linux network namespaces, native WireGuard, `python3`, `ip`,
`wg`, `ping`, `timeout` and scoped root authority for fixture setup. Existing
`/etc/wireguard` must be a root-owned real directory without group/other write
permission. The fixture creates only an exclusive `stl-u53-*` child (`0700`) and
its new key (`0600`). It uses normal `wg` pathname access compatible with that
configuration directory; it does not modify or disable AppArmor. It never reads
or rewrites installed STL State or retained production keys.

The public UDP endpoints must be free. Bind the actual public IP explicitly;
do not stop or replace an existing resolver, listener or service to free port 53.
Inspect before creating anything. No host route, firewall, sysctl, DNS policy,
SSH configuration, third relay, raw spoofing or port-pool probing is needed or
authorized by these commands. An exact platform refusal remains a stop for that
operation; do not repackage or replay it through another tool.

## Commands for one fresh generation

Run from the directory containing these three files. Commands below are foreground
commands for an explicitly tracked job/session runner. Record each job's actual
identity and completion; do not use anonymous detached processes. Keep logs and
receipts in the task's private evidence location.

```bash
RESEARCH_DIR="$(pwd)"
sha256sum udp53_wg_adapter.py udp53_fixture.py udp53_apps.py
command -v python3 ip wg ping timeout
```

Choose one orientation at a time. These exact example tuples and private addresses
must be freshly checked for availability; they are not evidence that a test ran.
Use a fresh namespace/root/key directory for a genuinely new generation. A name
collision is a refusal, not permission to delete the existing object.

| Case | Host / `SIDE` | `ROLE` | `NS` | `OUTER_BIND` | `OUTER_PEER` | `LOCAL_PRIVATE` | `PEER_PRIVATE` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `a` | IR / `ir` | `dial` | `u53-a-ir` | `193.111.235.101:53053` | `91.107.246.220:53` | `10.253.53.0` | `10.253.53.1` |
| `a` | DE / `de` | `listen` | `u53-a-de` | `91.107.246.220:53` | `193.111.235.101:53053` | `10.253.53.1` | `10.253.53.0` |
| `b` | DE / `de` | `dial` | `u53-b-de` | `91.107.246.220:53054` | `193.111.235.101:53` | `10.253.54.1` | `10.253.54.0` |
| `b` | IR / `ir` | `listen` | `u53-b-ir` | `193.111.235.101:53` | `91.107.246.220:53054` | `10.253.54.0` | `10.253.54.1` |

For example, set the variables for **Case a on IR** as follows. On its peer, use
the Case a DE row; both endpoints use the same fresh `RUN_ID`.

```bash
CASE=a
SIDE=ir
ROLE=dial
NS=u53-a-ir
OUTER_BIND=193.111.235.101:53053
OUTER_PEER=91.107.246.220:53
LOCAL_PRIVATE=10.253.53.0
PEER_PRIVATE=10.253.53.1
RUN_ID=u53-a-20261030
FIXTURE_ROOT="/tmp/stl-u53-${CASE}-${SIDE}"
KEY_DIR="/etc/wireguard/stl-u53-${CASE}-${SIDE}"
```

On each host, create and inspect the owned fixture. Setup fixes inner MTU at 1152
and uses namespace-local `/32` addresses/routes. `NAMESPACE_READY.public_key` is
public; the private key must not be printed or copied into commands/logs.

```bash
python3 "$RESEARCH_DIR/udp53_fixture.py" setup \
  --root "$FIXTURE_ROOT" --key-dir "$KEY_DIR" --name "$NS" \
  --addr "$LOCAL_PRIVATE" --peer "$PEER_PRIVATE" \
  --wg-port 42511 --local-port 42512
```

Exchange only the two `public_key` values from these independent receipts. Set
`PEER_PUBLIC_KEY` to the other endpoint's exact public value, then configure:

```bash
PEER_PUBLIC_KEY='REPLACE_WITH_OTHER_ENDPOINT_PUBLIC_KEY'
python3 "$RESEARCH_DIR/udp53_fixture.py" configure \
  --root "$FIXTURE_ROOT" --pubkey "$PEER_PUBLIC_KEY"
python3 "$RESEARCH_DIR/udp53_fixture.py" inspect --root "$FIXTURE_ROOT"
```

Configure fixes `PersistentKeepalive=0` and rejects a different peer key on the
same recorded generation. Wrong-key controls need a fresh fixture. A setup failure
can leave owned partial resources: retain its receipt and reconcile exact identity
before cleanup/retry. Do not assume every partial stage is automatically recoverable.

Start the listener adapter first, then the dialer adapter, each as its own tracked
job. Verify each `READY` tuple and namespace device/inode against the intended
fixture receipt before private traffic. `INTRO_ARGS` is empty on the listener.

```bash
INTRO_ARGS=()
if [ "$ROLE" = dial ]; then INTRO_ARGS=(--introduction); fi
timeout --signal=TERM --kill-after=5s 610s \
  python3 "$RESEARCH_DIR/udp53_wg_adapter.py" \
  --role "$ROLE" --outer-bind "$OUTER_BIND" --outer-peer "$OUTER_PEER" \
  --inner-bind 127.0.0.1:42512 --inner-peer 127.0.0.1:42511 \
  --netns-path "/run/netns/$NS" --run-id "$RUN_ID" \
  --duration 600 --max-datagram 1200 --introduction-settle 1.5 \
  "${INTRO_ARGS[@]}"
```

Start a private application server on each endpoint in separate tracked jobs:

```bash
timeout --signal=TERM --kill-after=5s 610s \
  ip netns exec "$NS" python3 "$RESEARCH_DIR/udp53_apps.py" serve \
  --run "$RUN_ID" --side "$SIDE" --bind "$LOCAL_PRIVATE" \
  --peer "$PEER_PRIVATE" --port 42053 --seconds 600 --tcp-seconds 60
```

Generate the first private packet **only from the selected public dialer**. Require
matching WG handshake evidence before escalating; successful packet submission or
DNS-looking responses do not satisfy this gate.

```bash
timeout 15s ip netns exec "$NS" ping -n -I "$LOCAL_PRIVATE" \
  -c 3 -W 2 "$PEER_PRIVATE"
python3 "$RESEARCH_DIR/udp53_fixture.py" inspect --root "$FIXTURE_ROOT"
```

After authenticated small exchanges work, invoke the following from each endpoint
to establish application initiation in both directions. Reconcile independent
server and client receipts by `run`, `phase`, sender, byte count and SHA-256.

```bash
timeout --signal=TERM --kill-after=5s 65s \
  ip netns exec "$NS" python3 "$RESEARCH_DIR/udp53_apps.py" tcp \
  --run "$RUN_ID" --side "$SIDE" --bind "$LOCAL_PRIVATE" \
  --peer "$PEER_PRIVATE" --port 42053 --phase "smoke-${SIDE}" \
  --bytes 65536 --tcp-seconds 60
timeout --signal=TERM --kill-after=5s 20s \
  ip netns exec "$NS" python3 "$RESEARCH_DIR/udp53_apps.py" udp \
  --run "$RUN_ID" --side "$SIDE" --bind "$LOCAL_PRIVATE" \
  --peer "$PEER_PRIVATE" --port 42053 --phase "smoke-${SIDE}" \
  --count 32 --size 512
```

## Controls, acceptance and limits

Before a WAN attempt, complete a native local control with the same namespace-born
WG/adapter composition. For two fixtures on one authorized host, use distinct
namespaces and roots with `--outer-bind 127.0.0.1:53061 --outer-peer 127.0.0.1:53062`
on one adapter and the reciprocal tuple on the other. Keep `--netns-path` and
fresh reciprocal WG keys. This is local native-L3 evidence, not WAN evidence.

`--loopback-control` replaces `--netns-path` only for an unprivileged framing/socket
test: both outer addresses must be loopback. It does not create native WG or prove
private L3. Do not substitute that simpler control for the native control.

Escalate traffic only after small authenticated exchanges pass. A useful next
sample can be 1 MiB TCP per direction; larger/simultaneous samples up to the
fixture's 64 MiB-per-request ceiling need a concrete acceptance purpose. The UDP
fixture permits at most 256 packets per invocation and 1024 bytes per packet.
Preserve every initial failure, partial count, duplicate, reordering observation,
timeout and ACK error. Sender end-to-end TCP timing is the principal useful-rate
measurement; receiver timing excludes expected-digest preparation.

Record source hashes, kernel/tool versions, public/private endpoints, namespace
and socket identities, UTC window, actual first public transmitter, independent
WG/app receipts, loss/integrity, useful rate and adapter CPU/RSS. Adapter counters
describe its forwarding process only, not whole-host or kernel-WG resource cost.
Its maximum datagram bound is a UDP-payload bound; it is not the private IP MTU.

Idle/keepalive, controlled restart, MTU and changed-tuple recovery are separate
observations. `PersistentKeepalive=0` alone does not establish complete wire
silence; inspect actual traffic/counters. The fixture has no automatic primer
retry, tuple refresh, NAT roaming or failover. A newly coordinated tuple is a new
generation, not same-session migration. Do not broaden tests or repeat blocked
operations merely to obtain a successful sample.

Report `PASS`, `FAIL`, `PARTIAL`, `INCONCLUSIVE` or `NOT_RUN` at the measured layer.
Keep `TOOL_SAFETY_BLOCKED` separate from network failure. A useful research decision
does not establish long-term reliability, other-provider behavior, production
security review, multi-Link sharing of port 53, installed STL lifecycle, reboot
restoration or universal connectivity.

## Stop, teardown and evidence retention

Stop only the exact recorded application/adapter jobs. Verify process termination
and collect final `SERVER_STOPPED`/adapter `STOPPED` receipts; a requested stop is
not proof that the process exited. Then run on each host:

```bash
python3 "$RESEARCH_DIR/udp53_fixture.py" inspect --root "$FIXTURE_ROOT"
python3 "$RESEARCH_DIR/udp53_fixture.py" cleanup --root "$FIXTURE_ROOT"
```

Cleanup rejects live namespace processes, changed root/boot/namespace/WG/key
identity, symlinked key directories and unexpected key-directory contents. It
removes the original WG and namespace before removing only its original key and
exclusive key directory. Verify the reported absence independently and compare
installed STL State and unrelated host resources with the pre-test baseline.

The nonsecret fixture and cleanup receipts remain under `FIXTURE_ROOT`; do not
delete unique evidence before verified preservation. Any ambiguous or partial
cleanup remains explicit retained state. No wildcard process kills, recursive
configuration cleanup, retained-credential deletion or name-only force removal.
Keep raw captures/private diagnostic material in the authorized evidence store;
publish only sanitized decision-grade results to #125 and decision changes to #142.

## Successor research: identity-preserving, coordinated local recovery (not WAN)

`test_udp53_identity_recovery.py` is a **root-required, Dev-host-only**,
explicitly bounded local proof of native WireGuard surviving transport-helper
replacement. Do not run it on production, an installed STL physical test target,
or any host without an exact authorized temporary-namespace experiment. It uses
**only 127.0.0.1 outer UDP sockets**, never UDP/53 over the public Internet.
It reuses the same original `udp53_fixture.py` and `udp53_apps.py`; native WG
keys, peer public identities, interfaces and private addresses stay fixed
through two public-role orientations and replacement of both adapters' source
socket tuples. The local harness directly coordinates both adapters; **this is
not a distributed recovery control protocol** and not a self-healing Carrier.

Unprivileged transport checks (four real-loopback controls, no native WG):

```bash
python3 scripts/research/test_udp53_wg_adapter.py --result /tmp/stl-u53-loopback-result.json
```

On an **authorized disposable Dev host only**, with the native WG kernel and
`ip`, `ping`, `nft`, Python 3 and a verified executable `wg` binary available,
run the native fault/recovery proof as root. The exact absolute path is to a
verified tool binary; the harness does not install packages or alter global
host configuration. No new service, route, nft rule, forwarding setting or
DNS listener is created.

```bash
python3 scripts/research/test_udp53_identity_recovery.py --wg-tool /absolute/path/to/wg
```

The `--lab-drop-outer-after` adapter option is rejected unless **both public
socket endpoints are loopback**; it deliberately discards a local outbound
UDP datagram after a bounded interval. Each orientation first proves real
native WG/private ping, independent SHA-256 checked TCP receipts and exact UDP
receiver/ACK counts in both directions; then verifies failed private probes
and zero UDP ACK under the artificial blackhole. A single *test-harness*
coordinated socket generation refresh is allowed, **without changing keys**;
private ICMP/TCP/UDP must succeed again, including after a short local idle.
No application sender bytes or handshake timestamp alone count as delivered
payload. Strict test failures retain negative receipts rather than masquerade
as a recovered link. Failure detection requires actual private application
proof, not only a recent WireGuard handshake.

The test owns `u53-lab-*` temporary namespaces and exclusive `stl-u53-lab-*`
private key directories under `/etc/wireguard`, verifies process termination,
retains task-specific **nonsecret** fixture and cleanup receipts in the
restricted Dev evidence location
`/srv/ai-workspace/stl-research-evidence/2026-10-31-udp53-local/`, then removes
only verified task-owned temporary fixture roots and keys. It independently
hashes current host routes, rules, addresses and nft rules before/after. It
never touches installed STL Link State. A missing or conflicting resource is
a failure, not permission to take over another service.

**Interpretation gate:** a local recovery PASS proves only that native WG
identity may be retained while an out-of-band test orchestrator replaces both
outer sockets. It does not prove why the IR/DE real UDP path becomes unusable,
or how two separated peers can coordinate when their only transport is down.
For a real Carrier, that control requirement needs an explicitly approved,
fail-closed, authenticated peer contract or an independently available approved
control channel; do not silently add port hopping, third-party relays, credential
regeneration, persistent helper polling or fallbacks. Physical two-host
post-idle data delivery, source tuple causality, sustained throughput/PPS,
capacity, multi-Link admission and managed Engine/systemd lifecycle remain
separate GO/NO-GO gates under #125/#142. Keep the original historical
`research/udp53-native-wg-proof` branch and its full evidence intact.
