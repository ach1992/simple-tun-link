# Diagnostics, quality and MTU contracts

This document defines the **measurement semantics and backend-neutral
safety rules** in `internal/diagnostics`. For user commands and JSON
syntax see [CLI.md](CLI.md); for changing a saved Link see the
[canonical Engine](ARCHITECTURE.md), not a diagnostic adapter.

## What observations can prove

- `link list`: saved **desired** Links, not live connectivity.
- `link status`: a matching, STL-owned local interface and supported
  public counters/identity, not remote packets.
- `link diagnose <id>`: bounded probes **to the peer Link Address**
  and observed quality/MTU data, not a durable health guarantee.
- `link diagnose --all [--timeout 10m] [--parallel 1..4] [--json]`: one
  stable ordered inventory, independent time-local Link probes and
  explicit observed/blocked/unknown/interrupted outcomes. Default
  parallelism is `1`; an operator may opt into up to four simultaneous
  read-only backend observations/peer pings. The per-Link and overall
  timeout contracts still apply, and the JSON schema/ordered output
  do not depend on which Link finishes first.
- Managed WireGuard-over-WSS is diagnosed separately with
  `link diagnose-wss <id> [--json]` for bounded, read-only
  helper/nft/kernel WG status. The **shared active** `link diagnose <id>`
  does not yet implement WSS carrier-aware PMTU/ICMP measurement, and
  `link diagnose --all` reports an ordinary managed WSS Link
  **blocked** with reason `wss_active_diagnostics_not_implemented`.
  A durably superseded original is instead **blocked** with reason
  `wss_original_superseded`; its Link summary includes
  `disposition: quarantined_old` and the protected `superseded_by`
  ID from the same read-only State snapshot. Interrupted checks remain
  unknown, and no generic active WSS peer probe is attempted. Neither
  native WireGuard handshake counters nor local status alone prove
  active WSS-carried peer responses.
- `link throughput`: a separate, explicitly approved short TCP
  traffic test; not a default health check or a tunnel bandwidth cap.

An ICMP reply means the particular probe reached the peer at that
moment. A completed, valid ICMP probe with no reply contributes a
**measured lost packet** to short quality statistics; that alone does
not prove the whole Link is down. The overall Link outcome can remain
**unknown** (`link_probe_no_reply`). An interrupted or malformed ping
subprocess is **not** a confirmed lost packet. Missing capability or
ownership yields `blocked` or `unknown`, never silent success.
Conditionally unadmitted IPsec reports
`ipsec_runtime_not_registered` with safe next step
`stl doctor ipsec`, without activating the daemon. On an
actual host, the doctor also reports `provisioning_readiness` from
the same **read-only native-exclusive Preflight** used before IPsec
PREPARE. A StrongSwan **unit file existing on disk** is not proof
that a VPN service is active, enabled or using UDP 500/4500.
The current Preflight's separate stable reason/next-step fields
distinguish missing/ambiguous systemd identity, executable, daemon,
port, private VICI and service-state problems. They cannot authorize
service startup or ownership changes.

Every operation remains **network-config read-only** unless it is an
explicit Engine lifecycle command. Diagnostic probes can send bounded
ICMP/TCP traffic but must not apply MTU, change routes or firewall,
load modules, start services or repair an interface.

### All-Link cancellation and observability

One trustworthy State snapshot defines the Link set; live probes
are independent and may observe changing kernel state. Each probe
has a bounded budget; the optional **total** deadline starts
before State loading and runtime construction, not after.
A late result or interrupted/unprocessed Link remains unknown.
If cancellation prevents trusted inventory, emit the versioned
`diagnostic_interrupted` error (exit 1), **not** a fabricated
successful empty list. A genuinely empty saved inventory can
complete successfully but proves no peer connectivity.
There is no arbitrary limit on the number of configured Links.

Versioned v1 reports include only validated Link/backend identity,
quality and MTU data, stable reason/next-step fields and verified
backend counters. Unknown metrics are absent or `null` by contract;
do not invent a zero. Never echo arbitrary Link display names,
raw external output, private credentials or SENSITIVE Setup Links.

## Common Linux probe contract

Before transmitting, the read-only adapter must verify the selected
backend's capability and exact owned interface name/ifindex, local
Link Address, interface UP state, and route-derived physical underlay
source/device/MTU toward the saved **underlay peer**. A replaced
interface under a reused name or mismatched route blocks measurement.

`DFProber.Probe(ctx, link, packetBytes)` probes the inner IPv4
datagram size (including the 20-byte IPv4 plus 8-byte ICMP headers),
never the public underlay address. The Linux `ping` adapter uses
bound local Link IP and interface, IPv4/DF nonfragmentation and
`-s (packetBytes - 28)` with explicit bounded argv and
deterministic locale. Parse only a complete matching peer/sequence
and summary; reject truncated or unexpected tool output.

| Probe result | Meaning |
| --- | --- |
| `reply` | A matching actual ICMP reply and parseable RTT |
| `too_large` | A definite local/remote packet size rejection |
| `timeout` | Confirmed send without reply; no PMTU upper bound established |
| `unsupported` | Missing/unavailable probe capability |

A canceled process, malformed stdout or tool failure is not
automatically a reply, a lost packet or a measured MTU.

## Backend measurement requirements

| Backend | Independent verification and measured data |
| --- | --- |
| GRE Native/FOU/GUE | Deterministic owned interface/ifindex, mode, local IP, route, GRE options/encapsulation overhead and public packet/byte/error counters |
| IPIP Native/FOU/GUE | Same identity and route rules; transport overhead 20/28/32 bytes for IPv4 Native/FOU/GUE |
| WireGuard | Owned interface/ifindex, public local/peer keys, listen port, local Link IP, handshake timestamp and RX/TX bytes; IPv4 data overhead **60 bytes** |
| WireGuard over WSS (development) | Separate `diagnose-wss` reports read-only helper/ingress/WG status and handshake/counters; generic active PMTU/ICMP is **blocked** until a safe WSS-specific probe with verified carrier overhead and ownership exists |
| IPsec ESP/NAT-T | **Admitted** STL-exclusive runtime, exact owned XFRM interface name/ifindex/`if_id`, VICI connection and matching SA before any probe; conservative overhead planning bounds **128/136 bytes** |

GRE overhead is supplied by the backend from actual GRE fields,
key/checksum/sequence, FOU and GUE encapsulation rather than guessed
by the common measurement core. GRE keys are not authentication.
WireGuard's zero/missing last handshake does not prove peer
failure. IPsec ESP/NAT-T overhead is a conservative planning bound,
not a claim about a negotiated exact transform.

IPsec **XFRM interface packet counters** are optional and distinct
from SA/peer-authentication evidence. Before reporting RX/TX, a
bounded `ip -s -details -json link show dev <owned-interface>`
must independently confirm name, ifindex, `if_id`, ownership alias
and both `stats64.rx.packets` / `stats64.tx.packets`.
If unavailable or ambiguous, omit `rx`, `tx` and `counter_unit`;
a verified numeric zero is valid only when actually measured.
Other backends' verified counters keep their own supported units.
No healthy status follows from a counter alone.

## MTU selection versus MTU application

The selected backend supplies its **actual outer encapsulation
overhead** and a route-aware underlay MTU; the shared IPv4
decision ceiling is:

~~~text
ceiling = min(65535, underlay_route_MTU - backend_overhead)
~~~

A nonexistent/invalid overhead or less than the minimum
68-byte IPv4 packet allowance fails validation.

- **Manual diagnostic MTU** must be 68 through the actual ceiling;
  it is not clamped or automatically applied.
- **Auto measurement** first probes the ceiling, then when needed
  a conservative `min(1280, ceiling)`, and uses at most
  **18** DF probes to seek a reply-confirmed usable packet size.
- Only `too_large` constrains a known upper bound; a
  timeout cannot prove the path MTU. An actual reply establishes
  a **sampled reachable size**, not the precise maximum.
- If no reply confirms a valid size, report an explicitly
  **unverified conservative fallback** or an error after a
  definite minimum-size rejection. Never promote a fallback
  to a measured PMTU.

Changing kernel MTU is **not a diagnostic action**. Desired State
v3 and input schema v2 support endpoint-local `unmanaged`,
`auto` and `manual` policies, applied/verified/undone only by
the canonical Engine under the usual ownership locks.
Peer Setup Links do not copy endpoint-local MTU settings.
Read-only diagnostic output cannot silently modify them.

## Short link quality and explicit throughput

The default quality sample is **five** ICMP probes (maximum ten)
using an 84-byte inner IPv4 packet when MTU permits.
Linux `ping -W 1` retains its one-second reply window; the Go process
allows up to two seconds for each quality sample to emit a valid exit
summary. MTU discovery retains its separate one-second per-attempt
allowance (at most 18 attempts). Together the default subprocess
allowance is 28 seconds inside the 35-second per-Link diagnostic
deadline; parent cancellation never becomes fabricated packet loss.
Reports distinguish confirmed sent-but-unanswered loss,
measured min/mean/max RTT and arithmetic mean of absolute
adjacent-successful RTT differences (loss breaks the pair).
This is short-term variability, **not** sustained link
availability or a general RFC 3550 jitter measurement.
No measured samples yield unavailable/`null`, not `0 ms`
or fabricated 100% loss.

The opt-in `stl link throughput <id> --confirm <id>
[--seconds <1..10>] [--json]` sends one short TCP stream
only to the committed peer **Link Address**, port **5201**.
The remote operator must independently authorize and start
an iperf3 listener bound to that Link IP; STL never starts it.
Before traffic, require exact owned interface and source IP,
a kernel route without gateway/underlay fallback, unchanged
Link identity and locally supported iperf3 **3.x >= 3.11**.
The client uses `--bind` plus `--bind-dev` for the
**actual data socket**, with no unbound retry if checks fail.
The Engine per-Link lock prevents concurrent STL Remove/Ensure
while the brief test runs.

The throughput operation reserves the same bounded 35-second
diagnostic preflight, five seconds for scoped preparation, three
seconds to verify iperf3, the requested test duration plus six
seconds of subprocess allowance, and two seconds for result
completion: **51 seconds plus the requested duration** overall.
This does not increase the requested TCP traffic duration or
introduce automatic retries. A genuinely expired operation cannot
publish late or incomplete metrics as a successful measurement.

The throughput report projects bounded numeric byte/Mbit/s
rates, test duration, Link ID/backend/protocol only. Tool
failure, missing listener, malformed JSON or unknown version
does not become measured zero. A short benchmark does not
establish sustained capacity or act as a tunnel-wide limiter.

## Testing and evidence

Unit/fake-runner tests verify parser, limits, error classification
and algorithm behavior; optional local loopback smoke can
check iputils syntax without touching external peers:

~~~sh
STL_LIVE_LOOPBACK_PING=1 go test ./internal/diagnostics -run '^TestLinuxDFProberLoopbackSmoke$' -count=1
~~~

Real native kernel packets, multi-Link ownership, XFRM counter
availability, restored MTU and installed-release behavior
need separate authorized disposable E2E evidence.
See [cross-backend](operations/CROSS-BACKEND-REAL-E2E.md),
[IPsec](operations/IPSEC-REAL-E2E.md) and
[supported environments](SUPPORTED-ENVIRONMENTS.md).
