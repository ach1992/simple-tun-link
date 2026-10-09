# Diagnostics and MTU decision contract — Issue #9

This file describes the independently implementable, backend-neutral
diagnostics core. The acceptance owner remains
[Issue #9](https://github.com/ach1992/simple-tun-link/issues/9),
with root outcomes in PROJECT-SPEC.md and behavior in ARCHITECTURE.md.

## Scope of the current component

`internal/diagnostics` currently provides:

- Observational, bounded inner-IPv4 MTU/PMTU candidate selection.
- A manual MTU override with explicit underlay/encapsulation validation.
- A conservative fallback that is **never described as measured**.
- Short, bounded Link Address probe aggregation for loss, RTT and jitter.
- One versioned `Report` with a shared human-readable `Summary()`.
- A Linux read-only probe and route-aware preflight adapter, using the same
  common report and algorithm, without hardcoding backend overhead.

The pure core is OS-independent. The optional Linux adapter executes bounded
read-only inspection commands and ICMP echo probes but **never modifies**
network state, applies MTU, repairs a tunnel, installs software, stores keys
or claims live backend E2E acceptance. Binding the real backend interface and
overhead is owned by Issues #4–#7; release E2E by Issue #12.

## Measurement contract

`DFProber.Probe(ctx, link, packetBytes)` measures an **inner IPv4
datagram**, with `packetBytes` including the 20-byte IPv4 and 8-byte
ICMP echo headers. The destination must be the **peer Link Address** for the
specific stable Link ID, not merely the public underlay address. The Linux
iputils ping adapter uses `-s (packetBytes - 28)` and ensures
non-fragmenting/DF probing. See the
[Linux ping documentation](https://man7.org/linux/man-pages/man8/ping.8.html).
No shell interpolation or untrusted free-form command string may be used.

An adapter must distinguish:

- `reply`: an actual received echo reply for this request;
- `too_large`: an actual local/remote fragmentation or size rejection;
- `timeout`: a sent probe without a reply, **not proof** of path MTU;
- `unsupported`: probe capability unavailable.

A tool execution failure or canceled/deadlined adapter operation is **not**
a received reply or automatically a lost packet. Probes must honor the
supplied context and its child deadline. Probe implementations remain
read-only, Link-scoped, and limited to the authorized selected interface.

## Linux read-only adapter

`PreflightLinux(ctx, link, opts)` resolves the actual route toward the
**underlay peer**, requires the kernel-selected source to match the requested
underlay source, then checks that the selected backend-supplied Link interface
is UP and owns the exact local IPv4 Link prefix. The physical underlay device
must also be UP. Underlay MTU comes from the kernel's physical route-device
MTU, restricted by any explicit route MTU metric. Backend overhead is required,
positive, and passed from the backend; no common encapsulation guesses apply.
Missing or mismatched state fails closed before any active probes.

`NewLinuxDFProber` binds one Link ID and Link Address pair to its selected
interface. A single DF echo is executed with separated argv (no shell),
using the supported Linux `env` tool to set `LC_ALL=C` for deterministic
`iputils ping` parsing. It forces IPv4, disables name lookup, sends exactly
one echo with `-M do`, uses `-s (packetBytes - 28)`, and binds both
`-I <Link-interface>` and `-I <local-Link-IP>`. The destination is the
peer Link IP, **never the underlay peer IP**.

A reply is accepted only with a confirmed one-packet summary, matching peer
address/sequence and parseable RTT. Definite local or remote fragmentation
returns `too_large`; a verified sent-but-unanswered summary returns
`timeout`. Unsupported/missing tooling or malformed output cannot become
a successful measurement or established MTU ceiling. Arbitrary command
output/errors are not propagated into the versioned report. Cancellation
prevents further probes.

`ObserveLinux` composes this adapter with the common read-only
`Observe` decision/report model. Missing backend capability/counter hooks
and operator integration are still distinct acceptance work.

Optional nonprivileged runtime verification uses only the local loopback
interface, without sending packets to external destinations:

~~~sh
STL_LIVE_LOOPBACK_PING=1 go test ./internal/diagnostics -run '^TestLinuxDFProberLoopbackSmoke$' -count=1
~~~

This verifies iputils syntax and parser behavior, **not** real Link
data-plane reachability, FOU/GUE or multi-Link E2E acceptance.

## GRE adapter — backend identity and counters

`ObserveGRE(ctx, link, inspector, runner, manualMTU)` connects the
backend-neutral v1 measurement and Linux DF-probe implementation to the
already implemented GRE backend, without duplicating the MTU/quality logic.

It requires a GRE Link, the backend's capability report and
`DiagnosticState` ownership/counter inspection. Before transmitting
any Link Address ICMP echo, it verifies the deterministic GRE interface name,
encapsulation and positive kernel ifindex. The Linux preflight then requires
the same ifindex in the selected Link-interface address snapshot; an interface
replaced under a reusable name cannot be silently mixed with the earlier
backend diagnostic view.

The backend itself supplies its real worst-case overhead for native GRE,
key, checksum, sequence, FOU/GUE UDP and GUE headers. Source route, underlay
MTU and selected Link Address checks remain in the single Linux adapter.
Measurements are bounded and purely observational; **no suggested MTU is
automatically applied**. Live GRE operational interface/counter verification
does not by itself prove traffic to a remote peer.

`GREReport` preserves the common `schema_version: 1`, `link_id`,
`mtu` and `quality` keys, adding only the GRE backend kind and
the secret-free, identity-checked interface counters as `state`.
Capability failures, unknown ownership and mismatched interface observations
return explicit non-success; they are not mislabeled as healthy.

The adapter has fake-runner regressions covering live-observation composition,
FOU overhead vs manual MTU, wrong backend, unavailable capability, stale
ifindex, foreign interface, malformed counter identities, and cancellation.
These tests do **not** claim real FOU/GUE data-plane acceptance (Issue #4),
CLI/operator commands (Issue #10), or release E2E (Issue #12).

## MTU policy

`MTUConstraints.UnderlayMTU` comes from route-aware source/interface
inspection toward the real peer. `BackendOverhead` is supplied by
the selected backend, including its outer IP/transport/encapsulation and
relevant variable overhead. An unknown or zero overhead is rejected rather
than silently treated as a valid tunnel configuration. The common algorithm
does not hardcode GRE/FOU/GUE/WireGuard/IPsec overhead guesses.

For IPv4, the outer-MTU-derived upper bound is:

~~~text
ceiling = min(65535, underlay_route_MTU - backend_overhead)
~~~

Inputs leaving less than 68 bytes for IPv4 are invalid. The 68-byte minimum
and PMTU probing behavior follow
[RFC 1191](https://www.rfc-editor.org/rfc/rfc1191).

In `manual` mode, the requested value must be between 68 and the
computed ceiling; it is not silently clamped and is **not** falsely marked
probe-verified.

In `auto` mode:

1. Test the computed ceiling once (fast success path).
2. When needed, test the initial conservative candidate
   `min(1280, ceiling)`.
3. Use at most 18 total DF probe calls to seek a larger confirmed reachable
   MTU (or a smaller one when the initial candidate is definitively too
   large).
4. A definitive `too_large` constrains the upper bound.
   A timeout cannot establish that upper bound.
5. Return a **probe-confirmed** MTU only where a response was observed.
6. Otherwise return an **unverified conservative fallback**, with a
   structured reason, bounded by any known TooLarge rejections.
7. If the minimum supported IPv4 size is decisively rejected, return a
   verification error rather than claiming a working MTU.

Probe-confirmed means **the selected packet size received a reply**,
not that the exact maximum path MTU or end-to-end application throughput
was proven. ICMP rate limiting, filtering, transient loss, route changes
and dynamic backend encapsulation can limit inference. The algorithm
is a bounded decision aid, not a permanently accurate remote path oracle.
It may be rerun after backend/route changes. A fallback is not authority to
mutate a Link or apply new MTU settings without the canonical Engine path.

## Short quality measurements

Quality probes use an 84-byte inner IPv4 packet (up to selected MTU):
20 IPv4 + 8 ICMP + 56 data bytes. Default: five probes; maximum: ten.
Successful replies generate min/mean/max RTT. Short-term jitter is the
arithmetic mean of absolute RTT differences between **adjacent successful
probes**; any packet loss breaks that pair. This is a diagnostics measure,
not a full transport or RFC 3550 RTP-jitter implementation.

Only explicit sent-but-unanswered probes contribute to packet loss. A tool
error, unavailability or local TooLarge rejection makes quality unavailable
or partial; it does not fabricate 100% loss. Metrics without any measured
samples are JSON `null`, not zero milliseconds/zero packet loss.

## JSON and safety contract

`Observe(ctx, link, constraints, prober)` returns a versioned
`Report` with top-level integer `schema_version: 1`,
stable Link ID, MTU result and quality result. A human `Summary()`
is derived from the same model rather than reimplementing diagnostic logic.

The report contains no Link display name, private key, shared PSK, executable
arguments, arbitrary external tool output or unvalidated backend strings.
Errors keep their underlying cause for programmatic inspection but expose
only known secret-safe categories/reasons. The absence of measurement remains
visible via choice/status/reason and nullable metrics.

Health observation is **not** repair. Real adapters must not use
`Observe` to mutate another Link or the requested Link itself.
Any explicit repair will use the canonical owned transactional Engine,
with its separate authorization/ownership checks.

## Remaining Issue #9 implementation

This Linux adapter does not complete Issue #9. Still required:

- Connect this GRE-specific backend diagnostic adapter to the operator CLI,
  and add equivalent capability/interface/overhead/counter integration for
  IPIP, WireGuard and IPsec as their backends become available (#5–#7);
- Safe MTU application through the Engine, never from health observation;
- Backend state/counter integration (#4–#7);
- Operator diagnostics/JSON entry points and optional throughput path (#10);
- Live namespace Link Address/PMTU, multi-Link isolation and release E2E (#12).

The Linux adapter is independently reviewable without touching the
in-flight privileged GRE candidate. Keep Issue #9 OPEN until remaining
acceptance is genuinely completed.
