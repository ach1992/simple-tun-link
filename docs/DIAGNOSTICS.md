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
- Test-only fake DF-probe adapters and deterministic behavior/failure tests.

It does **not** modify any network state. It does not execute system commands,
configure the tunnel, trigger repair, install a probe tool, store credentials,
create host probes, or claim live tunnel reachability. Real Linux/backend
integration follows Issue #3 and backend Issues #4–#7.

## Measurement contract

`DFProber.Probe(ctx, link, packetBytes)` measures an **inner IPv4
datagram**, with `packetBytes` including the 20-byte IPv4 and 8-byte
ICMP echo headers. The destination must be the **peer Link Address** for the
specific stable Link ID, not merely the public underlay address. A future
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

The current core is not full Issue #9 completion. Still required:

- Runtime capability/tool/module preflight reuse from the common Linux layer;
- Real read-only Linux DF probe adapter bound to Link Address/interface;
- Backend-provided worst-case overhead and safe MTU application mapping;
- Integration with backend state/counter observations (#4–#7);
- Operator diagnostics/JSON commands and optional throughput tests (#10);
- Namespace/live Link reachability, PMTU and Multi-Link isolation verification
  in the E2E harness (#12).

The independent core can be reviewed and merged separately once its own
review/integration gates pass. Do not close Issue #9 until the actual
diagnostic and operator acceptance requirements are proven.
