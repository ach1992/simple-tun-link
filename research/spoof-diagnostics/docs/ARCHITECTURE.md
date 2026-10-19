# Spoof Diagnostics — independent Field architecture

**Status: development candidate, not field-proven.** This architecture
supersedes the now-removed Private Lab runtime on the separate
`dev-spoof` development line. It does not modify STL or turn this
program into a VPN backend. The controlling source-IP research remains
[Issue #125](https://github.com/ach1992/simple-tun-link/issues/125).

## Explicit architecture and trust boundary

Two controlled roles, A and B, operate in either independently configured
`A_TO_B` or `B_TO_A` direction. Directly assigned receiver IPv4 only: NAT-forwarded public destinations are not supported by this first design. A third-party receiver, reflector, route
installer or scanner is not included.

1. A holds an exact, direction-scoped `field_candidates` IPv4 inventory.
2. A signs a short-lived challenge binding A/B roles, destination IPv4,
   destination UDP port, each source candidate, packet size and run ID.
3. B checks that the signed destination IPv4 is directly assigned to a local, active non-loopback interface, independently checks its **own** candidate allowlist, verifies A's
   Ed25519 identity chain and signs an exact matching grant.
4. Both A and B verify that signed grant. B explicitly binds its own
   assigned destination IPv4 and keeps a consumed-run ledger (0700).
5. A sends **1–10 independently signed 128–1200 byte diagnostic datagrams
   per selected candidate** (CLI default 5), at most 32 distinct candidates
   per signed run and 320 total samples, with at least 200 ms between sends.
   Samples are interleaved across candidates for temporal spacing. The signed
   plan and grant bind the exact sample list. The receiver automatically
   scales its default finite window to the planned sample duration, clipped
   by the signed challenge expiry. There is no CIDR expansion,
   public scan, automatic retry or continuous background sender.
6. B validates each signed UDP application packet and emits a portable
   Ed25519-signed receipt. Each observation carries **both selected
   source and actual observed UDP source**, plus a boolean exact match.
7. Offline `field verify` reconciles challenge, grant, certificate chain,
   run ID, source/packet identity, receipt signature and time envelope, then
   reports per-selected-IP planned/received/exact-match/rewritten/missing
   observations and explicitly qualified percentages. A signed plan is not
   proof that every planned packet was actually submitted. It does **not**
   infer unobserved packet loss, provider authorization or return behavior.

`field_udp_bound` uses normal Linux UDP and validates that every selected
IPv4 is actually assigned to an active non-loopback sender interface.
It is **not spoofing**. `field_raw_ipv4` creates real IPv4+UDP headers
containing the selected source; it requires an explicit UP sender NIC,
Linux `CAP_NET_RAW`, and independently established Owner/receiver/provider
permission before public forged-source transmission. A CLI acknowledgement
does not independently establish authorization. The raw socket never
alters default routes, host-wide sysctls, firewall rules or STL state.

An IP candidate can be globally routable or a legitimately operated
private IP; this is **not** the former restricted RFC1918 lab mode. IPv4
documentation, multicast, loopback, link-local and known reserved
special-purpose candidates are rejected as selected source/destination.
There is no IP-address range enumeration.

## Exact evidence levels

| Evidence | Meaning | Missing proof |
| --- | --- | --- |
| Signed plan + grant | A and B keys signed the same finite run | No network or provider packet transmission |
| `SUBMITTED_ONLY` | The sending socket call returned success | No independent physical NIC or provider egress |
| Receiver signed observation | B's process reports a verified UDP payload | No independent NIC capture or provider path guarantee |
| Per-IP observed/planned fraction | B received this fraction of samples listed in the signed plan | Not a packet-loss measurement without independently proving actual submissions |
| `source_matched=true` | UDP peer address equals selected IPv4 at B's socket | Does not by itself establish upstream ISP policy or return routing |
| `source_matched=false` | B's UDP source differs from signed selected source | Possible NAT/rewrite; root cause unverified |
| Zero observations | B signed no validated receipt samples | `INCONCLUSIVE`, not proof that a source is blocked |
| Return/private L3 | `NOT_TESTED` | Requires distinct proof, not built into this tool |

A raw packet with a forged Source IP may receive an answer routed
somewhere other than A. Neither the signed receipt nor this program
establishes a return route, even when B receives a signed request.

## Scope and compatibility

- Standalone Go with standard library, Linux AMD64/ARM64, CGO disabled.
- Offline installer, versionless release channel and `spoofdiag-v*`
  assets independent of STL `main` and STL `v*` releases.
- No host service daemon, public listener automatically started,
  automatic source discovery, third-party reflection, TUN/WireGuard,
  tunnel switching, or STL integration.
- No public network test or two-real-host test for this new Field code.
- Previous private netns/KVM results are **historical for a different
  implementation**, preserved in [LOCAL-LAB-ACCEPTANCE.md](LOCAL-LAB-ACCEPTANCE.md).
  They are not evidence that the Field engine works.

## Authorization and release gates

The Owner explicitly allows automated builds, CI, offline/unit and approved
controlled validation. This does not authorize any public-WAN forged-source
Field trial. Such use still requires separately established Owner, peer and
provider approval, operator-owned destinations and appropriate platform
permissions. A permit string, receipt, successful packet delivery or local
signature alone is not independent evidence of authorization.

Automated Go tests and CI validate code behavior; two-real-host packet
capture, provider acceptance and independent review are separate kinds of
evidence and cannot be inferred from CI. For this experimental pre-release,
the Owner has explicitly authorized Master self-review in place of
independent review; the release must say so plainly. Keep all SpoofDiag
integration and release tags off protected STL `main`.
