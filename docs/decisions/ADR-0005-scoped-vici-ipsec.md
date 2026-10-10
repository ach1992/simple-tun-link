# ADR-0005: IPsec uses per-Link VICI calls; no global strongSwan reload

- Status: Accepted for the IPsec implementation boundary
- Date: 2026-10-10
- Controlling acceptance: Issue #7

## Context

The accepted v0.1 backend uses strongSwan/IKEv2 and Linux XFRM
interfaces with distinct Link identity, policy and credential ownership.
A host may run other users' independent strongSwan connections.

The ordinary swanctl --load-conns --file <single-Link-file> workflow is not
a per-connection load: upstream load_conns_cfg unloads daemon connections
missing from the file. Similarly, swanctl --load-creds reconciles and may
unload shared credentials missing from new input without a global --clear.
Those bulk operations must not be used for STL.

## Decision

1. Use strongSwan's VICI Unix-domain control interface, with a dedicated,
   reviewed Go client. The vendor-maintained MIT-licensed govici library
   supplies protocol framing; STL must not construct ad-hoc VICI wire bytes.
2. Only narrow load-conn / unload-conn and load-shared /
   unload-shared calls may eventually be used for one specific Link.
   Global load-conns, load-creds, clear-creds, daemon-wide
   reload/flush/restart and wildcard removal are prohibited.
3. Derive the same deterministic connection/child/shared-key and nonzero
   XFRM interface identities from the full canonical 128-bit Link ID.
   The XFRM ID is a 32-bit non-secret collision identity, NOT evidence of
   ownership; Engine claims and host inspection must reject accidental
   hash/interface truncation collisions.
4. Never replace an existing matching-name daemon object just because its
   name appears STL-shaped. The backend must establish durable, exclusive
   canonical Engine ownership and re-inspect after resource locks before
   any write/unload. A VICI response alone is not sufficient ownership proof.
5. Keep PSK material only in protected, descriptor-verified per-Link
   credentials and deliberately SENSITIVE Quick Link operations. Generate
   a fresh 256-bit PSK by default; never encode it in ordinary Link JSON,
   VICI inventory, status, diagnostics, stdout, logs or errors.
6. Scope child selectors to exact /32 Link Addresses on both peers and
   scope IKE endpoints/identities to the Link. Prefer ESP normally;
   force NAT-T encapsulation only when requested. Never negotiate
   0.0.0.0/0 as an implicit convenience.
7. Startup, rollback, unload, SA termination and credential retirement
   require independently verified owner-only effects and failure receipts.
   The preliminary reader/profile module intentionally enables no
   production mutation or new CLI option until those gates and real
   disposable IKEv2 traffic tests exist.

## Evidence and limitations

Official strongSwan VICI API documents per-object load-conn,
unload-conn, load-shared, unload-shared, get-conns, and get-shared.
govici has its own protocol implementation and MIT license.

References:
- https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadConns.html
- https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadCreds.html
- https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html
- https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md
- https://github.com/strongswan/govici

The initial PR proves only public identity/profile formation, read-only
VICI inventory handling and fail-closed unit behavior. It is not an IPsec
dataplane, IKEv2/ESP/NAT-T, secret-storage, restart, or release acceptance.
Issues #7 and #12 remain OPEN.

The follow-up protected-PSK storage milestone introduces a dedicated
no-replace, owner-private per-Link credential store with secret-redacted
values and a shared audited directory traversal guard used by WireGuard.
It deliberately performs NO VICI/Engine mutation, recipient import, credential
retirement, real IKEv2/ESP traffic or release acceptance. Engine ownership
and lifecycle proof remain mandatory before using the stored key operationally.
Issues #7 and #12 remain OPEN.


## Protected credential staging follow-up

Before any owner-verified operational VICI/XFRM change, the Engine
may stage an IPsec Quick Link and per-Link PSK through the canonical
maintenance -> Link -> resource lock order. The ordinary state stores
only the full public pending Link, endpoint role, and (for the sender)
the digest of the exact SENSITIVE v2 handoff; never the PSK or URL.
A missing public intent never grants permission to adopt an orphan PSK
with a matching filename. Sender pending state records offer.Link()
(creator-local orientation), not the recipient-facing Preview.Link.
Recipient state records offer.ReceiverLink() (exact opposite orientation).
Exact retry may continue a previously durable pending intent only after
verifying the *existing* protected PSK with a constant-time equality
check; missing material fails closed and is never silently recreated.

For backward compatibility, previously exported v2 IPsec Quick Links
with PSKs other than 32 bytes remain previewable but cannot be staged
or activated. This deliberately does not change the existing v2
pairing schema or imply silent migration/rekey authorization.

Staging alone authorizes no connection load/unload, SA termination,
Linux network change, operational claim, or public release.

## Read-only activation vacancy checkpoint

A follow-up source-only preflight requires exact durable staged public
identity and a protected PSK under canonical Engine locks, then refuses
existing same-name strongSwan connection/PSK objects, XFRM interfaces with
colliding names/32-bit IDs, and orphaned policies/SAs with matching if_id.
XFRM inspection accepts only verified JSON rows with unique relevant field
identities, complete policy/SA endpoints and valid `dir` / `proto`, or
semantically verified legacy iproute2 text with complete headers and valid
descriptor values. The Linux link inventory must also reject duplicate or
case-ambiguous ifname/linkinfo/info_kind/info_data/if_id identities at each
relevant nesting level and reject those identities if placed at the wrong
nesting level (even when an unrelated value might otherwise appear vacant).
A state selector's proto is not a second SA proto; only structurally located
top-level descriptor lines establish SA identity. Do not skip the selector
tail: parse recognized iproute2 protocol, sport/dport, ICMP type/code, GRE
key, dev and optional uid fields with bounded values; unknown, duplicate,
malformed, or misplaced if_id tokens must fail closed. Follow the actual
iproute2 output contract: decimal numbers have canonical formatting;
ICMP type/code are uint8 rather than uint16; an MH `(dport)` value has the
fixed-width lowercase `0x` plus four hex digits; foreign `dev` names follow
Linux `dev_valid_name` rather than STL's planned-interface alphabet.
Legacy iproute2 text parsing and successful-empty inventory checks must
use ASCII structural whitespace byte-by-byte, not Unicode-aware token
splitting/trimming: preserve non-ASCII bytes verbatim for the kernel
device-name check, rejecting `0xa0` while retaining Linux-valid sequences
like UTF-8 `c2 85`. Unicode-only nonempty inventory never means vacancy.
Selector protocol names derive from the file-backed host `/etc/protocols`
primary names as used by default Debian/Ubuntu iproute2/libc, not a static
IANA subset; unknown/unreadable names or ambiguous tables fail closed.
Non-file NSS overrides are not assumed equivalent without host evidence.
This scoped selector grammar follows the iproute2 source:
https://github.com/iproute2/iproute2/blob/e11870d5b9414b2e0770463bd6fc2399744dc734/ip/ipxfrm.c
and preserves the bounded Debian-bookworm text path. An absent `if_id` is harmless only after the row is
positively recognized; a null, conflicting or invalid present ID is unknown.
Never accept an inventory probe failure as evidence of vacancy. Kernel state
and temporary decoded JSON copies are sensitive and must be cleared, never
included in errors or logs.

The connection-name vacancy gate must check **both** VICI-exclusive
`get-conns` and the daemon-wide `list-conns` streamed `list-conn`
events filtered to the exact canonical IKE connection name. strongSwan
documents that `get-conns` excludes configurations loaded by non-VICI
backends, while `load-conn` updates/replaces a same-name connection.
The full filtered stream must be exhausted successfully; malformed,
duplicate, unexpected or interrupted events mean unknown vacancy, never
permission to overwrite a foreign config. A filtered stream is a
read-only collision check, NOT owner proof or a transaction with other
strongSwan writers. Source: the upstream VICI protocol README
(https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md).

## Host NSS protocol-name gate (non-operational)

Legacy iproute2 XFRM selector text prints the primary protocol name
returned by glibc `getprotobynumber()`, not necessarily the first name
in `/etc/protocols` when non-file NSS providers are configured.
For each named selector, first resolve the bounded file-backed primary
and then verify exact agreement with a read-only, absolute-path
`/usr/bin/getent protocols <decimal-ID>` NSS lookup. GNU getent passes
numeric protocol keys to the same libc function used by distro iproute2.
The call has a short deadline and bounded output; a per-inventory cache
and overall lookup budget avoid repeated unbounded slow-provider calls.
Disagreement, unsupported/missing NSS tooling, malformed reply and
timeouts fail closed. This preserves the supported `db files` Debian
configuration when its effective mappings agree, while refusing false
vacancy from custom non-file providers. A custom primary absent from
`/etc/protocols` remains unsupported until an independently reviewed
full-NSS resolver is added. No writer, system-wide NSS change or
activation permit is introduced.

References:
- https://man7.org/linux/man-pages/man1/getent.1.html
- https://man7.org/linux/man-pages/man3/getprotoent.3.html

A successful preflight is NOT persistent ownership proof, a reservation
against other administrators or a VICI/XFRM write permit. Any future
transaction must repeat fresh host checks while holding STL locks and prove
STL-owned effects with receipts/host identity before repair, rollback, unload
or credential retirement. In particular, public PendingIPsec and derived
VICI names alone NEVER authorize destruction of an existing daemon object.
No production runtime registration, VICI or kernel mutation is enabled by
this checkpoint. Issue #7 retains the operational backend and backend-focus
IKEv2/ESP/NAT-T acceptance; Issue #12 retains release-wide E2E.

## Durable VICI preparation and issuing journal (source-only milestone)

A follow-up, deliberately **unregistered** Engine pathway introduces a
public-only, durable per-Link VICI *operation journal*, with a random
nonzero transaction nonce and the **exact complete staged public intent**
(sender/recipient identity and sender handoff digest included). Its phases
are `prepared`, `issuing-shared`, `shared-observed`,
`issuing-connection`, and `connection-observed`. Every transition is
validated against the unchanged canonical PendingIPsec state; malformed,
orphaned and duplicate transaction records fail closed at state load.

`PrepareIPsecVICI` rechecks durable pending intent, protected PSK and the
complete daemon/XFRM collision surfaces under the canonical maintenance,
Link and resource locks, then durably records `prepared` without affecting
the daemon. **No real VICI effectful writer, constructor, production
Apply method or daemon-send path exists in this milestone.** The
`simulatePreparedIPsecVICI` method is defined **exclusively in a Go
`_test.go` file**: it passes fakes through the Engine-locked flow to
verify that pre-effect `issuing-*` phases, readbacks, interruptions,
missing acknowledgements and cross-phase drift fail closed. Those
tests do **not** constitute proof of actual strongSwan writes.

**Critical no-clobber constraint:** upstream strongSwan's
`load-shared` replaces an existing key with the same unique identifier,
and `load-conn` updates/replaces a connection with the same name.
A foreign VICI writer may insert the object after even the most recent
read-only vacancy check and before an STL effect. STL's maintenance,
Link and resource locks do not serialize non-STL daemon clients. **No
extra read-before-write inspection can make these operations atomic.**
Because neither an atomic load-if-absent nor another independently
proven exclusive daemon namespace exists in the accepted implementation,
the real writer is intentionally absent. Before operational activation,
select and verify an exclusive no-clobber ownership mechanism or a
security-reviewed isolated-daemon architecture and record any owner-level
decision. Neither a journal nonce nor a matching name is owner proof.

The journal reserves explicit phases: `prepared`, `issuing-shared`,
`shared-observed`, `issuing-connection`, and
`connection-observed`. In production currently only `prepared`
can be generated by the Engine. The remaining transitions are available
to the test-only simulation, which enforces adjacent-only transitions
and exact unchanged PendingIPsec binding. Every journal state that
could describe an interrupted future effect is non-authoritative and
requires explicit reconciliation; no automatic recovery or operational
Link commit is claimed.

**Forward/backward state compatibility:** This source-only milestone
adds the optional `ipsec_vici_operations` member under state schema
v2. The current reader accepts older v2 state with no member, but an
older binary with `DisallowUnknownFields` will reject a non-empty
journal-bearing v2 state. Until production activation, no standard
CLI/backend creates this journal; downgrade after a journal-bearing
state has been created is **not supported**. Before production
registration, choose an explicit schema migration/version bump or a
documented upgrade-only policy with automated compatibility tests.
No backward-reader compatibility is inferred from an unchanged version
number.

## strongSwan debug logging remains an activation blocker

The daemon's VICI credential loader has a CFG level-4 debug trace that
formats the *raw* shared IKE key (`DBG4(DBG_CFG, "key: %#B", &data)` in
upstream `vici_cred.c`). Hiding plaintext from STL's own stdout/status
is therefore insufficient if the independently configured daemon uses
verbose CFG logging. Prior to production registration, the activation
contract must verify the effective strongSwan log configuration and
fail closed if it may emit PSK material; do not globally reconfigure an
unrelated administrator's daemon as a convenience. No production
writer exists at this checkpoint, so this mandatory future
activation prerequisite is **not satisfied**.

## XFRM interface alias is not atomic at creation

An isolated Debian 13 / Linux 6.12 disposable **network namespace** probe
with iproute2 6.15 showed that `ip link add name ... alias ... type xfrm
if_id ...` did not yield an `ifalias` in `ip -details -json link show`;
only a separate `ip link set dev ... alias ...` produced the alias.
This probe created/deleted only temporary test-namespace resources. A
future XFRM creation transaction therefore must first persist an uncertain
*pre-effect* phase and prove the actual STL-created kernel interface
identity, preserving the original ifindex/ownership evidence across the
non-atomic alias step. An alias on a restarted process is not sufficient
proof and an interrupted create must not blindly delete by derived name.

## Owner decision (2026-10-11): portable native-exclusive v0.1 runtime

The Owner accepted **one shared IPsec control-plane implementation** with
small, capability-selected Linux packaging/service adapters, not separate
IPsec engines for Debian/Ubuntu and not a mandatory privileged container or
network namespace. The first operational profile will have **one STL-owned
strongSwan daemon per host**, not per Link, with an STL-owned VICI/config/
credential boundary and standard IKE/NAT-T UDP 500/4500, reusing current
Link/Quick Link identity without adding remote IKE port fields.

This is an **operational target, not an implemented/verified feature**.
Before even attempting a daemon start, key transfer, VICI load or XFRM
mutation, separately prove exclusive configuration/service/socket/port
ownership, effective secure logging policy, controlled package install
behavior and durable owner-only kernel interface/SA/policy identity. Process
absence or an STL-shaped name/nonce is insufficient. No untrusted external
strongSwan service may be stopped, adopted, reloaded, or modified.

A preexisting or uncertain strongSwan owner, IKE port conflict, suspicious
configuration, ambiguous host identity or missing capability **disables only
IPsec** and returns a stable reason plus actionable operator guidance; GRE,
IPIP and WireGuard remain usable. The accepted v0.1 architecture does not
promise simultaneous foreign strongSwan coexistence. A separate isolated
runtime may be designed later after proven need and reviewed distro/version
compatibility. Extra read-before-write probes on a shared daemon remain
**explicitly rejected** as a substitute for ownership.

The project-wide observability contract in docs/ARCHITECTURE.md applies to
this backend: secure reason codes, operator next steps, bounded correlation,
read-only doctor, no sensitive daemon stderr/VICI payloads, and no CFG DBG4
raw PSK logs even during troubleshooting. Existing source-only journal and
no-effectful-writer constraints remain until the operational security and
real IKEv2/ESP/NAT-T E2E gates pass. Issues #7 and #12 stay OPEN.
