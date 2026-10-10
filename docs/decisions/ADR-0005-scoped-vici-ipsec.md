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
XFRM inspection accepts verified JSON or strictly parsed legacy iproute2
text, never an inventory probe failure as evidence of vacancy. Kernel state
output is sensitive and must not appear in errors or logs.

A successful preflight is NOT persistent ownership proof, a reservation
against other administrators or a VICI/XFRM write permit. Any future
transaction must repeat fresh host checks while holding STL locks and prove
STL-owned effects with receipts/host identity before repair, rollback, unload
or credential retirement. In particular, public PendingIPsec and derived
VICI names alone NEVER authorize destruction of an existing daemon object.
No production runtime registration, VICI or kernel mutation is enabled by
this checkpoint. Issue #7 retains the operational backend and backend-focus
IKEv2/ESP/NAT-T acceptance; Issue #12 retains release-wide E2E.
