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
