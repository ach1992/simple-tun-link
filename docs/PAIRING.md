# Pairing format and trust boundary — Issue #8

This document describes the first backend-neutral pairing component implemented
by `internal/pairing`. The overall v0.1 requirements are owned by
`docs/PROJECT-SPEC.md`, `docs/ARCHITECTURE.md`, Issue #8, ADR-0003 and ADR-0004.
Backend-specific interface configuration and key generation remain owned by
Issues #4–#7; CLI/import/apply orchestration remains owned by Issue #10.

## Versioned setup links

GRE/IPIP/IPsec continue using the v2 setup-link transport:

~~~text
stl://2.<unpadded-base64url-of-JSON>.<lowercase-sha256-of-JSON>
~~~

The JSON contains:

- `schema_version`: integer `2`;
- `mode`: explicit `"quick"`;
- `link`: the creator-oriented backend-neutral `domain.Link`, including its
  stable Link ID, local/peer underlay endpoints and local/peer Link Addresses;
- `recipient_secret` (optional): a `kind` and unpadded-base64url `data`.

The SHA-256 value detects accidental corruption or damage. **It is neither a
MAC nor a signature.** Anyone who can modify a setup link can recompute its
checksum. Base64 is encoding, **not encryption**. Treat a secret-bearing Quick
Link as a credential, not as a shareable diagnostic artifact.

Version 2 adds the typed `link.gre` object required to carry GRE key/advanced
options and the FOU/GUE UDP port without weakening strict unknown-field
rejection.

**Configured WireGuard Quick Links use schema v3** (`stl://3.`), not v2.
This preserves the exact strict v2 decoding contract. V3 carries a typed,
**public-only** `link.wireguard` with `local_public_key`, `peer_public_key`,
`listen_port`, `peer_port`, `local_keepalive`, and
`peer_keepalive`. These contain no private key and are centrally swapped
with the underlay and Link Addresses when inverting an offer. New WireGuard
Quick Links require two distinct canonical public keys, two explicit listen
ports, and a recipient private key whose derived public key matches the
specified recipient identity. A mismatch is rejected even if the SHA-256
checksum was recomputed. This is a key-identity binding check, **not** sender
authentication or transport encryption. Use a trusted channel to establish
the setup link's origin.

The WireGuard backend, **confirmed v3 recipient import** and protected sender
Create/Resume now use the canonical Engine: only a validated v3 Quick Link with a receiver credential
matching its declared public key can be applied. `stl link ensure` desired
JSON v1 remains unchanged; direct WireGuard provisioning requires an already
protected local per-Link KeyStore credential. Legacy credential-only v1/v2
WireGuard and v1 IPsec pairing remain preview-only. Strict IPsec v2 offers
containing a **nonzero, exactly 32-byte PSK** are eligible for protected import only
when STL's native-exclusive strongSwan admission passes. Other previously
valid v2 PSK lengths remain preview-only, not silently rekeyed.
An explicit protected-key retirement action is also available only after
persisted Link absence and read-only live interface, WireGuard public identity
and owned firewall absence are established. These additions do not prove
privileged handshake/traffic, coexistence or complete release acceptance.

The decoder also preserves previously valid v1/v2 credential-only WireGuard
offers with no public configuration for redacted preview and re-export; they
are **not** ready-to-activate configuration. V1 GRE Native, IPIP and IPsec
payloads remain decodable, and a decoded v1 offer retains v1 on re-export.
Legacy v1 GRE FOU/GUE is rejected with an explicit regeneration requirement
because v1 lacks the UDP port; inventing one would change ownership semantics.
V1 rejects v2 GRE options, and v1/v2 reject v3 WireGuard public fields.

The decoder limits the entire input to 24 KiB and decoded JSON to 16 KiB.
It rejects noncanonical Base64/checksum, malformed/duplicate/unknown fields,
nested extensions without an explicit schema contract, invalid UTF-8,
unpaired JSON UTF-16 surrogate escapes (which Go's JSON decoder otherwise
silently replaces), truncated or mismatched checksums, unsupported mode/version,
and incompatible backend/encapsulation/credential combinations. Valid Unicode
surrogate pairs and explicit U+FFFD characters remain supported. IPv6 underlay
addresses without zones remain supported; scoped IPv6 zone identifiers are
rejected because they are host-local and unsafe to reproduce in a portable
human-readable pairing block. It never evaluates embedded content as a command
or path.

## Perspective and credential model

An encoded offer represents the **initiator's** Link orientation. An importer
must use `Offer.ReceiverLink()` (which centrally swaps local and peer underlay
and Link Addresses, plus WireGuard's public keys/listen ports and per-side
keepalive settings when present) before applying. The stable Link ID, backend,
encapsulation, and display name remain unchanged; multiple independent Links
to the same underlay endpoint pair retain separate IDs.

`NewQuickOffer(link, recipientCredential)` creates an in-memory offer.
Recipient credentials may be present only for:

- WireGuard/UDP: canonical Base64 of exactly 32 private-key bytes, intended
  exclusively for the receiving endpoint. Initiator code must not store that
  receiver private key in ordinary initiator state.
- IPsec/ESP or IPsec/NAT-T: a bounded PSK intended for authorized endpoints.
  Backend code is responsible for creating a high-entropy secret and storing
  it with restrictive permissions.
- GRE/IPIP Native, FOU and GUE: no credential payload is accepted. GRE keys
  and other GRE backend options are ordinary non-secret pairing data; GRE keys
  are identifiers rather than encryption.

`PreviewSetupLink(input)` is the preferred import-preview entrypoint: it
returns redacted recipient metadata without returning an `Offer` containing a
credential. `Offer.Preview()` is recipient-oriented and includes credential presence and
kind **without any secret value**. `Offer.MarshalJSON`, `String`, and `GoString`
are deliberately redacted; callers must not use the export methods for
ordinary status/diagnostic logging. `RecipientCredential()` makes an
independent copy available only for explicit backend import and protected
storage. Its caller is responsible for restricting lifetime and persistence.

`Offer.EncodeSetupLink()` and `Offer.HumanReadableBlock()` explicitly
produce **potentially sensitive export material**. The latter includes the
actual setup link alongside readable receiver-facing public settings and
labels secret-bearing exports `SENSITIVE`. Neither method writes a file or
sends data to an external service. The explicit `stl link create-wireguard` sender command now writes the
one-time sensitive URL to a user-selected, same-owner private directory with
atomic no-replace `0600` publication. **Before** this publication, the
same canonical maintenance/Link-locked transaction has already durably
staged the sender's own private key and the complete public pending sender
Link plus SHA-256 of the precise SENSITIVE URL (never the receiver private
key) in `state.json`. The Engine only applies after the handoff is visible,
then atomically commits desired Link state while consuming Pending.
A hard crash that leaves an intact private
`.stl-handoff-<hex>.tmp` before atomic publication can now be reconciled
explicitly with `stl link recover-handoff --source <original-temp>
--output <private-destination> --confirm <exact-link-id> [--json]`.
The source must be the original same-owner, single-link `0600` temporary
in its original `0700` directory; target must be an absent file in
**that same directory**. The canonical Engine locks preserve the original
sender-only pending intent, exact Link and URL SHA-256, and protected local
WireGuard public identity or IPsec PSK before a no-clobber rename and fsync.
This re-exposes the **original** receiver secret, never regenerates one,
modifies host networking, or treats a pending sender as an active tunnel.
An orphan key without the original intact URL or matching pending record
has no automatic destructive repair. The optional JSON output includes only
version, Link identity/backend and destination path, never URL bytes/PSK.
`resume-wireguard` checks **every field** against the durable pending public
Link **and** exact original handoff digest, verifying the protected sender
private/public identity without regenerating a peer private key. Once the
Link is committed, its exact desired state authorizes idempotent reapply.
 Ordinary Link export remains GRE/IPIP-only; after the recipient
key is delivered it is intentionally unrecoverable from the sender's public
saved state. All secret-bearing export files must avoid shell history,
world-readable destinations, and ordinary logs.

## CLI recipient preview via protected stdin

The non-interactive operator command `stl link preview --stdin [--json]`
reads at most the protocol's bounded setup URL size, accepting at most
one trailing line terminator for piped input. The setup URL is **not** a
positional argument or CLI option, which avoids automatic disclosure in
shell history and process arguments. For an existing protected local file:

~~~sh
stl link preview --stdin --json < /path/to/private/setup-link.txt
~~~

Do not put the secret URL literally into shell command text or logs. The CLI
uses the canonical pairing decoder and recipient inversion, then emits only
Link ID, backend, encapsulation, public endpoint/address metadata, non-secret
GRE knobs (including key identifier and FOU/GUE UDP port), format version,
Quick mode, and secret **presence/type**. Arbitrary display names
and the supplied URL are omitted. Credential data stays in memory only for
the decode lifetime. Malformed/unsupported links produce redacted structured
errors. No file, Link state, route, firewall, interface or backend is changed
by previewing.

The preview command never applies anything. It emits an exact-URL
confirmation token for supported credential-free GRE/IPIP, configured,
credential-bound v3 WireGuard, **and strict v2 IPsec with a nonzero 32-byte
PSK** Quick Links. Token availability is a schema/credential check, **not**
a strongSwan admission decision or proof of network reachability. V3
preview includes the receiver's **public** key identities, listen/peer ports, and per-side
keepalive preferences; the private key is always redacted. A token is a
binding to the reviewed encoded input, **not sender authentication**.
Interactive import also requires freshly typing the exact Link ID.
Legacy WireGuard v1/v2, IPsec v1 and IPsec v2 with non-32-byte PSKs
and IPsec v2 with all-zero PSKs remain preview-only; no import confirmation
is issued for these offers.

## Explicit GRE/IPIP export CLI

`stl link export <link-id> [--json]` intentionally produces a
versioned Quick Setup Link and a receiver-oriented human-readable block
for an existing saved GRE or IPIP Link. It calls `pairing.NewQuickOffer`
and the canonical pairing export API; there is no second URL encoder.
Export itself does not inspect live host networking, mutate state or
attempt to set up the peer. Non-secret GRE Native/FOU/GUE configuration
(including explicit UDP port/key identifier) and IPIP Native/FOU/GUE
configuration (whose UDP port derives from the shared Link ID)
round-trip through the same versioned schema and receiver inversion.

`stl link export` remains intentionally restricted to **credential-free
GRE/IPIP**. It cannot recreate a receiver-only secret from public saved
state. WireGuard and IPsec exports are denied rather than silently dropping
recipient private keys or PSKs; the initiating caller can construct a new
sensitive v3 WireGuard offer through the existing pairing library from an
explicit ephemeral recipient keypair, but no guided sender-side export UX is
part of this slice.
Human/JSON output intentionally includes the full Setup Link URL and
must be treated as **explicitly requested share/export material**, not
ordinary diagnostic/status output. Even without a secret credential,
it discloses network endpoints, Link ID and encoded display-name/config
metadata. SHA-256 integrity does not authenticate who sent it.
Use `link preview --stdin` at the receiving endpoint, then an
explicit, confirmed `link import --stdin --confirm <preview-token>` for a
supported GRE/IPIP plaintext or WireGuard v3 Quick Link. V3 WireGuard
receiver import provisions the protected KeyStore **inside the canonical
Engine Link lock**, not in a separate CLI-managed transaction. A matching
pre-existing key permits idempotent retry; an existing different key is
never overwritten. An uncertain/failed apply can leave a protected key for
explicit reconciliation and exact-credential replay. No auto-cleanup of
private keys is attempted during network removal.

## Apply and backend integration

Decoding and generating a preview **never applies a Link, starts a command,
creates a device, or persists credentials**. The explicit importer requires the exact preview confirmation token and
uses the canonical Engine. For WireGuard v3 the receiver secret is separately
validated against its declared public identity, stored with mode 0600 under
owner-private directories, and only passed to `wg set` through a verified
inherited, read-only file descriptor (`/proc/self/fd/3`), never argv or
ordinary JSON. WireGuard status only inspects public keys, listen ports,
peer identities and counter/handshake state.

The pairing module carries validated backend options but does not itself apply
them, implement the final interactive UI, or perform privileged installation.
Application still goes through the canonical Engine/backend lifecycle. Pairing
therefore remains an **independent, testable portion of Issue #8**, not Issue
#8's full acceptance or any live tunnel-recovery requirement.

A future `secure_exchange` mode requires an explicit protocol/schema update,
not a reinterpretation of v1 Quick Link secrets. An unknown mode or
schema version currently fails closed.

## Confirmed setup-link import via the canonical Engine

A non-interactive receiving operator may apply a reviewed credential-free
GRE/IPIP `stl://` offer, a configured credential-bound WireGuard v3
Quick Link, **or a strict 32-byte-PSK IPsec v2 Quick Link** with
`stl link import`. `link preview --stdin [--json]` first
produces a redacted receiver-side preview and, only for these structurally
importable offers, `import_confirmation`:
the full SHA-256 digest of the exact input setup URL after accepting
a single optional trailing line terminator.

`link import --stdin --confirm <import_confirmation> [--json]` requires
the same URL bytes and a matching token. Invalid, changed and unsupported
offers (including legacy WireGuard v1/v2, IPsec v1 and IPsec v2 with an
unsupported PSK length) are rejected before backend/runtime state is
assembled. Import uses the same `Offer.ReceiverLink` inversion as preview
and delegates convergence to `Engine.EnsureImported` (GRE/IPIP),
`Engine.EnsureImportedRecipient` (WireGuard v3 with protected key
provisioning under the canonical Engine locks), or
`Engine.StageIPsecRecipient` followed by `Engine.ActivateStagedIPsec`
(strict IPsec v2 after fresh native-exclusive admission). The IPsec
transaction protects the existing PSK, checks durable exact intent, and
refuses foreign/uncertain strongSwan ownership; it does not silently start
or adopt a foreign service.
Under the canonical Link lock, it permits only first creation or
idempotent re-ensure of the **exact previously committed desired state**.
An existing Link ID with different saved configuration fails with a
redacted conflict and remains unchanged: the preview token is not approval
to replace an existing Link. An explicit reconfiguration must use the
separate desired-state `link ensure` workflow. This is local, explicit network mutation; preview and export remain
read-only. Confirmation is a reviewed-payload binding, not sender
authentication. GRE/IPIP Link traffic remains plaintext and unauthenticated;
WireGuard v3 encrypts Link traffic, but its SENSITIVE Quick Link must be
delivered to the intended peer through a trusted channel.

Plaintext GRE/IPIP, protected WireGuard v3 and conditionally admitted,
protected IPsec v2 recipient import are implemented; none alone completes
Issue #8. The IPsec path requires an exactly 32-byte PSK, an already
verified STL-exclusive native service and separate explicit IKEv2
initiation/traffic validation. Remaining credential recovery/edge cases
are tracked in #8; real cross-backend and external acceptance remains #12.
A preview confirmation digest binds exact payload bytes
but does **not** authenticate the sender or securely transport a Quick Link.
