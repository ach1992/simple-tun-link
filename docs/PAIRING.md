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

The WireGuard backend and **confirmed v3 recipient import** now use the
canonical Engine: only a validated v3 Quick Link with a receiver credential
matching its declared public key can be applied. `stl link ensure` desired
JSON v1 remains unchanged; direct WireGuard provisioning requires an already
protected local per-Link KeyStore credential. Legacy credential-only v1/v2
WireGuard and IPsec pairing **remain preview-only and unimportable**.
These backend/CLI additions do not constitute privileged traffic, handshake,
peer pairing, key retirement, or complete release acceptance.

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
sends data to an external service. Any future export-to-file functionality
must enforce protected, no-clobber permissions and avoid shell history,
world-readable output, and routine logs.

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
confirmation token for supported credential-free GRE/IPIP **and configured,
credential-bound v3 WireGuard** Quick Links. V3 preview includes the
receiver's **public** key identities, listen/peer ports, and per-side
keepalive preferences; the private key is always redacted. A token is a
binding to the reviewed encoded input, **not sender authentication**.
Interactive import also requires freshly typing the exact Link ID.
Legacy WireGuard v1/v2 and IPsec remain non-importable.

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

## Explicit plaintext import via the canonical Engine

A non-interactive receiving operator may apply a reviewed,
credential-free GRE/IPIP `stl://` offer with `stl link import`.
`link preview --stdin [--json]` first produces a redacted receiver-side
preview and, only for those importable offers, `import_confirmation`:
the full SHA-256 digest of the exact input setup URL after accepting
a single optional trailing line terminator.

`link import --stdin --confirm <import_confirmation> [--json]` requires
the same URL bytes and a matching token. Invalid, changed, unsupported or
credential-bearing offers are rejected **before** backend/runtime state
is assembled. Import uses the same `Offer.ReceiverLink` inversion as
preview and delegates stateful convergence to `Engine.EnsureImported`.
Under the canonical Link lock, it permits only first creation or
idempotent re-ensure of the **exact previously committed desired state**.
An existing Link ID with different saved configuration fails with a
redacted conflict and remains unchanged: the preview token is not approval
to replace an existing Link. An explicit reconfiguration must use the
separate desired-state `link ensure` workflow. This is local, explicit
network mutation; preview and export remain read-only. The confirmation
is a reviewed-payload binding, not sender authentication, and the plaintext
transport remains insecure
against active network attackers.

This is only a **plaintext pairing slice**, not Issue #8 completion.
Receiver private key/PSK import, protected secret storage and interactive
pairing remain unsupported until integrated with the WireGuard/IPsec
backends and their review/validation gates.
