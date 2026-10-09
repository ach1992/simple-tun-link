# Pairing format and trust boundary — Issue #8

This document describes the first backend-neutral pairing component implemented
by `internal/pairing`. The overall v0.1 requirements are owned by
`docs/PROJECT-SPEC.md`, `docs/ARCHITECTURE.md`, Issue #8, ADR-0003 and ADR-0004.
Backend-specific interface configuration and key generation remain owned by
Issues #4–#7; CLI/import/apply orchestration remains owned by Issue #10.

## Version 2 setup links

The current canonical transport string is:

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
rejection. The decoder remains compatible with version 1 payloads whose
semantics were complete (including GRE Native, IPIP, WireGuard and IPsec), and
a decoded v1 offer preserves v1 when re-exported. Legacy v1 GRE FOU/GUE links
are rejected with an explicit regeneration requirement because v1 never carried
the now-required UDP port; inventing one during import would change networking
semantics and collision ownership. Version 1 also rejects v2-only `gre` fields.

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
and Link Addresses) before applying. The stable Link ID, backend,
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

Actual user-confirmed credential storage and import/apply remain separate
Issue #8/#10 acceptance; this command does not imply they are implemented.

## Apply and backend integration

Decoding and generating a preview **never applies a Link, starts a command,
creates a device, or persists credentials**. The backend-specific import
adapter and CLI must obtain an explicit local apply action after displaying
the redacted preview, then use the canonical Engine and backend secret
storage instead of inventing a second Link lifecycle.

The pairing module carries validated backend options but does not itself apply
them, implement the final interactive UI, or perform privileged installation.
Application still goes through the canonical Engine/backend lifecycle. Pairing
therefore remains an **independent, testable portion of Issue #8**, not Issue
#8's full acceptance or any live tunnel-recovery requirement.

A future `secure_exchange` mode requires an explicit protocol/schema update,
not a reinterpretation of v1 Quick Link secrets. An unknown mode or
schema version currently fails closed.
