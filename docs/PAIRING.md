# Pairing format and trust boundary — Issue #8

This document describes the first backend-neutral pairing component implemented
by `internal/pairing`. The overall v0.1 requirements are owned by
`docs/PROJECT-SPEC.md`, `docs/ARCHITECTURE.md`, Issue #8, ADR-0003 and ADR-0004.
Backend-specific interface configuration and key generation remain owned by
Issues #4–#7; CLI/import/apply orchestration remains owned by Issue #10.

## Version 1 setup links

The canonical transport string is:

~~~text
stl://1.<unpadded-base64url-of-JSON>.<lowercase-sha256-of-JSON>
~~~

The JSON contains:

- `schema_version`: integer `1`;
- `mode`: explicit `"quick"`;
- `link`: the creator-oriented backend-neutral `domain.Link`, including its
  stable Link ID, local/peer underlay endpoints and local/peer Link Addresses;
- `recipient_secret` (optional): a `kind` and unpadded-base64url `data`.

The SHA-256 value detects accidental corruption or damage. **It is neither a
MAC nor a signature.** Anyone who can modify a setup link can recompute its
checksum. Base64 is encoding, **not encryption**. Treat a secret-bearing Quick
Link as a credential, not as a shareable diagnostic artifact.

The decoder limits the entire input to 24 KiB and decoded JSON to 16 KiB.
It rejects noncanonical Base64/checksum, malformed/duplicate/unknown fields,
nested extensions without an explicit schema contract, invalid UTF-8,
truncated or mismatched checksums, unsupported mode/version, and incompatible
backend/encapsulation/credential combinations. It never evaluates embedded
content as a command or path.

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
- GRE/IPIP Native, FOU and GUE: no credential payload is accepted. GRE keys,
  when introduced by their backend, are identifiers rather than encryption.

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

## Apply and backend integration

Decoding and generating a preview **never applies a Link, starts a command,
creates a device, or persists credentials**. The backend-specific import
adapter and CLI must obtain an explicit local apply action after displaying
the redacted preview, then use the canonical Engine and backend secret
storage instead of inventing a second Link lifecycle.

The current module intentionally does not implement backend-specific
parameter mapping, the final interactive UI, or a privileged installation.
It therefore completes an **independent, testable portion of Issue #8**, not
Issue #8's full acceptance or any live tunnel-recovery requirement.

A future `secure_exchange` mode requires an explicit protocol/schema update,
not a reinterpretation of v1 Quick Link secrets. An unknown mode or
schema version currently fails closed.
