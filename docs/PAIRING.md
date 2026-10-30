# Setup Link format and trust boundary

This is the **wire-format and compatibility contract** for
`internal/pairing`. User commands are documented in
[CLI.md](CLI.md); key storage and recovery rules belong to
[SECURITY.md](SECURITY.md). Pairing decodes and inverts
configuration; it must **never mutate a host by previewing**.

## Why a versioned Quick Link?

STL uses a simple one-step `quick` offer so that the receiving
operator can configure the complementary endpoint without a
second key-exchange round trip. That simplicity means an offer
containing the recipient's WireGuard private key or an IPsec PSK
is **SENSITIVE** credential material. Base64 encoding is **not
encryption**, and the embedded SHA-256 checksum detects accidental
damage, **not** malicious rewriting or sender identity.

A future local-key/`secure_exchange` flow would need a
separately versioned protocol, not a reinterpretation of an
existing Quick payload. Treat Setup Links as untrusted input.

## Wire formats and compatibility

The canonical GRE/IPIP/IPsec v2 form is:

~~~text
stl://2.<unpadded-base64url-of-JSON>.<lowercase-sha256-of-JSON>
~~~

Its JSON contains integer `schema_version:2`,
`mode:"quick"`, creator-oriented public `link` fields
and optional `recipient_secret` with `kind` and Base64
`data`. Typed `link.gre` includes key presence/value,
GRE advanced flags and FOU/GUE UDP port so that importing
does not manufacture a collision-sensitive setting.

Configured WireGuard uses **v3** (`stl://3.`): a public-only
`link.wireguard` carries
`local_public_key`, `peer_public_key`, `listen_port`,
`peer_port`, `local_keepalive` and `peer_keepalive`.
The receiver private key belongs only in the deliberately
sensitive credential payload and must derive the recipient's
declared public key; a recomputed checksum cannot bypass that
identity requirement. Two distinct canonical public keys and
explicit configured ports are required for new operational offers.

| Offer | Decode/preview | Confirmed import |
| --- | --- | --- |
| GRE/IPIP v2 with valid options | Yes | Yes, after token and identity checks |
| GRE/IPIP v1 with supported Native options | Yes | Only supported validated configurations |
| WireGuard v3, public config + matching receiver secret | Yes | Yes, through protected credential provision |
| Legacy credential-only WireGuard v1/v2 | Yes, redacted | **No**; missing operational public peer config |
| IPsec v2 with nonzero exactly 32-byte PSK | Yes | Only with fresh native-exclusive admission |
| IPsec v1 or v2 with unsupported PSK size | Yes where structurally valid | **No**; never silently rekey |
| Unsupported version, incompatible backend/mode or invalid checksum | No | No |

A legacy decoded v1 offer retains its format on intentional
re-export. GRE FOU/GUE v1 is rejected when its missing UDP port
would require inventing identity; v1 does not accept new v2 GRE
fields and v1/v2 cannot carry v3 WireGuard public extensions.

Decode bounds are **24 KiB entire input** and
**16 KiB decoded JSON**. Require canonical Base64/checksum,
known fields and compatible backend/mode options, no duplicate
or case-variant keys, valid UTF-8/surrogate handling, no shell
evaluation and no arbitrary file/command interpretation.
Scoped IPv6 zone identifiers are not portable and are rejected;
IPv6 underlay without zones may be valid even though IPv4
Link Addresses are the initially supported link dataplane.

## Creator / recipient perspective

The offer describes the **creator's** local/peer underlay
endpoints and Link Addresses. `Offer.ReceiverLink()`
centralizes inversion at the recipient, swapping those
endpoints/addresses and—for WireGuard—the public key,
listen/peer port and endpoint keepalive roles. Stable Link ID,
backend/encapsulation and display name stay unchanged.
Individual Link IDs are distinct even for same-peer Links.

The ordinary application `Link` is public configuration:
- GRE/IPIP carry no private credential (GRE key is a
  nonsecret identifier, not an encryption key).
- WireGuard receiver secret is exactly a recipient-bound
  private key and is never inserted into the initiator's
  ordinary State.
- IPsec v2 protected import requires a fresh, nonzero
  256-bit PSK shared by the intended two endpoints.

`PreviewSetupLink` / `Offer.Preview()` return only
receiver-facing public metadata and credential
**presence/type**. `Offer.MarshalJSON`, `String` and
`GoString` must remain redacted. Only deliberately
named export methods such as `EncodeSetupLink()` and
`HumanReadableBlock()` may produce full sensitive bytes,
with explicit private-handling responsibility. The
`RecipientCredential()` call returns a private copy only
for authorized backend provisioning.

## Preview, consent and Engine integration

`stl link preview --stdin --json` reads an original URL on
**stdin** and never performs network, State or credential
mutations. A supported importable payload emits a
`import_confirmation` (lowercase SHA-256 of the exact
normalized input, tolerating at most one trailing newline).
The token binds the **bytes** reviewed, not the sender's
authority. No secret or arbitrary display name enters
generic JSON or logs.

`stl link import --stdin --confirm <import_confirmation>`
re-decodes that same original URL and uses the
canonical Link-locked Engine to activate the inverted
recipient Link. It never replaces an existing Link ID
with different configuration. Credential-bound import
requires protected key/PSK storage and fresh backend
admission; local success is not proof of peer traffic.

`stl link export` intentionally re-creates a saved
**credential-free GRE/IPIP** offer, including its network
metadata, but does not rebuild a missing WireGuard/IPsec
receiver credential from public saved State. Guided
sender Share instead retains the **original** owner-private
SENSITIVE receiver handoff with fresh `SHOW` consent.
Sender Create stages its own key plus full public pending
Link and exact offer digest **before** protected no-replace
handoff publication; exact Resume or
`recover-handoff` can reuse only intact original
material. Unknown orphan keys, mismatched receipts or a
missing offer are not authority to regenerate secrets or
delete resources. Consult [SECURITY.md](SECURITY.md)
and [CLI.md](CLI.md) for protected file/recovery commands.

## WireGuard over WSS R1 confidential peer JSON (distinct from stl:// Quick Link)

WSS R1 deliberately does **not** reinterpret existing v1/v2/v3 stl://
payloads. Its bounded JSON receiver file uses schema_version=1,
sender/receiver public Link objects, receiver_wireguard_private_key and
receiver_tls (four receiver-local mTLS CA/leaf/key/bearer files). WSS fields
were introduced in versioned ordinary State v4 **without** private material
and remain readable in the current State v5 schema.
The creator generates both endpoint keys and the independent Link-specific
authorization token once. The CA signing key is intentionally discarded,
not stored with the receiver file. Receiver import checks exact reciprocal
peer roles, addresses, ports and WireGuard key identity.

The separate preview-wss command has no host effect. Its lowercase SHA-256
confirmation binds the exact reviewed private JSON byte sequence (ignoring
a single trailing newline); it does **not** prove sender authority. Transport
the original handoff by an authenticated encrypted channel and verify peer
details out of band. A copied WSS JSON file is a secret, **not** a shareable
public Setup Link. Reissuing a revoked or retired Link requires a fresh ID,
CA, leaf identities and bearer; do not recycle any retired credentials.

## Managed QUIC confidential peer JSON (distinct schema 1)

Managed QUIC uses a dedicated private JSON handoff with `schema_version:1`,
public `sender` and `receiver` Links, `receiver_wireguard_private_key`, and
four receiver-local `receiver_tls` byte values. It is not a native
`stl://` v1/v2/v3 offer and is not a WSS offer. Each public Link explicitly
selects `wireguard-quic` and its endpoint-local role, forwarding port and
MTU policy. Validation checks reciprocal physical/private addresses,
WireGuard keys and ports, complementary roles, exact TLS SAN, trust anchors,
leaf/key pairing, credential lifetime and the complete allowed field set.

A receiver must preview the original bytes and confirm their SHA-256 before
import. The sender publishes only a protected no-clobber private handoff,
after its own material is durably staged under the Engine's managed
pre-effect journal. It retains no CA signing key. The receiver private key
and bearer never enter public State or normal command output. Treat every
external copy as a live secret and transfer it through an authenticated
private channel.

Saved handoff sharing verifies the original public topology and protected
sender generation before showing the original token. Repeated import can
reuse only the same committed recipient identity and material. Sender
Resume uses the original sender Link and existing credentials; it cannot
silently replace keys or consume an unresolved operation. See
[the QUIC command contract](CLI.md#managed-wireguard-over-quictls).
