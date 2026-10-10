# Security Model

## Security is backend-specific

The Link abstraction does not imply encryption.

- GRE/IPIP, including FOU/GUE encapsulation, do not provide confidentiality or peer authentication by themselves.
- GRE keys are identifiers, not cryptographic secrets.
- WireGuard provides encrypted/authenticated transport when configured correctly.
- IPsec/XFRM provides encrypted/authenticated transport when configured correctly.

The UI and JSON status must not label plaintext backends as secure merely because a key/encapsulation exists.

## No “undetectable” guarantee

The project may support transports that work across different network conditions, but it must not claim any backend is undetectable or guaranteed to bypass a censor/filter. Encryption and traffic distinguishability are different properties.

## Secrets

Never expose secrets through ordinary observability or machine-status surfaces:
- WireGuard private keys;
- IPsec PSKs/private keys;
- future bearer credentials;
- SSH credentials.

Rules:
- redact secrets from logs/status/diagnostic bundles/generic JSON;
- restrictive file modes for persisted secret state;
- a v0.1 Quick Link is an explicit, deliberate exception for pairing transport and may contain receiver credentials;
- secret-bearing setup links/configuration blocks are explicitly marked **SENSITIVE**;
- import preview shows secret presence, not the secret value;
- do not automatically write secret-bearing payloads to logs, shell history, diagnostic bundles, or world-readable files;
- when STL itself writes a secret-bearing export file, use restrictive permissions;
- after generating a WireGuard peer keypair for Quick Link, the initiator persists only the peer public key and must not retain the peer private key in ordinary state.

### WireGuard key-material boundary

The WireGuard adapter under `internal/backend/wireguard` supports a
credential-protected, Engine-owned per-Link interface lifecycle and v3
receiver import, **not** a privileged-traffic-accepted/released backend. It uses Go's standard X25519
implementation and clamped `wg genkey`-compatible output. Generic JSON and
formatting do not serialize private bytes; deliberate `SecretWireValue()`
access is reserved for credential-specific pairing/file operations, never
status, diagnostics or normal desired-state storage.

`KeyStore` places a private key in a dedicated per-Link file under the
STL state root's private `credentials/` directory. It requires owner-private
directories, rejects symlink traversal, reads only a same-owner singly-linked
regular file with mode `0600`, and publishes a synced temporary key file with
an atomic **no-replace** hard link followed by directory sync. Concurrent
new-key writes for one Link must not overwrite one another. Publication
uncertainty must be reconciled rather than blindly deleting an existing key.
The store intentionally has no generic update/remove API. A verified,
read-only FD can be inherited by `wg set private-key /proc/self/fd/3`
without exposing the private key in argv, shell history, generic status or
normal JSON. `EnsureRecipient` is replay-safe only for an identical key.
Failed/uncertain activation preserves protected credentials for safe retry;
interface removal does not silently destroy a private key. Before a
**destructive** WireGuard Remove, the Engine-held validation and the immediate
Apply preflight both require a protected, safely readable private credential
whose public identity matches the persisted Link. Missing, permission-drifted,
or mismatched credentials refuse deletion of both the interface and firewall,
so an uncommitted Remove can still reconstruct the original owned state.
An explicit, identity-bound credential retirement action is available only
after a **specific durable successful canonical Remove receipt** for the
Link ID, WireGuard backend and exact local public identity, plus read-only
live host absence checks under the Engine Link lock. An unrelated committed
state file is never sufficient; indeterminate Remove and failed first Ensure
never issue retirement authorization. On a new Ensure attempt for the same
ID, any old receipt is invalidated *before* staging/Apply. Successful key
retirement marks the exact receipt retired as a durable idempotency witness;
normal Remove still preserves the key for rollback. A missing/unsafe file,
missing proof or live STL-owned resource refuses retirement. Safe
retirement is not secure physical-media erasure, and unexpected external
privileged filesystem changes still require operator reconciliation.

The caller must store the **local** private key only at its owning endpoint.
The initiator must never persist a generated *recipient* private key as local
state; that material belongs only in the explicitly SENSITIVE Quick Link
until protected receiver-side import.
Sender Create stages its **own** protected private key and a no-secret,
SHA-256-bound public `pending_senders` reservation in ordinary state **before**
allowing the recipient handoff to become visible. A successful canonical
Engine state commit consumes Pending atomically while publishing the Link.
After incomplete creation, exact Resume checks every field and the original
full payload digest, not just the sender's public key. An untrusted modified
and rechecksummed offer cannot become the original pending sender Link.
The pending record is public configuration, not a backup of either private
key; loss of a receiver handoff before publication requires explicit orphan
reconciliation rather than silent rekeying.
 Configured v3 receiver import now
provisions the local key under canonical Engine locks. The guided sender
now generates its own protected private key and a separate ephemeral receiver
private key only for a deliberately exported 0600 SENSITIVE Quick Link,
while its ordinary state retains only the receiver public key. Real WireGuard
handshake/traffic/coexistence and persistence proof remain Issue #6/#8/#12
acceptance. Read-only status
reports public handshake and counter observations; it does not authenticate
who supplied the setup URL or prove bidirectional traffic.

### IPsec protected-PSK foundation (not yet a live backend)

The IPsec module now has a separate Link-scoped protected PSK store under
the same descriptor-verified root's private `credentials/` directory.
It uses `<link-ID>.ipsecpsk` files, distinct from `.wgkey`, with strict
`0700` directories, owner-only `0600` regular single-link files, no-symlink
descriptor traversal, and atomic no-replace publication followed by directory
fsync. The shared `internal/credentials` implementation retains the existing
WireGuard path checks; two independent backend keys cannot overwrite one
another, including when their Link ID text matches.

The IPsec v0.1 store accepts **exactly 32 random bytes** (256-bit PSK),
rejects all-zero and noncanonical stored encoding, redacts generic Go
formatting and JSON, returns a private copy only through the deliberately
named `SecretBytes()` function, and requires the caller to clear that copy.
`EnsureExact` allows replay of the identical PSK but never silent rekey or
replacement. Publication errors after a no-replace write may leave an orphan
credential; this is deliberate fail-closed recovery preservation.

**Security scope boundary:** No production IPsec Engine registration, VICI
load/unload, IKE identity proof, live SA, XFRM interface, pairing CLI or
credential retirement is implemented by this storage milestone. A VICI name
match never proves ownership; future Engine operations must hold the
canonical maintenance/per-Link/resource locks and prove exact owned state
before any daemon mutation or removal. Legacy v2 Quick Link IPsec offers are
still preview-only; some older offers may contain bounded PSKs other than
32 bytes, but this protected store does not silently accept or mutate them.
Their eventual migration/import policy needs explicit compatibility handling
before exposing a user-facing IPsec import or rekey flow.

### Engine-locked IPsec credential intent (pre-operational)

A source-only canonical Engine staging transaction now reserves a full
public IPsec Link identity and its collision-sensitive resource claims in
`state.json` before an explicitly **SENSITIVE** Quick Link can be handed
to a peer. The sender reserves a SHA-256 digest of the exact legacy v2
Quick Link; the receiving endpoint requires confirmation of the exact
original previewed URL bytes, then records the fully inverted public Link
and role. Raw PSK and setup URL do **not** enter ordinary state.

The Engine acquires the existing shared maintenance gate, per-Link lock,
and resource locks. With no previous pending record it uses no-replace
PSK publication, then durable public-intent publication before invoking
an explicitly supplied sensitive handoff callback. A retry requires the
same complete public Link, original exact setup-link digest, and exact
**existing** protected PSK. A missing, unsafe or different key under an
otherwise durable pending intent requires explicit reconciliation, not
automatic regeneration (including if the sender/recipient Link and digest
match). The sender records the creator-oriented Link, while the recipient
records its exact inversion. Failed or uncertain publication preserves an
orphan PSK or pending record; it never guesses ownership or silently
adopts, removes, or rekeys the file. An explicit future operator reconciliation path is
required for orphaned keys without a matching durable public intent.

Existing v2 IPsec payloads still decode for preview; only exactly 32-byte
PSKs may enter the new protected staging transaction. Different-length
legacy payloads remain preview-only and require an explicit user decision
about rekey/import, not automatic coercion. The staged state is **not**
a committed live Link and cannot authorize VICI writes, XFRM changes,
SA teardown, credential retirement, or an operational success message.
No production IPsec CLI/backend is registered by this milestone.

## Setup-link safety

A setup link is untrusted input.

Decoder requirements:
- scheme/version validation;
- bounded input/decompression/decoded size;
- strict field validation;
- no shell evaluation;
- no arbitrary file paths/commands;
- no automatic apply without preview/explicit local action;
- reject incompatible backend/encapsulation fields;
- integrity/damage detection.

Encoded is not encrypted. In v0.1, Quick Link is the default one-step mode for secret-bearing backends, so possession of such a payload may grant tunnel access. Documentation/UI must clearly say so and treat the payload like a credential. The versioned schema must allow a later secure/local-key exchange mode without weakening or ambiguously reinterpreting existing Quick payloads.

## Host mutation

Network changes can affect host connectivity.

Rules:
- inspect before change;
- do not touch the AI Server Agent/control-plane network during tests;
- no firewall flush;
- no default-route replacement for ordinary Link creation;
- no global ip_forward enablement for host-to-host links;
- no global rp_filter disablement by default;
- track/restore only state the tool owns;
- validate interface identity before update/delete.

## Privilege

Creation/removal of Linux network links generally requires elevated capability/root. Keep privileged operations small and explicit.

Any future external integration that exposes privileged network mutation must provide appropriate authentication, authorization, input validation, and local policy boundaries.

## Dependency/supply chain

Keep dependencies minimal. Review additions to Go modules, CI actions, installers, and downloaded binaries as security-relevant changes.

## Reporting

Private vulnerability reporting is enabled for this public repository. Report suspected vulnerabilities through GitHub's private vulnerability reporting/Security Advisory flow rather than publishing exploitable details in a public Issue.
