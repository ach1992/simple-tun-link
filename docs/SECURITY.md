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
interface removal does not silently destroy a private key. Verified Link-owned
credential retirement and reconciliation tooling remain outstanding.

The caller must store the **local** private key only at its owning endpoint.
The initiator must never persist a generated *recipient* private key as local
state; that material belongs only in the explicitly SENSITIVE Quick Link
until protected receiver-side import. Configured v3 receiver import now
provisions the local key under canonical Engine locks, but **guided sender
export, credential retirement, real WireGuard handshake/traffic/coexistence,
and persistence proof** remain Issue #6/#8/#12 acceptance. Read-only status
reports public handshake and counter observations; it does not authenticate
who supplied the setup URL or prove bidirectional traffic.

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
