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
