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

Never expose by default:
- WireGuard private keys;
- IPsec PSKs/private keys;
- future bearer credentials;
- SSH credentials.

Rules:
- redact secrets from logs/status/diagnostic bundles;
- restrictive file modes;
- setup links containing a secret are explicitly marked sensitive;
- import preview shows secret presence, not the secret value;
- avoid moving a private key between hosts when a local-key pairing path is available.

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

Encoded is not encrypted. If a format contains secret material, possession of the link may grant tunnel access and documentation/UI must say so.

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

Future panel/agent work must not expose privileged network mutation directly without authentication, authorization, input validation, and local policy boundaries.

## Dependency/supply chain

Keep dependencies minimal. Review additions to Go modules, CI actions, installers, and downloaded binaries as security-relevant changes.

## Reporting

Until a dedicated security policy/contact is established, use a private repository-owner contact channel for suspected vulnerabilities rather than publishing exploitable details in a public Issue.
