# ADR-0004: Quick Link is the v0.1 default for secret-bearing pairing

- Status: Accepted
- Date: 2026-10-07

## Context

WireGuard and IPsec can require secret material on the receiving endpoint. A two-step/local-key exchange can minimize secret transport, but it adds pairing state, a response exchange, and more user/implementation complexity.

The v0.1 product goal favors the simplest reliable setup while keeping security consequences explicit and preserving a path to stronger exchange modes later.

## Decision

For v0.1, **Quick Link** is the default one-step pairing mode for secret-bearing backends.

The pairing schema carries an explicit exchange mode. v0.1 defines `quick`; a future `secure_exchange` or equivalent local-key mode may be added without changing the core Link model or reinterpreting existing Quick payloads.

### WireGuard

- The initiator may generate the receiver keypair solely to prepare the pairing payload.
- The receiver private key may appear only inside the explicitly **SENSITIVE** Quick Link/configuration payload and then in the receiver's protected local state after import.
- The initiator persists only the receiver public key and does not retain the receiver private key in ordinary state.
- Private keys never appear in ordinary logs, status, diagnostics, or generic JSON.

### IPsec / PSK

- A shared PSK may be included in the explicitly **SENSITIVE** Quick payload.
- Each endpoint stores the PSK only where the IPsec implementation requires it, with restrictive permissions.
- The PSK never appears in ordinary logs, status, diagnostics, or generic JSON.

### Payload handling

- Encoded setup links are not encryption.
- Possession of a secret-bearing Quick payload may grant access and must be treated like a credential.
- Import preview reveals secret presence, not secret values.
- STL must not automatically persist secret-bearing exports to logs, shell history, diagnostic bundles, or world-readable files.
- If STL writes a secret-bearing export file, it uses restrictive permissions.

## Consequences

Positive:
- one-step setup is simpler for the user;
- v0.1 avoids a second exchange/state machine solely for pairing;
- standalone/manual use remains straightforward;
- external automation can transport one versioned pairing object.

Trade-off:
- the Quick payload itself becomes sensitive credential material.

Future:
- a local-key/Secure Exchange mode can be added if justified without breaking existing Quick Link payloads or the core Link abstraction.
