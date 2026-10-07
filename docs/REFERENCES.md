# References and Provenance

This document records decision inputs that future maintainers would otherwise have to recover from chat history. It is not a live status log.

## Predecessor repositories

### ach1992/simple-gre

Earlier standalone GRE manager. It demonstrated the desired simplicity but also motivated consolidating repeated lifecycle, route/source discovery, firewall, persistence, MTU, and error-handling logic into one typed engine.

At the 2026-10-07 audit, no root `LICENSE` file was present. Do not assume a public reuse license from repository visibility alone.

### ach1992/simple-wireguard-tunnel

Earlier standalone WireGuard manager. It informs the user workflow and reinforces that peer private keys should stay local by default.

At the 2026-10-07 audit, no root `LICENSE` file was present.

### ach1992/simple-ipsec-tunnel

Earlier strongSwan/VTI-oriented manager. STL intentionally moves the primary route-based IPsec design to Linux XFRM interfaces.

At the 2026-10-07 audit, no root `LICENSE` file was present.

These repositories are predecessor/reference inputs, not authoritative STL architecture after this repository was created.

## External reference projects

### AminMGMT/BackPack

Studied for pairing/setup-link usability and operational ideas.

Repository license observed on 2026-10-07: **GNU AGPLv3**.

Rule: do not copy AGPL implementation code into STL unless a future explicit licensing decision makes that compatible. Reimplement only independently derived concepts/behavior.

### LivingG0D/Golden-GRE

Studied for GRE/UDP-encapsulation and preflight/rollback operational patterns.

Repository license observed on 2026-10-07: **Apache License 2.0**.

Even when license-compatible reuse might be possible later, prefer independent implementation unless copying code has a clear benefit and provenance/notice obligations are deliberately handled.

## Primary technical references

- RFC 3021 — 31-Bit Prefixes on IPv4 Point-to-Point Links: https://www.rfc-editor.org/rfc/rfc3021.html
- Linux/iproute2 `ip-link(8)` — GRE/IPIP keys and FOU/GUE encapsulation: https://man7.org/linux/man-pages/man8/ip-link.8.html
- Linux/iproute2 `ip-fou(8)` — FOU/GUE receive-port behavior: https://man7.org/linux/man-pages/man8/ip-fou.8.html
- strongSwan route-based VPN/XFRM interfaces: https://docs.strongswan.org/docs/latest/features/routeBasedVpn.html
- Go release history/policy: https://go.dev/doc/devel/release

## Reuse rule

STL is licensed under the MIT License. Ideas, standards, and observed behavior may inform STL design. Source-code reuse is a separate decision and still requires explicit provenance/license compatibility. BackPack implementation code remains incompatible with STL's MIT licensing unless a future licensing decision explicitly changes that boundary; Golden-GRE direct code reuse would require deliberate Apache-2.0 attribution/notice handling. Independent reimplementation remains the default.
