# simple-tun-link

**simple-tun-link** is a fast, simple, extensible point-to-point Layer-3 link engine for Linux.

It creates and manages independent **Link Addresses** between Linux servers over selected tunnel backends. Applications and higher-level transports can use those addresses like normal IPv4 addresses without needing to know whether the underlying Link uses GRE, IPIP, WireGuard, or IPsec/XFRM.

Canonical CLI: **stl**  
Convenience alias: **stlink** (same executable/behavior when installed by the supported installer)

> Status: pre-release development. GRE/IPIP and core lifecycle CLI are integrated. The independently reviewed WireGuard backend and v3 receiver import are in `main`; sender creation, protected one-time handoff/Resume and conditional credential retirement are new development-candidate capabilities pending separate review. No real privileged WireGuard two-peer traffic, cross-backend coexistence, or release acceptance is established. Installer/update/uninstall have offline regression coverage but no public release is published; IPsec remains pending.

## Why

The immediate product stays intentionally small:

- install quickly on two or more servers;
- create and manage one or more independent point-to-point L3 Links;
- allow multiple Links to different peers and multiple simultaneous Links to the same peer pair;
- use GRE Native as the default path;
- keep common setup automatic while preserving advanced controls;
- provide interactive, manual, and versioned setup-link workflows;
- diagnose MTU/connectivity problems without becoming a general network-management suite.

STL is both a standalone tool and a reusable connectivity capability. External software of any kind can consume its stable CLI/JSON contract without reimplementing Link logic. STL does not prescribe what those consumers are or how they are built.

## v0.1 backend scope

| Backend | Mode | Security | v0.1 |
|---|---|---:|---:|
| GRE | Native | No encryption | Yes, default |
| GRE | FOU / UDP | No encryption | Yes |
| GRE | GUE / UDP | No encryption | Yes |
| IPIP | Native | No encryption | Yes |
| IPIP | FOU / UDP | No encryption | Yes |
| IPIP | GUE / UDP | No encryption | Yes |
| WireGuard | UDP | Encrypted/authenticated | Yes |
| IPsec/XFRM | ESP / NAT-T | Encrypted/authenticated | Yes |

VXLAN and Geneve are intentionally outside v0.1. They solve broader overlay/L2 use cases and can be reconsidered only when a concrete consumer needs them.

## Core terminology

- **Underlay Address** — reachable address used to establish the tunnel.
- **Link Address** — point-to-point private address created by STL.
- **Peer Link Address** — Link Address on the other endpoint.
- **Backend** — GRE, IPIP, WireGuard, or IPsec/XFRM.
- **Encapsulation** — backend-specific carrier such as Native, FOU, or GUE.

Consumer-specific concepts such as geography, product roles, orchestration policy, or application ownership are intentionally outside the STL data model. STL remains local/peer based and reusable.

## Project map

- [Project specification](docs/PROJECT-SPEC.md) — canonical purpose, scope, constraints, and success criteria.
- [Architecture](docs/ARCHITECTURE.md) — technical boundaries and runtime model.
- [Supported environments](docs/SUPPORTED-ENVIRONMENTS.md) — platform and backend capability policy.
- [Development](docs/DEVELOPMENT.md) — engineering rules and validation commands.
- [Install and recovery](docs/INSTALL.md) — installer, update, guarded uninstall and operator recovery.
- [Security](docs/SECURITY.md) — trust, credential, firewall, and setup-link rules.
- [References and provenance](docs/REFERENCES.md) — predecessor/research inputs and license boundaries.
- [Architecture decisions](docs/decisions/) — durable decisions and rationale.
- GitHub Issues and milestone `v0.1.0` — authoritative unresolved work and execution backlog.

## Installation (pre-release)

The [installation runbook](docs/INSTALL.md) documents the future tagged-release
one-command installer, checksum-verified atomic updates, the `stlink` alias,
and guarded uninstall. No public version/tag is currently available, so do
not execute the placeholder `vX.Y.Z` command as an actual installation.
For nonprivileged/offline test coverage, run `bash scripts/test-install.sh`.

## WireGuard Quick Link (pre-release)

The menu now offers a guided encrypted WireGuard/UDP sender workflow alongside
the default GRE Native path. The noninteractive `stl link create-wireguard`
creates a new WireGuard Link and writes a one-time **SENSITIVE** v3 receiver
setup URL only to an explicitly chosen, owner-private `0600` file. The peer
uses redacted `stl link preview` and confirmed `stl link import`; failed
sender activation can be resumed with `stl link resume-wireguard` using the
same protected handoff. Successful `stl link remove` preserves its private
key for rollback; separate `stl link credential retire` requires confirmed
committed-state and live-host absence before key deletion. [CLI instructions](docs/CLI.md)
explain the exact commands and safety boundaries. **No privileged two-peer
traffic, release readiness or secure channel for delivering the handoff is
implied by these source-level workflows.**

## Development

The control plane is written in Go. Native backend packet traffic stays in the Linux kernel/native implementation.

Current validation commands:

~~~bash
go test ./...
go vet ./...
test -z "$(gofmt -l .)"
~~~

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) before making implementation changes.

## License

Licensed under the [MIT License](LICENSE).
