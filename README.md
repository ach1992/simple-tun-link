# simple-tun-link

**simple-tun-link** is a fast, simple, extensible point-to-point Layer-3 link engine for Linux.

It creates and manages independent **Link Addresses** between Linux servers over selected tunnel backends. Applications and higher-level transports can use those addresses like normal IPv4 addresses without needing to know whether the underlying Link uses GRE, IPIP, WireGuard, or IPsec/XFRM.

Canonical CLI: **stl**  
Convenience alias: **stlink** (same executable/behavior when installed by the supported installer)

> Status: pre-release development. The GRE backend and observational CLI/diagnostics are implemented, but live GRE FOU/GUE traffic acceptance and IPIP/WireGuard/IPsec backends, complete CLI, installer and release E2E remain outstanding.

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
- [Security](docs/SECURITY.md) — trust, credential, firewall, and setup-link rules.
- [References and provenance](docs/REFERENCES.md) — predecessor/research inputs and license boundaries.
- [Architecture decisions](docs/decisions/) — durable decisions and rationale.
- GitHub Issues and milestone `v0.1.0` — authoritative unresolved work and execution backlog.

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
