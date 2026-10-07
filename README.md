# simple-tun-link

**simple-tun-link** is a fast, simple, extensible point-to-point Layer-3 link engine for Linux.

The project creates a stable **Link Address** between two Linux servers over a selected tunnel backend. Applications and higher-level transports can use that address like any other IPv4 address, without needing to know whether the underlying link is GRE, IPIP, WireGuard, or IPsec/XFRM.

Canonical CLI: **stl**

> Status: foundation/bootstrap. Tunnel backends are tracked in GitHub Issues and are not implemented yet.

## Why

The immediate goal is intentionally small:

- install quickly on two servers;
- create one point-to-point L3 link;
- use GRE as the default backend;
- support multiple underlay methods without changing the consumer-facing Link Address;
- provide simple interactive setup, manual setup, and versioned setup-link exchange;
- diagnose MTU/connectivity problems without turning the tool into a general network-management suite.

The architecture also preserves a clean future path for a panel/agent and for higher-level consumers such as backhaul or direct-tunnel systems.

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

VXLAN and Geneve are intentionally not v0.1 scope. They solve broader overlay/L2 use cases and can be reconsidered if a concrete consumer requires them.

## Core terminology

- **Underlay Address** — the reachable address used to establish the tunnel.
- **Link Address** — the point-to-point private address created by simple-tun-link.
- **Peer Link Address** — the Link Address on the other endpoint.
- **Backend** — GRE, IPIP, WireGuard, or IPsec/XFRM.
- **Encapsulation** — a backend-specific carrier such as Native, FOU, or GUE.

No geography-specific roles such as “Iran” or “Kharej” are part of the data model.

## Project map

- [Project specification](docs/PROJECT-SPEC.md) — canonical purpose, scope, constraints, and success criteria.
- [Architecture](docs/ARCHITECTURE.md) — technical boundaries and runtime model.
- [Development](docs/DEVELOPMENT.md) — engineering rules and validation commands.
- [Security](docs/SECURITY.md) — trust, credential, firewall, and setup-link rules.
- [Architecture decisions](docs/decisions/) — durable decisions and rationale.
- GitHub Issues — authoritative unresolved work and implementation backlog.

## Development

The control plane is written in Go. Data-plane traffic remains in the Linux kernel or the selected native tunnel implementation.

Current bootstrap commands:

~~~bash
go test ./...
go vet ./...
test -z "$(gofmt -l .)"
~~~

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) before making implementation changes.

## License

No open-source license has been selected yet. License selection is intentionally tracked as an owner decision before the first release.
