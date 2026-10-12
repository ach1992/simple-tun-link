# simple-tun-link

**simple-tun-link** is a fast, simple, extensible point-to-point Layer-3 link engine for Linux.

It creates and manages independent **Link Addresses** between Linux servers over selected tunnel backends. Applications and higher-level transports can use those addresses like normal IPv4 addresses without needing to know whether the underlying Link uses GRE, IPIP, WireGuard, or IPsec/XFRM.

Canonical CLI: **stl**  
Convenience alias: **stlink** (same executable/behavior when installed by the supported installer)

> Status: **pre-release; no public tag or GitHub Release**. The source
> integrates GRE/IPIP Native/FOU/GUE, WireGuard v3 Quick Link, and the
> **conditionally admitted**, native-exclusive IPsec/XFRM IKEv2 ESP/NAT-T
> backend. Privileged six-simultaneous-Link E2E passed on native AMD64 and
> ARM64 kernels with Ubuntu 24.04.5 and Debian 13 container userspaces
> ([PR #77](https://github.com/ach1992/simple-tun-link/pull/77)).
> Container userspaces share each runner's kernel; separate distro-kernel
> and whole-guest reboot evidence is tracked in
> [Issue #12](https://github.com/ach1992/simple-tun-link/issues/12).
> Full-guest IPsec ESP/NAT-T reboot, physical NAT-router traversal and abrupt
> power-loss recovery remain unproven. [Issue #11](https://github.com/ach1992/simple-tun-link/issues/11)
> owns tagged artifacts, published installer verification and public release.

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

## Read-only IPsec troubleshooting (pre-release)

Use `stl doctor ipsec` for a plain-language report or `stl doctor ipsec --json`
for stable reason identifiers, observed prerequisite state and suggested
next steps. This command is read-only. It reports `activation_allowed:true`
only when strict native-exclusive runtime admission independently attests
the STL-owned strongSwan configuration, loaded service, process, VICI,
UDP ports and relevant kernel ownership. Otherwise it reports an explicit
blocked/unknown state and exits unsupported (4); it never installs,
starts or adopts a service. An apparently empty process listing, non-observed
UDP 500/4500 binding or readable XFRM inventory is not proof of ownership.
Foreign or unverifiable strongSwan deployment blocks **only IPsec**, never
GRE/IPIP/WireGuard. See [CLI](docs/CLI.md),
[real IPsec acceptance](docs/operations/IPSEC-REAL-E2E.md) and
[ADR-0005](docs/decisions/ADR-0005-scoped-vici-ipsec.md).

## One-command Link health and troubleshooting

Inspect every configured Link from one place without repairing anything:

~~~sh
stl link diagnose --all
stl link diagnose --all --json
stl link diagnose --all --timeout 10m --json
~~~

The same feature is under **Tests & Diagnostics → all** in the terminal menu.
For each GRE, IPIP or WireGuard Link, STL checks the live backend identity,
uses bounded Link Address probes and reports observed MTU/quality/counters.
One failing Link does not hide other Links. IPsec remains separately
capability-gated: a blocked or unknown admission state must never be
reported as healthy. Reports distinguish replied, blocked and unknown
conditions with stable machine `reason_code` and safe `next_step`.
A reply proves reachability only during the test; unknown is **not**
silently promoted into a healthy result. Ordinary operator errors now
include actionable, redacted recovery guidance too.

See [CLI](docs/CLI.md) and [diagnostic contract](docs/DIAGNOSTICS.md).
These read-only source-backed diagnostics are **not** a substitute for the
separately required live release E2E tests in Issue #12.

## WireGuard Quick Link (pre-release)

The menu now offers a guided encrypted WireGuard/UDP sender workflow alongside
the default GRE Native path. The noninteractive `stl link create-wireguard`
creates a new WireGuard Link and writes a one-time **SENSITIVE** v3 receiver
setup URL only to an explicitly chosen, owner-private `0600` file. The peer
uses redacted `stl link preview` and confirmed `stl link import`; failed
sender activation can be resumed with `stl link resume-wireguard` using the
same protected handoff. Sender creation durably stages its own private key
and exact handoff-bound **public pending Link intent before exposing the
SENSITIVE URL**, and successful commit consumes Pending atomically.
Successful `stl link remove` preserves its private
key for rollback; separate `stl link credential retire` requires a
**Link-specific durable successful-Remove receipt** and live-resource absence,
never an unrelated state file. [CLI instructions](docs/CLI.md) explain the
exact commands, recovery boundaries and safety requirements. **The
create/import workflow alone does not establish encrypted traffic or a safe
handoff channel.** Focused real-kernel WireGuard/GRE evidence is recorded in
PR #53 / Issue #12; release, restart, multi-peer and cross-platform
acceptance remain open. Deliver the SENSITIVE handoff through a trusted channel.

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
