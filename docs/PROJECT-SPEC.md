# Project Specification

## 1. Project identity

- Repository: ach1992/simple-tun-link
- Product name: simple-tun-link
- Canonical CLI: stl
- Primary platform: Linux
- Initial distribution target: Debian/Ubuntu-class Linux servers; detailed baseline and capability rules live in docs/SUPPORTED-ENVIRONMENTS.md

This document is the canonical project-level specification. Detailed architecture belongs in docs/ARCHITECTURE.md; live work belongs in GitHub Issues.

## 2. Problem

Operators often need a simple private point-to-point IP between two Linux servers. Native GRE may work on one route/provider and fail on another. Existing single-method scripts duplicate setup, persistence, firewall, health, MTU, pairing, and diagnostics logic while exposing different failure behavior.

The project should provide one small tool that creates the same consumer-facing L3 link while allowing the underlying tunnel backend to vary.

## 3. Desired outcome

Given two Linux servers with mutually reachable underlay endpoints, an operator can install stl, create/import a link with minimal input, and obtain a stable point-to-point Link Address on both servers.

A successful link must be usable by normal IP applications and by future higher-level consumers such as backhaul or direct-tunnel software.

Multi-Link operation is a v0.1 requirement. A host may own zero or more independent Links, including multiple Links to the same peer underlay endpoint pair. For example, A <-> B may simultaneously use GRE Native, WireGuard, and GRE/FOU with distinct Link Addresses and resources. The model must not enforce a one-Link-per-host or one-Link-per-peer singleton. A specific combination may be rejected only when the selected backend/kernel cannot unambiguously distinguish the required resources.

Example conceptual result:

~~~text
Server A                            Server B
Underlay A <--- selected backend ---> Underlay B
Link A 10.80.20.0/31 <-----------> Link B 10.80.20.1/31
~~~

## 4. v0.1 user experience

The default path is an interactive terminal UI:

1. Open stl.
2. Show project/version/repository and concise local server/network facts.
3. Create Tunnel.
4. GRE / Native is preselected.
5. Common settings use safe automatic values.
6. Advanced settings are opt-in.
7. Create a versioned setup link and a human-readable configuration block for the peer.
8. Import on the peer, preview the effective configuration, apply, and verify.
9. Show concise connectivity and MTU/quality results.

A non-interactive CLI and machine-readable JSON output must expose the same core operations for automation and future panel/agent use.

## 5. v0.1 backend scope

### GRE — default
- Native GRE is the default backend and default encapsulation.
- Keyed GRE is supported; keys are identifiers, not security.
- FOU and GUE UDP encapsulation are supported as advanced alternatives.
- MTU supports Auto and Manual modes.
- TTL/TOS/PMTUD and other backend-relevant knobs may be exposed under Advanced only when they materially affect real routes.

### IPIP
- Native IPIP.
- FOU and GUE UDP encapsulation.
- Same common Link lifecycle and diagnostics model as GRE.

### WireGuard
- Native WireGuard transport.
- Secure/authenticated link.
- Private keys are local secrets and must not be logged or exposed by default.
- Pairing UX may require a response exchange when keeping private keys local.

### IPsec/XFRM
- strongSwan/IKEv2 with Linux XFRM interfaces, not the legacy VTI-first design.
- Native ESP and NAT-T/ESP-in-UDP behavior.
- Credential material is secret and follows setup-link security rules.

## 6. Link addressing

- v0.1 uses IPv4 point-to-point Link Addresses.
- Default allocation target is an unused RFC1918 /31 pair.
- Automatic allocation must check local routing/address state and, when peer information is available, avoid collisions on both endpoints and across every existing STL Link on the host.
- Manual Link Address configuration remains available.
- The internal model should not make future IPv6 support unnecessarily difficult.

## 7. Setup methods

Required:
- interactive create;
- manual configuration;
- versioned setup-link import/export;
- human-readable copy block;
- preview before apply.

Preferred future-friendly path:
- optional SSH-assisted pairing may configure both endpoints while keeping secrets local.

Setup-link data is data only. Import must never execute shell content embedded in a link.

## 8. Diagnostics and tuning

Creation must use a small high-value diagnostic set:

- backend/kernel/tool preflight;
- route/source endpoint validation;
- interface/port/subnet conflict detection;
- tunnel/link-address reachability;
- MTU/PMTU probe with manual override;
- short latency/loss/jitter measurement;
- backend-specific state/counter validation;
- optional throughput test, not mandatory during ordinary creation.

Health observation and repair are separate operations. A health check must not silently mutate the system.

## 9. System-change principles

- Do not enable global ip_forward merely to create host-to-host Link Addresses.
- Do not globally disable rp_filter by default.
- Any required sysctl change must be scoped as narrowly as possible, owned by the tool, and safely restorable.
- Firewall rules must be minimal, peer/protocol/port scoped where possible, and removable without flushing or rewriting unrelated policy.
- Do not change the host's primary network manager merely to create a link.
- Existing interfaces/configuration are never overwritten without identity validation.
- Apply operations are idempotent.
- Partial failure must roll back only state owned by the current operation.
- Creating, updating, repairing, or removing one Link must not mutate or disrupt another Link.
- Concurrent Link operations must coordinate collision-sensitive resource allocation so two operations cannot claim the same interface identity, Link Address, backend key/identifier, UDP/listen port, XFRM identity, route/firewall ownership, or persistence identity.

## 10. Architecture and performance constraints

- Go is the control-plane implementation language.
- Packet data should remain in Linux/native backend data paths; stl must not proxy packets for native backends.
- Core domain/backend logic must not depend on the interactive menu.
- CLI JSON output is a first-class contract for automation; every machine-readable payload carries an explicit schema version and breaking schema changes require a version bump.
- The automation surface provides idempotent desired-state semantics (for example, `stl link ensure ... --json`) so callers do not need to reproduce create/update/repair decision logic.
- The engine treats Links as a collection keyed by stable Link ID; it must not assume one active Link, one Link per peer, or one Link per backend.
- No daemon, central database, web panel, or multi-server control plane is required in v0.1.
- Boundaries must allow a future local agent/API/panel to reuse the same engine rather than reimplement tunnel logic.
- Avoid premature public-library APIs; promote a stable reusable API only when a second real consumer proves the requirement.

## 11. Standalone use and future composition

STL is a complete standalone tool and also a reusable connectivity capability.

~~~text
Human operator ----------------------> stl interactive CLI
Independent script ------------------> stl CLI / versioned JSON
Future node agent/control plane -----> STL engine or CLI contract
                                          |
                                   stable Link Address
                                          |
                             backhaul / direct / service
~~~

A future central platform may manage many servers, tunnel products, and even non-tunnel software. That platform may choose STL as a prerequisite/provider for point-to-point L3 connectivity while keeping its own concepts such as node inventory, geography/region, Iran/Kharej roles, application ownership, consumer references, and orchestration policy. Those concepts do not enter the STL domain model.

Higher-level consumers may depend on a Link. Dependency/consumer ownership belongs to the higher-level orchestrator; STL owns Link lifecycle and its local resources. The overall dependency graph must remain acyclic, so a Link cannot depend on a higher-level consumer that itself depends on that Link.

The v0.1 architecture preserves this composition path through stable Link IDs, desired/observed state, idempotent ensure/apply behavior, versioned state and JSON schemas, machine-readable errors, and UI-independent engine logic. It does not build a daemon, remote protocol, generic plugin framework, central database, or panel before a real consumer requires them.

Potential future work, explicitly not promised by v0.1:
- local agent/daemon and remote generic server/capability control plane;
- MASQUE/CONNECT-IP or other standardized userspace carriers;
- OpenVPN/TCP fallback;
- IPv6 Link Addresses;
- L2/overlay modes such as VXLAN/Geneve when a concrete use case justifies them.

No transport may be marketed or documented as “undetectable.” Encryption/security and traffic distinguishability are separate properties.

## 12. Non-goals for v0.1

- general-purpose router/firewall management;
- NAT/port-forwarding product;
- internet proxy;
- multi-node mesh controller;
- L2 virtual datacenter overlay;
- custom packet relay/camouflage engine;
- automatic routing of arbitrary LAN subnets;
- general host optimization/tuning suite.

## 13. Observable v0.1 success

v0.1 is complete when:

- a clean supported Linux host can install and run stl;
- GRE Native, GRE FOU/GUE, IPIP Native, IPIP FOU/GUE, WireGuard, and IPsec/XFRM have tested create/status/remove lifecycles;
- GRE Native is the default interactive path;
- setup-link and manual pairing are usable and validated;
- automatic MTU and core diagnostics produce actionable results;
- repeated apply is idempotent and partial failures roll back owned state;
- restart/reapply persistence works without corrupting unrelated network state;
- machine-readable CLI output exists for core operations with an explicit schema version and stable error/exit semantics;
- a script can converge a Link toward desired state through an idempotent automation operation without parsing interactive output;
- one host can operate multiple simultaneous Links to multiple peers and multiple independent Links to the same peer pair; the v0.1 E2E suite includes A <-> B with GRE Native, WireGuard, and GRE/FOU active together, each with independent Link Addresses;
- removing or repairing one Link in a multi-Link scenario leaves the other Links operational and their traffic unaffected;
- automated tests cover domain/config logic and Linux namespace/integration paths where technically feasible;
- documentation is sufficient for another maintainer to continue work without chat history.

## 14. Owner decisions still open

These are intentionally not guessed:

- open-source license for the first release;
- whether stlink should be shipped as an optional alias in addition to canonical stl;
- exact secure-vs-one-shot setup-link UX for secret-bearing backends after implementation spike evidence.
