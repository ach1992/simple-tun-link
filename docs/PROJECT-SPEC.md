# Simple Tun Link — Project Specification

## Purpose and authority

**Simple Tun Link (STL)** is a standalone Linux tool and a reusable connectivity
capability. It establishes and manages point-to-point IP connectivity between
servers over a selectable tunnel transport, giving applications and external
software a usable **Link Address** at each end without making the consuming
software implement a tunnel backend.

This document defines **why STL exists, what outcomes it must deliver, and the
durable product and engineering principles**. It is not a changelog, milestone
tracker, implementation report, UI layout specification, or release checklist.
Its principles guide future development; they are not tied to a particular
GitHub Issue, commit, candidate, or published version.

- Product/repository: `simple-tun-link` / `ach1992/simple-tun-link`
- Canonical executable: `stl` (optional installer alias `stlink` is the same
  program, not a second contract)
- Platform: Linux, initially Debian/Ubuntu-class servers; actual version,
  architecture, and capability support is defined in
  [SUPPORTED-ENVIRONMENTS.md](SUPPORTED-ENVIRONMENTS.md)
- License: MIT ([LICENSE](../LICENSE))

## The problem to solve

Two servers may need a directly usable private IP connection, while different
hosts, networks, and providers permit different encapsulations or transports.
Separate scripts for each tunnel type repeatedly implement—and differently
handle—addressing, pairing, resource ownership, diagnostics, persistence,
failure recovery, and automation.

STL provides **one consistent Link lifecycle with interchangeable backend
implementations**. The operator chooses a suitable transport; the consuming
application uses the Link Addresses instead of depending on how the link was
created.

## Intended product outcome

An operator or authorized external consumer can configure two reachable
underlay endpoints, select an available tunnel method, and obtain an
independent, usable Layer-3 point-to-point Link with a private Link Address on
each server. The product must distinguish a locally saved/created Link from
**observed bilateral connectivity**; one is not proof of the other.

STL is useful both directly through an understandable human interface and as
an infrastructure capability invoked by unrelated software. External
consumers may have different business logic and topology; STL manages Links,
not those products' workflows or policies.

A host may manage **zero to many independent Links**, including several Links
between the same pair of underlay endpoints using distinct backend identities
where supported. Links have stable IDs, separately owned resources and
lifecycles, and independently observed state. One Link's failure, repair or
removal must not disrupt unrelated Links.

A successfully committed working Link must survive ordinary service restart
and host reboot through recovery of the **same intended identity and
connectivity**, without requiring fresh manual pairing. An incomplete
pre-commit attempt is not a working Link and may instead require a fresh
operator-initiated attempt; safety and credential protection still apply.

## Core capabilities and scope

1. **Transport-neutral Link model.** One identity, desired/observed state,
   address model, lifecycle and diagnostic vocabulary serves all backends.
   The initial backend families are GRE, IPIP, WireGuard and IPsec/XFRM.
   GRE/IPIP support Native and, where technically supported, FOU/GUE;
   GRE Native is the straightforward interactive default.
2. **Practical two-endpoint configuration.** Provide guided creation,
   manually specified endpoints/Link Addresses, and explicit, versioned
   peer setup import/export. Start with IPv4 point-to-point addresses,
   including automatic suggestions and human-manual assignment, without
   designing the core model to prohibit future address families.
3. **Reliable lifecycle.** Plan, verify, apply, persist, inspect, repair,
   remove and restore only correctly identified STL-owned resources;
   distinguish successful completion, partial effects and uncertainty.
   Repeated desired-state operations should converge idempotently.
4. **Independent multi-Link operation.** Allow independent Links and backend
   combinations without an arbitrary product-imposed count or
   one-Link-per-peer assumption; resolve genuine kernel, address, service,
   port and resource collisions safely.
5. **Useful observation.** Report prerequisites, ownership, interface state,
   endpoint reachability, link quality and MTU information with the evidence
   actually available. Separate read-only diagnosis from intentional repair;
   optional traffic-generating tests require explicit invocation.
6. **Human and machine usability.** Offer a clear, low-friction terminal
   experience and stable non-interactive, machine-readable interfaces with
   equivalent core lifecycle capability, understandable failures and safe
   credentials handling.

## Durable architecture and development principles

- **API-first, not API-server-first.** The canonical backend-neutral Engine
  must be usable independently of terminal screens. Versioned CLI/JSON and
  idempotent desired-state operations are first-class integration contracts.
  Additional APIs or language bindings may be introduced when a real
  consumer justifies them, without making an HTTP daemon, database or a
  particular external platform a prerequisite for using STL.
- **One shared engine, replaceable adapters.** Authentication, provisioning,
  backend-specific kernel/service behavior and observation belong in small
  backend/platform adapters; common state, ownership, locking, lifecycle,
  errors and diagnostics must not be reimplemented per backend or frontend.
  New transport options should require proportionate extension, not
  duplication of the control plane.
- **Native efficient data path.** Use Go for control, not as a compulsory
  packet forwarding hop for native Linux backends. Prefer Linux and backend
  datapaths and avoid permanent background services, central storage,
  redundant abstractions and costly polling without demonstrated value.
- **Compatibility by explicit contracts.** Stable Link identity, versioned
  setup links, desired-state and machine schemas, deterministic error
  semantics and deliberate migration rules let standalone and external
  consumers evolve without parsing human text or assuming internal Go
  structures are public APIs.
- **Capability-based portability.** Detect relevant host/kernel/backend
  prerequisites. One unavailable or conflicting optional backend should
  not disable unrelated transports. Maintain practical supported-platform
  adapters rather than proliferating separate implementations.
- **Simple by default, powerful when chosen.** Make the common path easy,
  keep advanced transport/host settings discoverable, and avoid either
  hiding real capabilities or forcing expert configuration on beginners.
- **Evidence over claims.** An installed binary, successful command,
  configured interface, successful handshake, and verified peer packets
  establish different facts. Error messages, health reports and product
  documentation must preserve those distinctions.

## Operator autonomy and safety boundaries

**STL is an enabling tool, not a gatekeeper for the operator's legitimate
network design.** It must not impose arbitrary commercial, policy-driven or
convenience limits on Link count, chosen transport, sustained tunnel
bandwidth, consumer type or topology. Operators decide which supported
method to use and may knowingly choose an unencrypted transport; STL must
describe that choice accurately, not silently substitute a different one.

This freedom does **not** override technical correctness, ownership,
explicit authorization or confidentiality. Actual kernel/transport
constraints, resource collisions and finite host capabilities are legitimate
constraints, not artificial quotas. Bounded diagnostics, input validation,
concurrency coordination and explicit consent for consequential host changes
protect correctness; they must not become hidden throughput or Link-count
limits.

STL must never infer permission to overwrite, adopt, stop or delete unrelated
interfaces, services, credentials, routes or other host resources. Preview
material host effects and request specific approval when needed. Protect
secret-bearing pairing material separately from ordinary state and
observability; never assume that encoding a Setup Link encrypts it.
Plaintext GRE/IPIP are not authenticated or encrypted merely by their
encapsulation or GRE key. No backend is promised to be undetectable or
universally reachable across every provider/firewall/NAT.

Keep normal point-to-point setup scoped: no blanket firewall flush, default
route replacement, globally enabled forwarding, or unrelated system-wide
tuning. Unknown ownership and incomplete effects require honest,
actionable reconciliation rather than a falsely successful result or blind
retry.

## Product boundaries and non-goals

STL's responsibility is to **supply and manage reusable IP Links**, not to
become a general-purpose firewall/router administrator, Internet proxy,
central mesh controller, deployment platform, or host optimization suite.
Those may be built by separate consumers using the STL contracts; their
existence is not a reason to add consumer-specific roles or hidden coupling
to STL's core.

Not every possible transport, IPv6 mode, Layer-2 overlay, routed subnet,
automatic failover or network topology is an immediate deliverable.
They are potential extensions subject to real value, feasibility,
compatibility and proportionate maintenance cost—not permanent
prohibitions created by this document. Do not promise a feature solely
because the architecture leaves room for it.

## Success and completion criteria

The product meets its accepted scope when evidence shows that:

- A supported host can install, configure, inspect and maintain Links with
  predictable human and non-interactive workflows.
- Two correctly configured and mutually reachable endpoints exchange
  real traffic over their private Link Addresses for the supported
  backend/capability combinations; saved configuration alone does not pass.
- Independent Links, including multiple Links to one peer where technically
  distinguishable, coexist and remain isolated during create/update,
  diagnostics, removal and failure.
- Committed Link intent and credentials recover reliably after ordinary
  reboot/restart, without losing the identity or modifying unrelated
  network state; partial/uncertain operations have safe recovery behavior.
- Backend-independent, versioned machine contracts support external
  consumers without screen scraping, while the human experience remains
  practical for direct use.
- Prerequisite and diagnostic outcomes, resource ownership, secret
  handling, and allowed host effects are truthful and verifiable.
- The design supports adding an appropriate backend or consumer with
  bounded change to shared code, without duplicating the Link lifecycle
  or introducing unnecessary runtime overhead.

Acceptance evidence for a **particular release, host, environment or field
deployment** is maintained in code/tests, CI, releases and the controlling
GitHub work items; it must not be misrepresented as universal proof here.

## Where other authoritative details live

- [Architecture](ARCHITECTURE.md): implementation boundaries, Engine,
  backend contracts, ownership and runtime mechanics.
- [CLI and machine contracts](CLI.md) and [Pairing](PAIRING.md): exact
  command, schema and exchange behavior.
- [Security](SECURITY.md), [Diagnostics](DIAGNOSTICS.md) and
  [Operator recovery](OPERATOR-RECOVERY.md): enforceable operating rules.
- [Install](INSTALL.md), [Supported environments](SUPPORTED-ENVIRONMENTS.md)
  and [Release artifacts](RELEASE-ARTIFACTS.md): deployment, compatibility
  and distribution procedures.
- [Development](DEVELOPMENT.md) and [the IPsec runtime decision](decisions/ADR-0005-scoped-vici-ipsec.md):
  contributor rules and lasting decision rationale.
- GitHub Issues/PRs/checks/releases: outstanding work, implementation
  history, verification status and published artifact identity.
