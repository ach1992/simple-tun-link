# Project Specification

## 1. Project identity

- Repository: ach1992/simple-tun-link
- Product name: simple-tun-link
- Canonical CLI: stl
- Convenience alias: stlink, implemented as an alias/symlink to the same STL executable where the supported installer can provide it; it is not a second binary or separate interface contract.
- Primary platform: Linux
- Initial distribution target: Debian/Ubuntu-class Linux servers; detailed baseline and capability rules live in docs/SUPPORTED-ENVIRONMENTS.md

This document is the canonical project-level specification. Detailed architecture belongs in docs/ARCHITECTURE.md; live work belongs in GitHub Issues.

## 2. Problem

Operators often need a simple private point-to-point IP between two Linux servers. Native GRE may work on one route/provider and fail on another. Existing single-method scripts duplicate setup, persistence, firewall, health, MTU, pairing, and diagnostics logic while exposing different failure behavior.

The project should provide one small tool that creates the same consumer-facing L3 link while allowing the underlying tunnel backend to vary.

## 3. Desired outcome

Given two Linux servers with mutually reachable underlay endpoints, an operator can install stl, create/import a link with minimal input, and obtain a stable point-to-point Link Address on both servers.

A successfully activated and durably committed Link must remain usable by normal IP applications and external software, and restore its working Link traffic automatically after ordinary host reboot/service restart without repeating setup or pairing.

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

A non-interactive CLI and machine-readable JSON output must expose the same core operations for automation and arbitrary external consumers.

## 5. v0.1 backend scope

### GRE — default
- Native GRE is the default backend and default encapsulation.
- Keyed GRE is supported; keys are identifiers, not security.
- FOU and GUE UDP encapsulation are supported as advanced alternatives.
- MTU supports explicit managed Auto and Manual modes, while absence of a policy preserves legacy/unmanaged Links without changing their kernel MTU.
- TTL/TOS/PMTUD and other backend-relevant knobs may be exposed under Advanced only when they materially affect real routes.

### IPIP
- Native IPIP.
- FOU and GUE UDP encapsulation.
- Same common Link lifecycle and diagnostics model as GRE.

### WireGuard
- Native WireGuard transport.
- Secure/authenticated link.
- Private keys are secrets and must never appear in logs, status, diagnostics, or generic JSON.
- v0.1 uses **Quick Link** as the default one-step pairing mode: the initiator may generate the receiver keypair, include the receiver private key only in the explicitly sensitive setup payload, retain only the receiver public key, and never persist the receiver private key in ordinary initiator state.
- The pairing schema must allow a future local-key/secure-exchange mode without changing the core Link model.

### IPsec/XFRM
- strongSwan/IKEv2 with Linux XFRM interfaces, not the legacy VTI-first design.
- Native ESP and NAT-T/ESP-in-UDP behavior.
- Credential material is secret and follows setup-link security rules.
- v0.1 operational target: one STL-owned native-exclusive strongSwan runtime per eligible host, with standard IKE UDP 500/4500, not one daemon per Link. Preserve one shared IPsec engine and use small capability-driven packaging/service adapters across Linux distributions.
- Existing or ambiguously owned strongSwan services, management, ports, credentials or kernel resources block only IPsec activation; never stop or adopt a foreign daemon. GRE/IPIP/WireGuard remain independently usable. An isolated multi-daemon alternative is future work, not a prerequisite for v0.1.

## 6. Link addressing

- v0.1 uses IPv4 point-to-point Link Addresses.
- Default allocation target is an unused RFC1918 /31 pair.
- Automatic allocation must check local routing/address state and, when peer information is available, avoid collisions on both endpoints and across every existing STL Link on the host.
- **Human manual addressing:** the operator can specify both private IPv4 endpoints directly; a valid adjacent /31 pair stays supported, and two ordinary usable hosts in one /30 (such as 10.235.1.1 and 10.235.1.2) must also be accepted without weakening subnet/collision/peer checks. Do not ask beginners for canonical network-prefix or first/second host technicalities; advanced setup may still show the chosen CIDR.
- Manual Link Address configuration remains available.
- The internal model should not make future IPv6 support unnecessarily difficult.

## 7. Setup methods

Required:
- interactive create;
- manual configuration;
- versioned setup-link import/export;
- human-readable copy block;
- preview before apply;
- **Quick Link** as the v0.1 default for secret-bearing backends when a one-step payload materially simplifies setup.

A secret-bearing Quick Link is explicitly **SENSITIVE** credential
material: receiver private key/PSK never appears in ordinary State,
status/diagnostic JSON, logs, or generic inventory. The approved
Issue #91 guided sender **intentionally** retains a separate
owner-private, immutable per-Link receiver Setup Link until explicit
operator deletion, so it is not silently recorded in ordinary State.
Later retrieval from Manage/Share needs a fresh interactive SHOW and
verification of the unchanged sender Link identity; deleting it needs a
separate DELETE.
Import preview reports credential presence without disclosing it.

The pairing schema includes an explicit exchange mode so a future Secure Exchange/local-key flow can be added compatibly if later justified.

An interrupted *pre-success* setup may be discarded and begun afresh with a new Link ID; v0.1 does not need to reconstruct a lost sensitive Quick Link or add an orphan-credential deletion/recovery product workflow. Ordinary cancellation attempts owned rollback, but an abrupt crash cannot guarantee atomic erasure of external effects. Existing protected internal safety journals, fail-closed ownership and basic credential secrecy remain in force. Never treat unfinished setup as a successfully committed tunnel.

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
- At installation, setup, status, diagnostics, lifecycle and restore failures, show the operator a clear *why*, stable machine reason identifier, actionable next step and whether the observation is incomplete. Machine-readable JSON must not require prose parsing, and no diagnostic may silently repair.
- Prefer structured, bounded, redacted events tied to operation/Link/backend and stable reason code; normal users see concise output, while opt-in safe troubleshooting provides more context without exposing credentials or untrusted daemon/kernel output. Never turn on unsafe strongSwan credential-debug logging for diagnosis.

Health observation and repair are separate operations. A health check must not silently mutate the system.

MTU is persisted per Link and **endpoint-local**: absent policy on an old saved Link means legacy/unmanaged; explicit v2 `unmanaged` opts out of management; explicit `auto` is Engine-managed conservative MTU based on local underlay/backend overhead; explicit `manual(bytes)` is validated Engine-managed MTU. Older v1 input without an MTU field cannot silently erase an existing managed policy. New guided creation chooses Auto. Canonical lifecycle Apply/Verify/Undo, update and restore own mutations; read-only diagnostic probes never set MTU. Pairing must not copy the sender's local MTU or path measurement to the receiver.

## 9. System-change principles

- Do not enable global ip_forward merely to create host-to-host Link Addresses.
- Do not globally disable rp_filter by default.
- Any required sysctl change must be scoped as narrowly as possible, owned by the tool, and safely restorable.
- Firewall rules must be minimal, peer/protocol/port scoped where possible, and removable without flushing or rewriting unrelated policy.
- Do not change the host's primary network manager merely to create a link.
- Existing interfaces/configuration are never overwritten without identity validation.
- Apply operations are idempotent.
- Partial failures must undo only verified STL-owned effects. Distro package-manager changes may persist and must be reported honestly, not described as an atomic Link/binary rollback.
- Creating, updating, repairing, or removing one Link must not mutate or disrupt another Link.
- Concurrent Link operations must coordinate collision-sensitive resource allocation so two operations cannot claim the same interface identity, Link Address, backend key/identifier, UDP/listen port, XFRM identity, route/firewall ownership, or persistence identity.

## 10. Architecture and performance constraints

- Go is the control-plane implementation language.
- Packet data should remain in Linux/native backend data paths; stl must not proxy packets for native backends.
- Core domain/backend logic must not depend on the interactive menu.
- CLI JSON output is a first-class contract for automation; every machine-readable payload carries an explicit schema version and breaking schema changes require a version bump.
- The automation surface provides idempotent desired-state semantics (for example, `stl link ensure ... --json`) so callers do not need to reproduce create/update/repair decision logic.
- The engine treats Links as a collection keyed by stable Link ID; it must not assume one active Link, one Link per peer, or one Link per backend.
- No **STL management daemon**, central database, remote orchestration service, or consumer-specific integration layer is required in v0.1. The optional IPsec backend uses its native strongSwan service only after explicit, verified STL-exclusive ownership; this is not a new generic STL control daemon.
- Boundaries must allow arbitrary external software to reuse STL through stable machine contracts without reimplementing tunnel logic or forcing STL to model consumer-specific concepts.
- Avoid premature public-library APIs; promote a stable reusable API only when a second real consumer proves the requirement.

## 11. Standalone use and reusable integration

STL is a complete standalone tool and also a reusable connectivity capability.

~~~text
Human operator ----------> interactive STL
External software -------> versioned CLI / JSON contract
                               |
                           STL engine
                               |
                         stable Link Address
~~~

STL intentionally defines only its own contracts and lifecycle. It does not define the architecture, inventory, roles, workflow, ownership model, or product behavior of software that may consume it. Consumers may take any form. STL defines only the stable contracts needed to use Link functionality and does not prescribe consumer architecture.

The reusable boundary is kept generic through stable Link IDs, desired/observed state, idempotent ensure/apply behavior, versioned state and JSON schemas, deterministic errors/exit semantics, multi-Link isolation, and UI-independent engine logic. A public in-process Go API is not frozen until a real second in-process consumer proves that need.

Potential future STL capabilities, explicitly not promised by v0.1:
- additional standardized userspace carriers such as MASQUE/CONNECT-IP;
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
- already committed, working Links survive host reboot/service restart with restored traffic and no new pairing; interrupted pre-commit creation can instead be restarted from scratch;
- restart/reapply persistence works without corrupting unrelated network state;
- machine-readable CLI output exists for core operations with an explicit schema version and stable error/exit semantics;
- a script can converge a Link toward desired state through an idempotent automation operation without parsing interactive output;
- one host can operate multiple simultaneous Links to multiple peers and multiple independent Links to the same peer pair; the v0.1 E2E suite includes A <-> B with GRE Native, WireGuard, and GRE/FOU active together, each with independent Link Addresses;
- removing or repairing one Link in a multi-Link scenario leaves the other Links operational and their traffic unaffected;
- automated tests cover domain/config logic and Linux namespace/integration paths where technically feasible;
- documentation is sufficient for another maintainer to continue work without chat history.

## 14. Owner decisions

The project license is **MIT**. The canonical CLI remains `stl`; `stlink` is a low-cost convenience alias to the same executable when installed through the supported installer.

For v0.1, **Quick Link** is the default one-step pairing mode for secret-bearing backends. The format remains explicitly extensible so a future Secure Exchange/local-key mode can be added without changing the core Link model. Current development targets are tracked by the relevant GitHub Issues.

For IPsec v0.1, the Owner accepts a single native-exclusive STL-owned strongSwan runtime on eligible hosts and an explicit fail-closed IPsec-only unavailability on any host with foreign/ambiguous daemon ownership. Future coexistence/isolation modes require independent validation and review. The Owner also requires actionable, redacted operator diagnostics and coherent safe logging across **every** backend and CLI/menu workflow; this is a product-wide acceptance criterion, not an IPsec-specific embellishment.

2026-10-14 Owner acceptance: pre-success setup is disposable, but a fully committed working tunnel MUST be restored after reboot; basic protection against lost/unknown secrets or foreign resource deletion is not waived. The persisted MTU contract is `unset=legacy/unmanaged`, `auto`, or `manual(bytes)`, applied only under canonical local Engine ownership and never copied across pairing. Real physical WAN/NAT-router experiments are Owner-run **after** publication; do not claim them pre-tested or bypass platform restrictions. Installed released-artifact identity and successful committed-Link restart/traffic remain pre-publication acceptance. Stable publication/tag still needs separate Owner authorization.


## 15. Guided operator workflow and one-consent preparation

**Normative development target after immutable v0.1.0-rc.6.** This section
defines the future product contract; the rc.6 README/INSTALL/CLI still
describe what the released binary actually does. Active implementation:
[Issue #105](https://github.com/ach1992/simple-tun-link/issues/105)
(automatic IPsec setup), [Issue #106](https://github.com/ach1992/simple-tun-link/issues/106)
(all-screen operator UX). Physical-host WAN/NAT/systemd-249 acceptance
remains [Issue #93](https://github.com/ach1992/simple-tun-link/issues/93).

### The short path to a working Link Address

1. Show a concise project/version/host/source-IP and saved-Link summary.
   A saved Link is **not** proof of an active or reachable peer.
2. One Create entry defaults to GRE Native; WireGuard/IPIP are common
   choices, FOU/GUE/IPsec are accessible in Advanced. Select the OTHER
   server's reachable underlay IP. Suggest THIS server's own underlay
   source IP from the route, with bounded appropriate override.
3. Suggest an unused private IPv4 Link Address pair (`/31` by default),
   with direct human manual `/31` and usable `/30` pairing still supported.
   Show public/underlay IPs separately from the private tunnel/Link IPs.
4. Read-only check only the chosen backend's missing prerequisites.
   If needed, show one clear package/module/STL-private-service plan,
   affected resources, effects that may persist, and **one fresh PREPARE**
   confirmation covering the *entire selected preparation*. Automatically
   perform qualified work via the canonical installer, existing module
   adapters and existing exclusive IPsec provisioner. Reinspect readiness
   and continue the **same selected tunnel**. Already-ready backends
   must not show another preparation prompt.
5. Preview both endpoints, private IPs, encapsulation/port, local MTU
   policy, and scope. Creating or importing the actual Link needs its
   own affirmative YES. A failed or cancelled step must not claim success.
6. On a successful local Create, present **saved/created locally** as
   distinct from **verified peer connectivity**, and show the second
   server's correct copyable setup. GRE/IPIP Native can pair manually,
   with consistent GRE keys (including zero/unkeyed), and UDP FOU/GUE
   need matching selected ports. Guided WG/IPsec Create may immediately
   display the exact original *sensitive* receiver Setup Link only in
   a real private terminal under the existing Create consent. A later
   SHOW requires fresh consent, and DELETE permanently removes only
   the identity-verified retained receiver offer; it does not remove
   the active Link or recreate keys.
7. Other server: protected/plain setup import and exact peer-oriented
   preview, independent Create/Import approval and normal Engine checks.
   Claim an actual working connection only from observed peer handshake,
   packet/traffic or verified connectivity; five-ping/loss/RTT are
   measurements, while local MTU Auto is an **unmeasured local policy**
   until a peer/path probe is performed. Committed working Links must
   survive reboot without re-pairing.

### One consistent readable terminal language

- Task-first heading, compact aligned facts, optional concise rows,
  visible current selection, **one main next action**, and optional
  Details/Why for technical diagnostics. Keep author-written sentences
  short and avoid repeated warnings and paragraph dumps.
- Semantic tokens on a capable interactive terminal: **RED BOLD**
  REMOVE/DELETE and destructive failure; **YELLOW BOLD**
  PREPARE/INSTALL/UPDATE and cautions; **GREEN BOLD** verified success
  and ordinary YES; BLUE/CYAN for SHOW, navigation and informative
  data; secondary text dim. Color supplements explicit words and
  never substitutes for them.
- Responsive, visibly aligned output at ~60, 80 and 120 columns.
  Wrap human prose only. Never alter, split, truncate, decorate or
  log exact `stl://` handoffs, URLs, commands, opaque IDs, public keys,
  hashes or secret-bearing values. Never leak a private receiver
  handoff into normal logs/Status/Doctor/JSON. Respect `NO_COLOR`,
  `TERM=dumb`, small terminals and redirected streams; no unexpected
  ANSI/control characters or terminal-scrollback erasure.
- A failure view distinguishes **missing/recoverable**, **unknown**,
  **confirmed foreign conflict**, **failed before mutation** and
  **partially/uncertainly mutated**. Show the known scope, safe reason,
  current outcome and one actionable next step, not raw OS/daemon text.
  An inconclusive observation alone cannot prove a permanent blocker;
  uncertain mutable effects are not blindly retried.
- UI renderers do not change canonical Engine, versioned JSON,
  reason-code/exit contracts, stdout/stderr semantics or secret
  handling; reuse the existing shared terminal presentation instead
  of adding a second framework.

### Prepared automatically, without unsafe ownership changes

- The goal is an actual usable locally addressed tunnel, not a
  prerequisite checklist. A known manageable warning can be accepted
  for a **scoped, qualified** action. Status/Doctor/menu navigation and
  cancellation remain read-only; no silent root/network mutations.
- For missing strongSwan packages, STL—not the user—must handle the
  supported trusted distro APT dependencies after PREPARE consent,
  accounting for package hooks that can **enable AND start** a newly
  installed vendor service on a verified clean host. The Owner accepts
  this possible temporary activation, which must be disclosed in the
  PREPARE preview. Only the selected signed packages and disclosed
  required dependencies may be installed/updated: no unrelated removals,
  unrelated upgrades or hidden persistent service effects. Before installation STL must record that no
  foreign service, config, IKE port owner or daemon would be displaced.
  Only a vendor service positively attributed to this exact approved
  package transaction may then be stopped and disabled; verify that
  the vendor unit is inactive and has no enabled boot edge before
  the existing STL-private daemon is provisioned. No existing or
  ambiguous foreign service may be stopped, disabled or adopted.
  Avoid a separate global APT hook-interception framework. If a host
  cannot meet these conditions, give the specific reason and a safe
  operator-approved alternative.
- Package installation does not prove private IPsec readiness.
  Reuse the already-implemented receipt-bound STL-exclusive
  strongSwan service provisioner; independently verify loaded unit,
  secure logger, process/config/VICI/socket and IKE port ownership.
  A harmless absent/not-provisioned unit must be distinguished
  from a confirmed conflicting one. User PREPARE consent cannot
  convert unowned host resources into STL-owned resources.
- A partially executed APT operation may persist packages or leave
  dpkg in a state needing verified follow-up; do not promise atomic
  package rollback with the STL binary or Link. Show outcome and
  safe recovery explicitly, preferably inside STL itself.

The shipped immutable rc.6 still **does not** automate missing IPsec
package installation. Code changes for this contract require
real disposable-systemd/Ubuntu/Debian evidence, independent review
and separate integration/release gates; do not claim this behavior
in a published README until it exists. The development branch for
Issue #105 contains a guarded candidate and disposable Ubuntu/systemd
test coverage; these are not proof that a published release or physical
WAN/NAT acceptance (#93) already exists.
