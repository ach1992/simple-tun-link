# Architecture

## 1. Core model

simple-tun-link owns a **Link**, not a higher-level backhaul/proxy/service.

~~~text
Consumer
(backhaul / direct tunnel / service)
               |
          Link Address
               |
        simple-tun-link
               |
 Backend + Encapsulation
               |
            Underlay
~~~

Consumers should target the Link Address and remain independent of the selected backend.

## 2. Layer boundaries

### Presentation
Interactive terminal menu, direct CLI commands, and JSON output.

Responsibilities:
- collect/validate user intent;
- show plans, warnings, status, and results;
- never own tunnel semantics.

### Application engine
Coordinates lifecycle operations.

Target lifecycle:

~~~text
Inspect -> Plan -> Validate -> Apply -> Verify -> Commit
                                  |
                                failure
                                  v
                         rollback owned delta
~~~

Responsibilities:
- idempotency;
- ownership of created resources;
- rollback;
- backend selection;
- diagnostics orchestration;
- persistence orchestration.

### Domain
Backend-neutral link identity/config/status types.

The domain distinguishes:
- underlay endpoints;
- Link Addresses;
- backend;
- encapsulation;
- MTU policy;
- local/peer roles;
- dependencies;
- desired vs observed state.

### Backend adapters
Initial adapters:
- GRE;
- IPIP;
- WireGuard;
- IPsec/XFRM.

GRE/IPIP expose Native/FOU/GUE encapsulations through backend-specific configuration rather than pretending each combination is an unrelated product.

### Linux integration
Owns safe interaction with:
- ip / route/link/tunnel state;
- wg;
- swanctl / strongSwan;
- systemctl;
- sysctl;
- active firewall mechanism;
- kernel-module/preflight checks.

Native Linux/kernel tools remain authoritative for actual dataplane state.

## 3. Go package direction

Initial repository shape should grow toward:

~~~text
cmd/stl/                 CLI entrypoint
internal/app/            lifecycle/orchestration
internal/domain/         backend-neutral model
internal/backend/        backend contract
internal/backend/gre/
internal/backend/ipip/
internal/backend/wireguard/
internal/backend/ipsec/
internal/linux/          host integration boundaries
internal/state/          atomic local desired-state store
internal/pairing/        setup-link and copy-block formats
internal/diagnostics/    MTU/link-quality/backend checks
internal/ui/             interactive terminal presentation
internal/version/
~~~

Directories/packages are added only when an implementation slice needs them. Do not create empty framework packages merely to match this diagram.

Keep implementation private under internal/ until a real second consumer demonstrates a stable public Go API requirement.

## 4. Control plane vs data plane

Go owns the control plane. Native backends own packet movement.

For GRE/IPIP/WireGuard/XFRM:

~~~text
Application traffic -> Linux network stack -> native backend -> underlay
~~~

No Go packet copy loop sits in this path.

A future userspace carrier may legitimately introduce a data-plane helper, but it remains a distinct backend/transport with its own performance and security evidence.

## 5. Desired state and local persistence

Persist only what is needed to recreate and manage links.

Direction:
- versioned state schema;
- Links are a collection, not a singleton;
- zero or more Links may exist on a host, including multiple independent Links to the same peer underlay endpoint pair;
- one stable Link ID independent of interface display name and peer address;
- atomic write/replace;
- restrictive permissions for secret-bearing state;
- no central database in v0.1;
- observed kernel state is inspected, not blindly assumed from stored config.

Never store plaintext private keys in generic logs/status/JSON output.

## 6. Resource ownership

Every applied resource must have enough identity to decide whether it is:
- owned by this Link;
- shared/host state;
- unrelated external state.

Deletion/rollback may remove only state proven to be owned by the Link/current operation.

No blind:
- interface deletion by name alone;
- firewall flush;
- route table flush;
- global sysctl overwrite;
- config-file overwrite without identity.

### Multi-Link isolation and allocation

Multi-Link behavior is a first-class v0.1 requirement, not a future panel-only capability.

A host may maintain 0..N Links. Multiple Links may connect the same two underlay endpoints at the same time, including different backend/encapsulation choices such as GRE Native, WireGuard, and GRE/FOU. Each Link has its own stable Link ID, Link Address pair, lifecycle, observed state, and owned resources.

No resource identity may be derived solely from peer address or backend name. Planning/validation must account for every collision-sensitive resource relevant to the selected backend, including interface identity, Link Address/subnet, GRE key, FOU/GUE UDP port, WireGuard interface/listen port, XFRM interface/policy identity, routes, firewall entries, state files, and persistence units/configuration.

A backend may reject a requested same-peer combination only when the underlying kernel/backend cannot distinguish it safely; the rejection must be explicit and must not silently replace or reuse another Link.

Concurrent create/update/remove operations must be safe. Per-Link mutation should be isolated, while host-wide coordination is limited to allocation/ownership surfaces where concurrent operations could otherwise claim the same resource. Do not introduce a coarse global lock unless evidence shows it is necessary.

Removing, repairing, or rolling back one Link must verify current resource identity and affect only that Link's owned resources. Shared host prerequisites must remain available while any other Link still depends on them.

## 7. Backend contract principles

Each backend must provide enough behavior for the engine to:
- validate support/config;
- preflight prerequisites;
- inspect existing observed state;
- calculate a change plan;
- apply owned changes;
- verify actual data-plane reachability/state;
- remove owned changes;
- expose backend-specific diagnostics.

The engine owns transaction/idempotency semantics. Backend implementations must not bypass them with hidden global mutations.

## 8. Backend specifics

### GRE
Default backend.
- Native default.
- keyed GRE supported;
- FOU/GUE advanced encapsulation;
- Auto MTU default;
- TTL/TOS/checksum/sequence/PMTUD only exposed where meaningful;
- GRE key is not an authentication secret.

### IPIP
- Native default within the IPIP backend;
- FOU/GUE advanced encapsulation;
- minimal overhead and simple point-to-point behavior.

### WireGuard
- encrypted/authenticated;
- local private-key ownership preferred;
- endpoint/keepalive configuration is conditional, not globally hardcoded;
- status includes latest handshake/counters where available.

### IPsec/XFRM
- strongSwan/IKEv2 + XFRM interface;
- VTI is not the primary design;
- ESP/NAT-T behavior;
- explicit credential handling and XFRM/SA diagnostics.

## 9. Address allocation

Default IPv4 Link pair: RFC1918 /31.

Auto allocation must:
- inspect assigned addresses and routes;
- avoid obvious Docker/Kubernetes/VPN/link collisions;
- inspect peer state when peer data is available;
- permit manual override.

The Link model keeps address-family concepts explicit so later IPv6 does not require redefining the entire object model.

## 10. Endpoint discovery

Do not assume “first IPv4 on the default interface” is the correct tunnel source.

Use route-aware discovery toward the actual peer and validate that the selected local source is usable by the chosen backend. Multi-homing/NAT/floating-IP ambiguity must produce a clear warning or require an explicit override rather than silently selecting a wrong address.

## 11. MTU and diagnostics

Auto MTU is the normal path:
1. determine underlay/interface constraints;
2. account for backend encapsulation overhead;
3. create/apply candidate safely;
4. perform PMTU/DF-style probing when supported;
5. select a stable result with a conservative fallback if probing is inconclusive.

Manual MTU always remains available.

Keep default diagnostics small:
- preflight;
- link ping/reachability;
- MTU;
- short latency/loss/jitter;
- backend state/counters.

Throughput testing is opt-in.

Health is observational. Repair is explicit.

## 12. Setup-link format

Canonical shape is versioned and self-identifying, for example:

~~~text
stl://1.<encoded-payload>
~~~

Requirements:
- bounded decoder/input size;
- schema version;
- integrity/error detection;
- strict validation;
- preview before apply;
- no shell evaluation;
- backend/encapsulation compatibility validation;
- peer-side inversion handled centrally, not reimplemented in every backend.

A human-readable configuration block is an alternate representation of the same internal pairing model.

Secret-bearing one-shot links must be clearly labeled sensitive. WireGuard private keys should remain local by default; secure pairing may therefore require a response exchange or SSH-assisted setup.

## 13. Interactive UI contract

The menu is task-first, not protocol-dump-first.

Top-level direction:

~~~text
SIMPLE TUN LINK
version / repository
host / OS / kernel / source interface+IP / link summary

1) Create Tunnel
2) Import Setup Link
3) Manage Tunnels
4) Tests & Diagnostics
5) Settings
6) Update
7) Uninstall
0) Exit
~~~

Create Tunnel then selects backend. GRE is preselected.

Advanced settings remain progressively disclosed.

Menu startup must not block on external update checks or public-IP services.

## 14. Future panel/agent compatibility

v0.1 does not build a daemon/panel, but it preserves these options:

- core behavior is independent from terminal UI;
- direct CLI subcommands expose deterministic operations;
- JSON output is stable enough for automation;
- Link IDs are stable and multiple Links, including same-peer Links, are first-class;
- desired/observed state are separable;
- backends expose common lifecycle/status semantics.

A future agent can embed/reuse engine packages inside this repository or initially invoke the CLI contract. A public Go library is not created until a real cross-module consumer requires it.

The control plane must never become required for already-established native tunnels to carry data unless a backend intrinsically requires a userspace process.

## 15. Complexity rule

Prefer:
- one domain concept with backend adapters;
- stdlib before dependencies;
- explicit small interfaces where multiple implementations already exist;
- composition over duplicated managers;
- measured performance work.

Avoid:
- speculative abstractions;
- generic plugin frameworks before a third-party backend exists;
- databases/daemons/API servers before a consumer requires them;
- duplicating Linux networking logic in pure Go when a small, validated native-tool boundary is safer.

Architecture may expand only when a concrete accepted capability requires it.
