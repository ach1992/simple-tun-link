# Architecture

## 1. Core model

simple-tun-link owns a **Link**. It does not own or prescribe the architecture of software that consumes that Link.

~~~text
External consumer
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

### Integration surfaces

The same engine serves human and machine consumers without making any external product an architectural owner:

~~~text
Interactive CLI      Machine CLI/JSON
      \                  /
             Application engine
                    |
                  Link
~~~

- Interactive output is for humans and is never an automation contract.
- Non-interactive commands expose deterministic exit semantics and versioned JSON; callers must never scrape menu text.
- Idempotent `ensure` semantics allow any external consumer to declare desired Link state while STL performs inspect/plan/apply/verify.
- Engine packages remain private under `internal/` until a real second in-process consumer proves a stable public Go API is needed.
- Consumer-specific product concepts stay outside STL.

## 2. Layer boundaries

### Presentation
Interactive terminal menu, direct CLI commands, and versioned JSON output.

Responsibilities:
- collect/validate user intent;
- show plans, warnings, status, and results;
- never own tunnel semantics.

### Application engine
Coordinates lifecycle operations.

Target lifecycle:

~~~text
Ensure(desired state)
        |
Inspect -> Plan -> Validate -> Apply -> Verify -> Commit
                                  |
                                failure
                                  v
                         rollback owned delta
~~~

`Ensure` is the external idempotent desired-state operation; it does not bypass the underlying lifecycle.

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
- versioned state schema; current schema v2 adds backend-specific GRE options; compatible v1 state is migrated in memory, while legacy GRE FOU/GUE/options that lacked sufficient identity are rejected for explicit regeneration rather than guessed;
- Links are a collection, not a singleton;
- zero or more Links may exist on a host, including multiple independent Links to the same peer underlay endpoint pair;
- one stable Link ID independent of interface display name and peer address;
- atomic write/replace;
- restrictive permissions for secret-bearing state;
- no central database in v0.1;
- observed kernel state is inspected, not blindly assumed from stored config.

The installed Linux CLI uses /var/lib/simple-tun-link as its canonical
private state root (state.json plus locks). The minimal non-interactive
command stl link restore --all loads this state and invokes the same
Engine.RestoreAll / Engine.Ensure lifecycle. Unsupported backends or failed
reapply must exit nonzero; no second restore engine is permitted.

On systemd hosts, the normal Engine Ensure activates one STL-owned restore
unit before committing desired state, and Remove disables/removes the unit
after committing the last desired Link deletion. The host persistence
transition and desired-state commit share a narrowly scoped lock. An empty
restore reconciles an orphaned STL-owned unit after interruption or cleanup
failure. This does not replace or require systemd-networkd, NetworkManager,
Netplan, or another host network manager. Hosts without systemd may use
the ordinary engine in manual/non-persistent mode.

The owned restore unit has a 35-minute oneshot startup ceiling; the CLI
uses a 30-minute signal-aware (SIGINT/SIGTERM) context to bound Link
restoration and reserve time for bounded owned rollback. Persistence
installation is restricted to a canonical root-owned executable and a
non-writable, symlink-free directory chain. The privileged restore unit itself
must also be a root-owned regular file with no unprivileged-writable file or
parent-directory components; an STL ownership marker alone is insufficient.
Runtime-only systemd enablement, alias/linked/masked states, and ambiguous
identities fail closed rather than pretending reboot activation is durable. Negative
systemd enablement observations require both the expected process exit
status and matching stdout; a partial stdout from a timed-out command
is not authoritative. A completed final-Link unit removal must verify
the absence of both the owned file and enabled systemd identity.

Every backend rollback of an already-applied change runs with a
cancellation-detached, bounded cleanup context, including non-systemd
operations. All systemd post-publication compensation paths (durability,
daemon-reload, enable failure, and later Engine rollback) revalidate
**both the exact unit bytes and the original inode identity created by STL**.
A valid marker or byte-identical unit installed by another administrator
never grants ownership to disable, replace, delete, or re-enable it.
An operation's originating inode identity is retained through publication,
enablement, bounded compensation, and Undo. Both newly created staging and
previously installed canonical units keep their original opened descriptors
alive while their inode metadata authorizes any transition, including the
OLD side of exchange, removal and recovery after systemctl calls. Creation
failure cleanup and retirement-placeholder unlink also keep their originating
descriptors open through their final ownership-sensitive checks. This prevents
inode-number reuse (filesystem ABA) from making a new byte-identical file
pass an os.SameFile(dev,inode) check after the former object was unlinked.
Short-lived identities are explicitly closed at the transaction boundary;
the published identity is held by a returned Undo closure until it becomes
unreachable, when the os.File finalizer can close its descriptor.
A stale Undo whose original published inode has been replaced must fail
with an explicit conflict. This in-process protection is not a persistent
identity token across a process restart.

Initial installation and absent-unit deletion compensation share the same
no-clobber hard-link publication helper. The temporary source inode is
captured through its original opened descriptor, not a later Lstat.
The actual source and canonical identities/content are verified before and
after linking, and before a systemctl daemon-reload. Publication which may
have happened without a provable STL-created inode is **post-publication
uncertainty**, not an unchanged transaction; it must not be blindly
compensated. A potentially independent temporary source is retained with
an inspectable recovery location rather than unlinked, including when it
has the expected bytes on a different inode or was edited in place.

Existing-unit updates atomically exchange the incoming and existing unit
with Linux renameat2(RENAME_EXCHANGE). Before the exchange, the current
canonical inode and content are revalidated against the original operation
identity. After the exchange, both the displaced original inode/content
and the new canonical inode/content must be verified. A reversal may move
a canonical file only when that file remains the **exact original incoming
STL inode and bytes**, and the displaced staging object still matches the
file observed just before exchange. Proof that the old STL inode remains
recoverable is never permission to relocate an independently installed
canonical unit. On insufficient proof, preserve the current canonical
identity, retain available private recovery material and fail explicitly;
no daemon-reload/enable is performed on an unverified outcome.

Unit removal uses renameat2(RENAME_NOREPLACE) to a private recovery path,
validates the moved inode before retirement, and verifies expected ownership
before disabling the unit. Missing-unit compensation uses exclusive
no-overwrite publication and verifies the restored inode before re-enabling.
Filesystems without required atomic rename facilities fail closed; STL does
not fall back to clobbering rename. Before every unit content read, a
non-following, nonblocking file descriptor proves a regular inode; reads
are bounded to 64 KiB. Symlinks, FIFOs, devices, unexpected inodes, changed
contents, and oversized files fail closed. Protected .stl-unit-* and
.stl-retire-* recovery names are retained when an independent identity or
uncertain durability prevents safe cleanup. Manual reconciliation may be
required, and no recovery path should be deleted merely because it shares
an STL-style filename. Unrestricted concurrent root writers cannot be
serialized without their cooperation; all avoidable observed ownership
conflicts abort without overriding their canonical configuration.

The restore unit needs an installed, durable stl executable path. Real
backend adapters register through their own tracked implementation Issues;
this CLI/persistence substrate does not provide a synthetic production
tunnel backend. Future CLI commands in Issue #10 must reuse the same
state root, engine construction, and persistence integration.

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

Multi-Link behavior is a first-class v0.1 requirement, not a capability deferred to some external consumer.

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
- Native is the default; the v0.1 GRE implementation uses IPv4 underlay endpoints.
- Keyed GRE is supported, including an explicit key value of zero; the key is an identifier, not authentication or encryption.
- FOU/GUE are advanced encapsulations. Each Link owns one non-zero symmetric UDP port: the same fixed port is used as the tunnel encapsulation source/destination and as a receive mapping bound to the exact local/peer underlay pair and physical underlay device.
- Interface names are deterministically derived from Link ID and remain within Linux IFNAMSIZ; an `stl:<LinkID>` alias marks ownership. Destructive removal uses the observed kernel ifindex rather than deleting by reusable interface name alone.
- Multi-Link collision identity includes encapsulation, underlay pair, GRE key presence/value and, for FOU/GUE, UDP port. Distinct keys/encapsulations may coexist when the kernel can distinguish them.
- Auto MTU consumes backend overhead instead of hardcoded guesses: IPv4+GRE base overhead plus enabled GRE checksum/key/sequence fields, plus UDP for FOU and UDP+GUE base header for GUE.
- TTL/TOS/checksum/sequence/PMTUD are explicit advanced options and are verified from observed kernel state.
- The backend exposes read-only capability and packet/byte/error counter hooks for common diagnostics; health observation never repairs state.
- Native inbound firewall ownership is exact peer/local/protocol/device. FOU/GUE use exact peer/local/UDP-destination/device rules. Route drift with an older owned rule fails closed for explicit reconciliation instead of silently adding or deleting a different rule.

### IPIP
- Native default within the IPIP backend;
- FOU/GUE advanced encapsulation;
- minimal overhead and simple point-to-point behavior.

### WireGuard
- encrypted/authenticated;
- private keys are secret and excluded from ordinary logs/status/diagnostics/JSON;
- v0.1 Quick Link may carry the receiver private key once in a sensitive pairing payload; the initiator retains only the receiver public key and does not persist the receiver private key in ordinary state;
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
stl://2.<encoded-payload>
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

Pairing payloads carry an explicit exchange mode. v0.1 defines `quick` as the default mode for secret-bearing backends because it preserves the simplest one-step workflow and implementation. Quick payloads that contain a receiver private key or shared PSK are explicitly **SENSITIVE** credential material.

For WireGuard Quick Link, the initiator may generate the receiver keypair solely to construct the payload, persist only the receiver public key, and discard the receiver private key from ordinary local state after export. The receiver stores its imported private key locally with restrictive permissions. For IPsec/PSK, the shared PSK may be carried in the sensitive Quick payload and then stored as required by both endpoints.

The format must permit later addition of a `secure_exchange` (or equivalent local-key) mode without changing the core Link model or invalidating existing Quick Link payloads. Secure Exchange is not a v0.1 requirement.

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

## 14. Reusable integration and extensibility

STL is standalone, but its boundaries intentionally permit reuse by arbitrary external software:

- core behavior is independent from terminal UI;
- direct CLI subcommands expose deterministic operations and explicit exit semantics;
- every machine-readable payload has a schema version;
- Link IDs are stable and multiple Links, including same-peer Links, are first-class;
- desired/observed state are separable and an idempotent ensure operation converges desired state;
- backends expose common lifecycle/status semantics;
- STL does not model external consumer topology, roles, inventory, ownership, or orchestration policy.

External software should initially consume the CLI/JSON contract. If a real second in-process Go consumer appears, selected engine APIs may then be promoted from `internal/` rather than speculatively freezing a public package today.

For native backends, an external consumer must not be required to remain available for established Link data-plane traffic to continue.

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
