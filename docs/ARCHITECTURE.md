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

Logical lifecycle (with owner/resource locking and reinspection):

~~~text
Ensure(desired state)
        |
Inspect -> Plan -> Lock -> Reinspect -> Validate -> Apply -> Verify -> Commit
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

## 3. Go package layout

The shared package boundaries are:

~~~text
cmd/stl/                 CLI entrypoint
internal/app/            lifecycle/orchestration
internal/domain/         backend-neutral model
internal/backend/        backend contract
internal/backend/gre/
internal/backend/ipip/
internal/backend/wireguard/
internal/backend/ipsec/
internal/composition/    typed, fail-closed Provider/Carrier path admission
internal/carrier/wss/    restricted WSS command/policy rendering (not activated)
internal/linux/          host integration boundaries
internal/state/          atomic local desired-state store
internal/pairing/        setup-link and copy-block formats
internal/diagnostics/    MTU/link-quality/backend checks
cmd/stl/menu_*.go        interactive terminal presentation
internal/version/
~~~

Do not introduce speculative framework packages simply to mirror a diagram.

Keep implementation private under internal/ until a real second consumer demonstrates a stable public Go API requirement.

## 4. Control plane vs data plane

Go owns the control plane. Native backends own packet movement.

For GRE/IPIP/WireGuard/XFRM:

~~~text
Application traffic -> Linux network stack -> native backend -> underlay
~~~

No Go packet copy loop sits in this path.

A future Carrier may require a userspace data-plane helper, but this does
not require a second Link Engine or a new L3 packet engine. Its compatibility
with an existing backend and its host safety/performance cost must be
justified before implementing an adapter (see section 14).

## 5. Desired state, locks and reboot restoration

Canonical private state is `/var/lib/simple-tun-link/state.json`;
protected credentials, receiver handoffs, operation journals and
resource/maintenance locks live in separately controlled private
paths. State records **committed desired Links**, not assertions
about live kernel state. Each Link has a stable ID; multiple Links
share the same store without becoming a singleton.

State schema **v3** adds endpoint-local managed MTU. Valid legacy
v1/v2 State is loaded without changing previously unmanaged
interfaces; a pre-v3 document with an unexpected `mtu` field is
rejected rather than granted kernel-write authority. Unknown newer
versions or contradictory identities fail closed. A new executable
may persist v3 after a successful mutation; binary rollback to an
old reader is **not** a State downgrade. See
[INSTALL.md](INSTALL.md#persisted-state-v3-upgrade-and-safe-rollback-boundary).

For an owned Link, the Engine takes maintenance/Link/resource locks,
re-inspects state and host resources under those locks, then validates,
applies, verifies and commits atomically where the underlying
interfaces permit. Compensation is bounded and independent of
cancellation, and touches only verified owned changes. Partial
effects, crash-staged credentials or uncertain host publication
remain explicit recovery material; they are never conflated with a
successfully committed Link.

The installed systemd restore unit runs `stl link restore --all`
through **the same Engine**, reapplying the exact existing Link ID,
credentials and local MTU after reboot. The Engine owns enabling
the restore unit before its first committed Link and retiring the
unit after confirmed final-Link removal. The installer does not
manage Link/network/systemd resources as a second lifecycle.
Hosts without systemd may use nonpersistent/manual operation.

### Restore-unit publication trust

Only the canonical trusted root-owned `stl` binary and exact
STL-owned restore-unit identity can authorize persistence changes.
The unit's content, original inode and protected parent directory
chain are revalidated before enablement, disabling, replacement,
rollback and cleanup. A byte-identical unit, shared name, symlink,
unexpected mask/alias/drop-in or user-writable path **does not**
prove STL ownership.

Unit creation must not overwrite an existing inode; replacement and
retirement require supported atomic no-clobber/exchange operations,
sync/identity verification and ownership-bound undo. Retain an
original opened file descriptor during ownership-sensitive
transactions to prevent inode-reuse (ABA) from authorizing cleanup
of a newly substituted file. Uncertain publication, fsync failure,
replacement identity or retained protected `.stl-unit-*` /
`.stl-retire-*` material require explicit reconciliation, not
wildcard deletion or automatic adoption.

Systemd observations distinguish absent, loaded, masked, foreign
and unknown identities, using bounded output/exit-status checks.
On supported systemd 249, a missing restore unit may return
`is-enabled` exit 1 with **empty stdout**; classify absence
only after independent read-only confirmation of
`LoadState=not-found`, empty `UnitFileState` and empty
`FragmentPath`. An interrupted or partial read is not vacancy.
A successful unit commit is not proof that the remote peer replies.

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
- verify owned local data-plane configuration/state;
- remove owned changes;
- expose backend-specific diagnostics.

The engine owns transaction/idempotency semantics. Backends verify local owned runtime state; **they do not claim bilateral peer traffic from interface existence alone**. Backend implementations must not bypass the Engine with hidden global mutations.

## 8. Backend specifics

### GRE
Default backend.
- Native is the default; the v0.1 GRE implementation uses IPv4 underlay endpoints.
- Keyed GRE is supported, including an explicit key value of zero; the key is an identifier, not authentication or encryption.
- FOU/GUE are advanced encapsulations. Each Link owns one non-zero symmetric UDP port: the same fixed port is used as the tunnel encapsulation source/destination and as a receive mapping bound to the exact local/peer underlay pair and physical underlay device.
- Interface names are deterministically derived from Link ID and remain within Linux IFNAMSIZ; an `stl:<LinkID>` alias marks ownership. Destructive removal uses the observed kernel ifindex rather than deleting by reusable interface name alone.
- Multi-Link collision identity includes encapsulation, underlay pair, GRE key presence/value and, for FOU/GUE, UDP port. Distinct keys/encapsulations may coexist when the kernel can distinguish them.
- Auto MTU consumes backend overhead instead of hardcoded guesses: IPv4+GRE base overhead plus enabled GRE checksum/key/sequence fields, plus UDP for FOU and UDP+GUE base header for GUE.
- TTL/TOS/checksum/sequence/PMTUD are explicit advanced options and are verified from observed kernel state. A fixed GRE TTL with disabled PMTU discovery is rejected because Linux documents those semantics as incompatible.
- The backend exposes read-only capability and packet/byte/error counter hooks for common diagnostics; health observation never repairs state.
- Native inbound firewall ownership is exact peer/local/protocol/device. FOU/GUE use exact peer/local/UDP-destination/device rules. Route drift with an older owned rule fails closed for explicit reconciliation instead of silently adding or deleting a different rule.

### IPIP
- Native is the IPIP default; FOU/GUE are advanced UDP encapsulations with a deterministic, Link-ID-derived receive port, exact mapping ownership and IP protocol 4 for FOU.
- Linux IPIP tunnel lookup is not safely distinguished by FOU/GUE encapsulation or UDP port alone. On the tested Debian 13 / Linux 6.12 kernel, Native+FOU and FOU+GUE attempts for the same local/remote IPv4 underlay pair return EEXIST. STL therefore reserves the **same pair-wide backend resource/lock identity** for all IPIP encapsulations and rejects additional IPIP Links using that pair before applying changes.
- This IPIP-specific constraint does not forbid different backend kinds, such as GRE or WireGuard, from using the same underlay peers, nor independently addressable IPIP endpoint pairs. Multi-Link requests fail with an explicit conflict when the kernel cannot distinguish them.
- IPIP Native/FOU/GUE provide backend-specific overhead and owned, read-only state/counters to the common MTU/diagnostic layer. Diagnostic suggestions do not alter host network state.

### WireGuard
- encrypted/authenticated;
- private keys are secret and excluded from ordinary logs/status/diagnostics/JSON;
- v0.1 Quick Link may carry the receiver private key once in a sensitive pairing payload; the initiator retains only the receiver public key and does not persist the receiver private key in ordinary state;
- endpoint/keepalive configuration is conditional, not globally hardcoded;
- status includes latest handshake/counters where available.

### IPsec/XFRM

- strongSwan/IKEv2 with independent nonzero per-Link XFRM interface IDs,
  exact interface aliases/ifindexes, /32 selectors and protected 256-bit PSKs.
  ESP and kernel-confirmed NAT-T/ESP-in-UDP are implemented.
- The conditional runtime uses exactly one **STL-origin,
  native-exclusive** `charon-systemd` service and private VICI Unix socket
  per eligible host; all operations use the same canonical Engine and
  durable transaction journals. No global `swanctl --load-all`, wildcard
  unload, route flush or foreign-daemon adoption.
- Native service classification distinguishes harmless absent/not-found
  private-unit observations from an actual conflicting unit. Changing a
  positively verified pre-existing official vendor `strongswan.service`
  requires fresh exact-unit STOP confirmation under the maintenance gate;
  uncertain/foreign services remain untouched.
- Runtime admission requires verified config/unit origin receipts,
  effective loaded systemd state, trusted executable and process identity,
  private VICI/socket peer identity, safe logging and exclusive IKE UDP
  socket ownership. Failed admission blocks only IPsec. See
  [ADR-0005](decisions/ADR-0005-scoped-vici-ipsec.md) for the
  exact safety/consent contract.
- Create/Import/Connect/Ensure/Status/Diagnose/Restore/Remove and protected
  PSK retirement are exercised on real isolated Debian/Ubuntu traffic;
  an actual STL systemd service restart/restore passed in disposable Ubuntu.
  See [real IPsec E2E](operations/IPSEC-REAL-E2E.md) for
  reproduction and scope of evidence, not a general WAN guarantee.

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

The persisted MTU policy is per Link and endpoint-local: **absent in saved state** means legacy/unmanaged (no kernel MTU writes); explicit `unmanaged` in versioned v2 input opts out of managed MTU without mutating the live interface; **auto** means managed conservative overhead-aware local MTU (new guided creation default); **manual(bytes)** means managed validated local inner MTU. Older input/pairing without an MTU field preserves an existing committed local policy under the Engine lock, not silently clears it. Apply/Verify/Undo, update and restore run only through the canonical Engine-owned transactional lifecycle under Link/resource locks, with sibling isolation. A failed update must restore a proved unchanged original interface MTU or fail explicitly on uncertain identity. Probes and PMTU estimates are observational evidence, never durable proof. Read-only diagnosis cannot change MTU. Do not copy local policy to peers via Quick Link; version public schema changes deliberately and continue loading legacy saved state safely.

Keep default diagnostics small:
- preflight;
- link ping/reachability;
- MTU;
- short latency/loss/jitter;
- backend state/counters.

Throughput testing is opt-in.

Health is observational. Repair is explicit.

## 12. Setup Link integration

The [versioned pairing codec](PAIRING.md) centralizes strict payload
validation, creator-to-recipient inversion and optional sensitive
receiver credentials. Setup Links carry **data only**; an integrity
digest is not peer authentication. Preview is redacted and never
mutates the host; explicit confirmed import uses the same Engine.
Legacy/future schema compatibility is versioned independently of
internal State or CLI JSON.

One-step `quick` pairing is currently the simple default for
credential-bearing transports; a receiver private key or PSK in a
Quick Link is **SENSITIVE** even when encoded. A future local-key
exchange is an additive protocol decision, not an excuse to
reinterpret existing payloads or persist receiver secrets in
ordinary State.

## 13. Interactive UI and presentation boundary

The terminal UI is a client of the shared Engine and versioned machine
commands, not a second networking manager. Its operator contract is
documented in [CLI.md](CLI.md); reusable terminal rendering helpers
belong in `cmd/stl/menu_presentation.go`, not separate per-backend UI
frameworks.

- Keep a straightforward create/import/manage/test/update workflow with
  GRE Native as the guided default and optional advanced transport controls.
- Present observation, uncertainty, changes and the next action distinctly;
  do not equate saved/locally verified state with peer reachability.
- Confirm a planned host/prerequisite preparation separately from actual
  Link creation/import. Service interruption and deletion require their
  own specifically identified confirmation. Failed or uncertain actions
  return to an actionable recovery path, not silent retry.
- Use semantic color plus readable text; show one primary next action and
  optional detail. Align for narrow and wide terminals, but never wrap,
  truncate, color-inject or log exact IDs, commands or sensitive handoffs.
- Keep the interface usable with `NO_COLOR`, `TERM=dumb` and
  redirected streams; machine output must never depend on terminal colors,
  screen redraw, prose or prompt order.
- Menu actions never independently allocate addresses, install packages,
  own services, commit State, or rewrite firewall/routes; they delegate
  to the existing installer/Engine and trust boundaries.

## 14. Extensibility and complexity budget

Standalone terminal and external machine consumers share one Link
identity, Engine, backend contracts and resource lifecycle. The
public versioned CLI/JSON boundary is preferred for external
integration; internal Go types must not become an accidental public
API. A future in-process API, userspace carrier or daemon needs
demonstrated consumer value and its own compatibility/performance
evidence, not speculative infrastructure.

The current `Link` selects a native backend and one of its supported
encapsulations; it has no independent Carrier selection or generic
composition API. Native GRE emits IP protocol 47; GRE/IPIP FOU/GUE
require exact underlay endpoints, UDP ports and a resolved device, so
they cannot be assumed to work unchanged through a stream/WSS relay.
A Carrier does not by itself supply an authenticated private-IP Link.
For any proposed composition, first verify IP/UDP/stream framing,
dial/listen endpoint roles, required security, overhead/MTU, per-Link
resource claims, restart and owned rollback. Keep physical underlay
addresses, any future local Carrier endpoint and private Link Addresses
distinct. Add only a justified adapter to the existing Engine/Backend,
without a compulsory WireGuard/WSS combination or speculative cross-product
of backend/Carrier pairings. Future priorities and Owner gates belong in
[Issue #142](https://github.com/ach1992/simple-tun-link/issues/142);
none of these Carriers is shipped in the current CLI.

### Approved direction: lean L3 Provider and Carrier composition

The Owner selected the **lean composition** direction for the next
implementation phase ([Issue #142](https://github.com/ach1992/simple-tun-link/issues/142)).
The existing Engine, Link identity and backend transaction remain the only
authority for state, locking, resource claims, Apply/Verify, rollback and
reboot restore. Provider and Carrier are **separate compatibility concerns**,
not necessarily separate OS processes or a new public framework. The native
backend path must have zero helper/data-plane overhead.

A first internal, secret-free `internal/composition` path planner records:
- actual physical `Underlay`, private `LinkAddresses`, and (only when
  justified) a **different** local loopback UDP endpoint;
- exact outer payload framing and role; an outer transport supporting UDP
  does **not** imply the kernel GRE/IPIP FOU/GUE endpoint/source contracts
  are compatible with its forwarding semantics;
- one explicitly supported experimental WSS+kernel-WireGuard combination,
  with either physical-IP SAN or exact DNS certificate identity, separate
  dial/listen roles, per-Link TLS identity and deterministic per-Link resource
  reservations. All other WSS/backend combinations fail closed.
- the internal, non-runnable `ValidateWSSPeerPair` check verifies that two
  independently valid endpoint plans have reciprocal physical/private
  addresses, WireGuard peer keys and UDP ports, one dial/listen role, and the
  same exact WSS TCP endpoint and selected TLS name. WSS-only path
  validation also rejects private IPv4 routes overlapping loopback, link-local
  and other locally reserved ranges (without requiring RFC1918); it leaves
  Native address validation unchanged. The peer check intentionally does not
  claim support for a translated/NAT peer address, validate private
  credential matching, inspect host resources or establish a live Link.
  A future public pairing version must not treat this check as sufficient
  evidence to activate a Carrier.

The `internal/carrier/wss` adapter renders a restricted mTLS wstunnel
argv and an exact per-Link protected bearer-token/path-to-loopback-WG-UDP
policy. **Security boundary:** wstunnel v11.0.0 extracts the mTLS client
certificate CN only when it is present; a certificate with no parseable
CN can explicitly request another HTTP upgrade path. Therefore
`!PathPrefix` by itself is **not certificate identity authorization**.
The acceptance contract is **both** valid client-CA mTLS **and** possession
of an independent randomly generated 256-bit authorization token scoped
to the Link. The server additionally checks the exact link path and
permitted UDP/loopback destination. The CN check is defense in depth
when present, **not** sufficient or guaranteed alone. A trusted
certificate without CN that possesses the correct per-Link bearer can
still authenticate under this explicit model; no promise of strict
certificate-leaf CN pinning is made for upstream v11. This contract
must be independently reviewed before a runnable Carrier is admitted.

The client reads its `authorization-headers` from a verified private
0600 per-Link file using `--http-headers-file`; it never includes the
token in the process argv or environment. The server's generated
`restrictions.yaml` **contains the private token** and must remain a
protected 0600 secret; its bytes must never be logged, exposed in
normal diagnostics or checked into the repository. Only a publicly known
**test-only** bearer appears in the committed golden-policy fixture.
Upstream wstunnel v11 prints restriction rules (server) and authorization
HTTP headers (client) at DEBUG/TRACE, so such verbosity is **unsafe** with
this bearer-backed policy. Both generated invocations pin the explicit
global `--log-lvl INFO` flag, which takes precedence over an inherited
`RUST_LOG=DEBUG`; normal operational INFO/WARN/ERROR remains available.
Future process owners must preserve this flag and may not enable
DEBUG/TRACE unless an independently reviewed upstream patch or redaction
strategy prevents leaking credentials. Protecting both credential files
remains mandatory: log filtering cannot replace file permissions.
Issuance, peer exchange, token rotation and revocation are future
Carrier runtime gates, not implemented or authorized here.

The adapter also provides **read-only**, fail-closed local checks:
no-symlink per-Link TLS credential inspection under
`$stateRoot/credentials/wss/<LinkID>/` (private 0700 directories,
singly linked 0600 CA/cert/key **and bearer files**, valid CA/leaf
certificate usage including digital signatures and exact selected SAN),
and no-symlink pinned executable hash/owner/inode inspection.
The caller must supply a separately approved upstream SHA-256 and
revalidate the exact objects before actually starting the helper; file
inspection alone proves neither a peer's trust decision nor executable
lifecycle ownership.

An **opt-in disposable namespace acceptance**
(`scripts/e2e/wss-v11-compat.sh`) checks the real upstream
`wstunnel v11.0.0` executable on Linux x86_64 against a pinned hash,
using the renderer's exact committed server-policy fixture. The
runner checks binary identity and a new user+network namespace before
**any** private network modification, including when directly invoked
through its internal entrypoint. It tests a permitted UDP echo and
denies a foreign client CN (even with the correct bearer), an untrusted
client CA, a different remote UDP port, an untrusted server CA,
TCP forwarding, and a trusted-CA no-CN certificate that explicitly
forges the authorized path **without the valid Link bearer**;
a trusted missing-CN certificate **with** the valid bearer is a positive
check of the explicitly narrower authorization contract. Client denials
are isolated from unrelated retries, and the runner asserts that inherited
`RUST_LOG=DEBUG` does **not** leak the public test bearer to helper logs.
This is upstream helper/Policy compatibility evidence **only**, not
an STL-managed WireGuard Link or a multi-host throughput result.

A separate **non-runnable WSS-only kernel UDP ingress design gate** in
`internal/linux/wss_wg_ingress.go` produces a single exact nftables
`inet` table/hook/drop-rule transaction per Link and verifies the complete
table/chain/rule structure from `nft -j list table`. The guard denies
non-loopback IPv4/IPv6 packets to the selected kernel WireGuard UDP listen
port, before ordinary filter priority, while retaining the normal host
policy for all other traffic. Unlike an appended iptables DROP, its
separate early-priority hook cannot be bypassed merely by a pre-existing
filter-chain ACCEPT. Table and chain use **exclusive nft `create`
semantics in the same atomic batch**: a pre-existing same-name foreign
nft table must cause the whole batch to fail without modifying it,
regardless of a prior absence check. The table name and public
comment are **collision markers, not ownership proofs**; a matching
on-disk name or readback cannot authorize adoption, deletion, or
runtime activation.

A separate **non-runnable, read-only host coexistence probe** in
`internal/linux/wss_wg_host_coexistence.go` uses bounded direct command
readbacks (`nft -j list ruleset`, the IPv4/IPv6 iptables backend versions,
and both legacy iptables-save inventories). It refuses same-name nft table
collisions, nonempty foreign prerouting/ingress or equal/earlier input hooks,
unknown nft objects/flowtables, active legacy chains/policies, mixed
frontends and incomplete readbacks. It rejects duplicate ASCII JSON member
names and ASCII case aliases at every nesting level, and non-ASCII member
identifiers fail closed before Go JSON decoding (Unicode-folded struct field
aliases cannot conceal rule evidence). UTF-8 JSON *values* remain supported.
It requires one valid nft metadata object (JSON schema version 1); a
canonical metadata-only empty ruleset is valid.
Runner errors expose only fixed stages and recognized sanitized status
categories, never arbitrary runner output. A conventional later-priority
iptables-nft INPUT `ACCEPT` does not by itself override the earlier DROP.
The disposable real-kernel-WG lab also checks live full-ruleset admission,
foreign early-hook rejection and subsequent recovery inside its own namespace.
This is **point-in-time compatibility evidence only**, not effective host
admission: neither the host-wide snapshot nor a successful read-only probe
provides atomicity against later firewall changes, exclusive WG-port or
nft ownership, legacy-policy proof when inspection is denied, a durable
journal, crash compensation or permission to apply a guard. A future
runnable Engine integration must evaluate real host ownership and rule drift
under the proper locks; ambiguous mixed firewalls remain blocked.

An explicitly opt-in, rootless **disposable namespace** test
(`scripts/e2e/wss-wg-ingress-netns.sh`) executes the same unit-tested
nft batch beside a real kernel WireGuard UDP listener. The outer
launcher records its user/network namespaces and a private random
guard; internal `--isolated` entry requires that evidence and a
separate mapped-root user/network namespace before any host effect.
The lab deliberately collides with a foreign same-name table/chain
inside the disposable namespace and verifies exact unchanged objects.
It checks IPv4/IPv6 ingress-drop counters with a pre-existing ordinary
ACCEPT and verifies actual nft JSON readback using the Go validator.
This is limited to the tested network namespace/kernel/netfilter
semantics: it does not prove that every host's foreign-prerouting
configuration is compatible, provide an Engine-held ownership lock,
create a durable pre-effect journal, secure crash rollback, or prove
a two-peer authenticated WG handshake. Do not enable it on a
physical/production host or wire it into the Engine before the
remaining security, restore and authorization gates below.

The adapter still does **not** provision TLS credentials, start services
or enable a Carrier in the public Link schema. Current shipped/native
Link behavior is unchanged; staging is intentionally not runnable as
an STL-managed WSS Link until these non-optional steps pass:

1. Use a verified, pinned/offline-capable helper and a protected per-Link
   TLS and per-Link bearer issuance/rotation/trust store; verify exact
   server SAN/IP, TLS certificate chains, bearer pairing/revocation
   and strict destination allowlist before activation. Explicitly
   evaluate the narrowed bearer+mTLS identity model before release.
2. Make a composed **one-Link** backend plan own helper process/unit,
   private files, dedicated TCP/UDP listeners, kernel WG interface/port,
   exact input/firewall isolation, MTU and crash-recovery evidence. The
   passive `linux.TCPListenerProbe` reserves TCP ports host-wide; socket
   vacancy or a deterministic pathname alone is not ownership.
3. Enforce isolation of kernel WG's public UDP listen socket; setting the
   WireGuard peer to loopback does **not** bind its kernel socket to
   loopback. Preserve other services, rules, default routes and native
   WireGuard's existing scoped physical admission behavior.
4. Extend State/pairing/machine input only with explicit versioned
   compatibility and secret-safe peer handoff; old executables must never
   interpret a composed Link as native WG. A new State/Quick Link schema
   is **not** implemented or published at this stage.
5. Prove real two-peer private IP and process/boot recovery in disposable
   test environments, negative security/foreign-resource cases and exact
   loss/MTU/performance; independently authorize any physical-host trial,
   main merge and release. Standalone WSS+WG field evidence is a reference,
   **not** STL-managed Carrier acceptance.

Future WG+Paqet or other provider/Carrier pairs must pass equivalent
source, framing, underlay/security and lifecycle checks before admission.
No compulsory WireGuard/WSS pipeline, universal plugin ABI, second Engine,
generic TUN loop, automatic failover or new GOST integration is introduced.

Prefer shared small interfaces, standard-library primitives and
native Linux integration where they improve correctness or measured
performance. Avoid alternate Link managers, a generic plugin
framework, global polling services or a central database absent
a concrete accepted need. The lasting product principles and
non-goals belong in [PROJECT-SPEC.md](PROJECT-SPEC.md).

## 15. Runtime portability and operator observability

### Conditional native-exclusive IPsec

All supported IPsec Links share a **single STL-owned**
native-exclusive strongSwan service with individually owned
per-Link IKEv2/XFRM identities. The Engine never takes over a
foreign VICI namespace or uses bulk unload/reload of arbitrary
credentials and connections.

Admission must independently prove protected config/service
publication origin, actual effective systemd unit, trusted active
process/executable, protected VICI peer, safe effective logging,
IKE UDP port ownership and unambiguous kernel/XFRM resources;
all observations are rechecked under the correct Engine locks
before effectful changes. Unknown or foreign prerequisites block
**IPsec only**, leaving GRE/IPIP/WireGuard usable. No positive
doctor check alone proves encrypted peer packets.

Signed package/service preparation has its own scoped approval.
A verified **pre-existing official distro**
`strongswan.service` requires the *separate* exact
`STOP strongswan.service` consent, disruption warning and
fresh eligibility proof; generic `PREPARE` never authorizes
stopping foreign/unknown daemons. An unverified or partially
committed XFRM/VICI mutation stays journaled for exact-owned
reconciliation; missing original ifindex is not permission
to delete a similarly named interface.

The [IPsec runtime ADR](decisions/ADR-0005-scoped-vici-ipsec.md)
owns the rationale and consent trade-off;
[SECURITY.md](SECURITY.md) owns precise protective rules.
The [IPsec E2E runbook](operations/IPSEC-REAL-E2E.md) owns
reproduction and bounded evidence.

### Shared observations and error contracts

Every backend and CLI/menu workflow projects from a consistent result
model, without creating per-screen diagnostic or logging engines:

- Human-readable outcome: **what happened**, confirmed/unknown state, the
  specific safe reason, affected scope and one actionable next step.
- Machine-readable outcome: stable reason/error codes, versioned schema,
  deterministic exit behavior and redacted optional evidence. Evolve public
  contracts through explicit compatibility/versioning decisions.
- Correlation: safe operation, Link ID, backend, lifecycle stage, elapsed
  time and outcome. Sensitive handoffs, private keys/PSKs, daemon frames,
  raw command output and unvalidated paths never become logs or support
  payloads.
- `status` and `doctor` inspect, never mutate. `diagnose` may send
  explicitly requested bounded probes, never secretly repair. Real
  observed peer traffic, local interface identity and a successful
  restore are separately reportable facts.
- Keep `--json` stdout machine-only; optional support detail must remain
  secret-safe and may not corrupt the structured response. Add a logging
  daemon, database or retention machinery only when justified by an owned
  runtime requirement.

## R1 WireGuard over WSS (implementation candidate)

One canonical Link identity has Backend wireguard-wss (never Native WG
fallback), Encapsulation UDP, WireGuardOptions and endpoint-local WSSOptions.
Composition derives precisely WSS over kernel WireGuard, rejecting unsupported
Carriers. The existing Engine locks, desired-State v4 and resource claims
govern all effects. The WSS Backend applies in dependency order:
admit pinned helper/private mTLS + firewall coexistence → create private
nft kernel-WG UDP ingress guard → create owner-tagged WG Interface →
start one owner-scoped systemd WSS helper → verify complete host firewall,
exact systemd sandbox/restart properties and original TLS/bearer fingerprints
→ commit Link State and consume the exact pre-effect journal.
Dispatched nft/systemd errors are treated as potentially effectful:
the journal stays durable, and WG ingress protection is not rolled back
while an uncertain dependent helper could remain live. Remove performs the reverse, records the exact issued TLS/bearer
material hashes in its private-key retirement receipt **in the same
State commit**, and securely retires
protected Link-local TLS/bearer/WG credentials after separate host-absence
proof. A crash before a completed receipt requires owner-scoped recovery;
no foreign adoption or generic host cleanup is permitted.

### R2 — durable WSS pre-effect crash quarantine (stacked candidate)

The canonical Engine prepares a secret-free `wss_crash_operations`
record in State v4, after final resource-lock admission and **before**
calling the WSS Backend Apply. It stores the endpoint-local public Link,
operation, random nonce, prior-commit flag, and complete planned resource
claims. This is a **reservation/quarantine**, not proof of nft/kernel/systemd
ownership and not authorization to delete a named object.

Journal publication and fsync must succeed before the first host effect.
Successful Ensure/Remove consumes the *exact* record in the same atomic
State commit as the Link change. Crash/failed compensation/unknown host
state retains the journal, blocks automatic Link replay and reserves
resources from other Links. Restore may continue independent,
non-conflicting Links; an empty State with a pending journal must not
remove the host restore unit.

`stl link reconcile-wss-vacant ID --confirm ID` is restricted to an
uncommitted initial Ensure. It locks the same resources, refreshes the
transaction and requires read-only proof that no matching kernel WG
interface, nft ingress guard or loaded helper unit remains. Only then
does it clear the journal. It **never** modifies host objects, deletes
secrets or adopts name-matched objects.

A separately confirmed `stl link reconcile-wss-removed ID --confirm ID`
handles a committed Remove only when the exact original Link, immutable
committed owner claims, original credential fingerprints and pre-effect
journal still match. Independent inspection must confirm the nft guard,
kernel WG interface, **loaded** helper unit, and the original public
WireGuard key/listener (including on other interfaces) are all absent. Only then
does one durable State update consume the journal, delete the previously
committed Link and publish its original fingerprint-bound retirement receipt.
No host file/service/kernel resource is mutated; `retire-wss` subsequently
requires complete host absence and exact original file SHA-256 hashes.

The unreleased R3 candidate adds explicitly confirmed original-object
recovery without changing ordinary Link automatic replay:
- `reconcile-wss-repair-vacant` verifies the committed Link, original
  private-file contents, locked resource claims and complete host
  vacancy. Only its committed Ensure journal is consumed; desired State
  and original ownership remain intact for RestoreAll.
- `reconcile-wss-original` derives original host nonce from the initial
  journal or committed Link, separate from fresh repair/Remove journal
  transaction nonce. nft rule and transient systemd description bind
  to this original identity. An exclusive kernel WG create uses a 70-bit
  nonce-derived staging name first, then sets the alias BY IFINDEX and
  renames: this avoids a bare public-name creation window. Because Linux
  does not atomically publish IFLA_IFALIAS on initial WG NEWLINK, the nonce-
  derived name ALONE cannot attest pre-alias ownership. An unmarked staging
  object is always quarantined with its ingress guard and journal; STL cannot
  delete it by guessed name, even if it might be the original creation.
- Under canonical Engine locks, identity readback gates the exact
  original helper, kernel interface and guard in that order.
  **Network namespace-local** WG interface/key/listen-port inventories
  alone are NOT host-global evidence. A WG interface can move to another
  namespace but retain a UDP socket in its original birthplace
  namespace; when the moved WG is DOWN, even that socket vanishes
  until the interface is raised elsewhere. Thus every nft guard
  deletion must additionally have a fresh, same-transaction witness
  of a successfully deleted **exact original nonce-tagged WG ifindex**,
  and complete UDP socket enumeration in the guarded birthplace
  namespace must still show no listener at the protected port.
  Empty WG/UDP inventories cannot mint a deletion witness after
  a crash. Original Crash Journal and credentials therefore remain
  quarantined if that witness was lost; this is a deliberate safety
  limitation, including guard-only or post-deletion crash windows,
  rather than fabricated automatic recovery. Confirmed original
  helper/WG/guard compensation and final strict vacancy precede
  State/journal commit. Committed Remove publishes the original
  retirement receipt; committed repair preserves its Link.

**Durable cold-boot recovery phase:** an explicitly confirmed
`arm-wss-cold-boot` command atomically adds
`cold_boot_armed_from` (the current, kernel-issued UUID) **and**
`cold_boot_source` (`linux-initial-pid-unshadowed-procfs-v1`) to the
original validated State v4 pre-effect journal. The versioned source
marker is written only after successful live host-provenance checks;
it is not a cryptographic attestation against a privileged State writer.
It is never a host deletion witness and it cannot be changed after a reboot.
Legacy UUID-only checkpoints remain loadable and preserve reservations,
but CANNOT authorize Reconcile or be automatically re-armed/upgraded.
An independently Owner-authorized full-host kernel reboot terminates
the entire original WG kernel generation across all old network
namespaces, including moved-UP/DOWN devices. Cold-boot admission
requires the **initial host PID namespace and an unshadowed procfs
kernel boot-ID source** at both checkpoint and reconciliation (not
merely a valid UUID); containers, synthetic/bind-mounted boot IDs,
shadowed procfs and unverified mount provenance fail closed. On an
attested different host-kernel boot, `reconcile-wss-cold-boot`
revalidates original journal/committed claims, private issuance
identity, current-kernel helper/guard/WG/UDP absence and exact Boot-ID
change before its atomic State transition.
This path does NOT delete any host objects or retire credentials; a
committed Remove receives an exact immutable retirement receipt.
A container/unit/process restart or a spoofable operator-supplied
boot UUID is not sufficient. If any prerequisite fails, retain
quarantine. Rootless acceptance verifies that a bind-mounted virtual Boot ID
and nested PID namespace CANNOT arm/reconcile or clear crash journals;
positive State transitions use deterministic Engine fakes and are
not physical reboot acceptance. See OPERATOR-RECOVERY.md for Owner consent, affected
namespaces, backups and rollback.

Unverifiable/foreign effects are quarantined, not adopted by name.
Physical systemd/field/ARM64 WSS and independent review remain separate
from isolated executable proof.

For reproducible **31-scenario rootless real-kernel acceptance** on a
disposable amd64 Linux test host with the pinned local fixture already
prepared, run `bash scripts/e2e/wss-managed-wireguard-matrix.sh` from
a clean exact-HEAD checkout as an unprivileged user. It builds the
current tagged test CLI, serially reuses the existing locked namespace
harness, records per-case ignored local logs and prints exact HEAD/TREE.
This is an **opt-in acceptance script**, not a post-install action,
CI requirement or permission to change a physical production host.
The existing fixture/prerequisite admission still applies.

The rootless test `STL_WSS_R2_CRASH_TEST=1 bash
scripts/e2e/wss-managed-wireguard-r1.sh` sends SIGKILL after a
**real** nft guard creation and before Go State commit. It proves
durable journal reservation and fail-closed rejection of a guard-only
Crash without an original-kernel deletion witness; it does **not**
claim successful vacancy-only reconciliation or credential retry.
The same harness exercises original tagged partial WG compensation,
end-to-end genuine ICMP/TCP/UDP over WSS in normal Create/Remove,
and migrated WG objects both UP and DOWN via
`STL_WSS_R5_MIGRATED_WG_TEST=active|down`, proving that neither
namespace-local absence nor temporarily missing UDP socket alone
can retire an nft ingress guard or original WSS credentials.
The harness uses disposable rootless kernel WireGuard+nft with a
systemd **shim**, not real PID1 reboot or physical two-host recovery.
