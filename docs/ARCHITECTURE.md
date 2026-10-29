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
a generic Native-Backend/Carrier compatibility matrix is **not**
shipped as an arbitrary CLI combination. The separately managed
**WireGuard-over-WSS** path has shipped since Stable v0.1.10 and is
documented below; it does not establish general Carrier composition
or imply that additional research Carriers are available.

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

## Optional QUIC/UDP Carrier admission study (not a shipped Backend)

[Issue #142](https://github.com/ach1992/simple-tun-link/issues/142) owns the
decision, research and release/host gates for a **second** Carrier. Current
physical IRPT-101 ↔ DE-Hamed-Test research established DE-initiated UDP/KCP
payload delivery and DE-first QUIC Initial reachability, but **did not prove
an authenticated QUIC 1-RTT session or a secure managed WireGuard Link over
the physical public path**. TCP proxy/wrapper alternatives reuse the already
working WSS TCP underlay; UDP QUIC can add a genuinely distinct *conditional*
path. Paqet/PCK and destination-port hopping remain Owner-parked. No
automatic Carrier fallback is implied.

The **non-runnable** `internal/carrier/quic` adapter first targets an
optionally installed, exact-SHA256-verified upstream Hysteria **app/v2.13.0**
helper. It produces only public endpoint/role topology and a sensitive
strictly scoped **JSON configuration** (never a ready-to-run STL Link),
with separate Dial and Listen roles, an explicit physical QUIC UDP socket
and a distinct Dial-side `127.0.0.1` UDP socket for **kernel WireGuard**
forwarding. The protected config requires verified server TLS identity,
client-certificate authentication through a restricted client CA, a second
independent per-Link random authorization secret, and a server ACL accepting
only the selected `127.0.0.1:<owned-kernel-WG-UDP-port>` destination with a
final deny-all. No HTTP, SOCKS, unrestricted forwarding, proxy, TUN, Native
GRE/IPIP/FOU/GUE or public-IP fallback is admitted. The binary and
generated config are not silently installed or started, and the existing
WSS/native Link schema, CLI, on-host helpers and v0.1.12 release are unchanged.

A separate, still **non-runnable** per-Link credential issuer creates two
independent ephemeral CA signing authorities (server and client) and their
role-specific TLS leaf identities plus a random 256-bit Link bearer. Only
the appropriate leaf key, peer trust anchor and bearer are returned for each
role; the CA signing keys are not exported or persisted. Bundles are
sensitive in-memory data, not authorization to import credentials, rotate
identities or start a helper. A source-only preparation
component now provides explicit, caller-locked `StageCredentials` and
read-only `InspectCredentials`: per-Link/role exact four-file material under
`$stateRoot/credentials/quic/<LinkID>/`, verified no-symlink `0700`
directories, singly linked `0600` files, no-replace/idempotent bytes, TLS
leaf purpose and exact server SAN checks, protected CA/bearer checks and
public-only SHA-256 readback identities. Unexpected opposite-role material,
credential drift and uncertain readback fail closed; a partial publication is
**preserved**, not automatically deleted or overwritten. Local inspection
cannot prove cross-host CA matching or authenticate a peer.

A separate read-only `InspectPinnedHysteria` verifies the optional installed
binary using exact upstream AMD64/ARM64 SHA-256, owner/mode/inode and
no-symlink path checks. It reuses the Linux trusted-executable inspection
shared with WSS; neither the optional binary nor certificates are installed
by these APIs. The **source-only, non-runnable** canonical QUIC pre-effect
journal described below can now durably reserve the proposed identities,
but it neither calls these protected APIs nor attests/owns their actual
files, executable, service or kernel generation. A future runtime Engine
must recheck exact credential and executable fingerprints under locks and
prove partial effects independently before treating any resource as owned.

A follow-up, still **non-runnable** public-topology admission function,
`quic.Plan.CarrierClaims(localKernelWGUDPPort)`, now proposes the exact
host-wide exclusive UDP reservations for a future composed Engine plan:
the **local native kernel-WireGuard UDP listen port** plus either the Dial
role's `127.0.0.1` helper forwarder port or the Listen role's physical
QUIC UDP listener. The Dial peer's remote WireGuard destination port is
**not** a local reservation. Existing STL UDP-port collision semantics
apply conservatively across bind addresses and native/WSS/QUIC adapters.
The helper, per-Link TLS-identity and scoped nft guard have distinct
secret-free resource identities. Listen rejects a mismatched local
WireGuard/ACL port and either role rejects an intra-Link helper/WG
socket-port collision; renderer validation shares the role/port contract.
These are **only proposed identities**, not host ownership; the bounded
source-only Engine journal below can also durably preserve these claims.
There is still no committed runnable QUIC Link, actual socket reservation,
nft rule, service identity, certificate admission, helper start or public
QUIC Link activation.

A separate **read-only source-only** `app.Engine.CheckQUICPreparation` now
consumes `quic.Plan.LocalAdmission`'s validated, port-only projection and
composes it with `composition.WireGuardProviderClaims`, the same
native WireGuard interface/address/local UDP/public-key claims consumed by
shipped native/WSS planning. Both local and peer private IPv4 Link routes
reuse WSS's global-unicast and reserved-prefix overlap checks (including
loopback and link-local), without imposing RFC1918-only addressing.
Within canonical Engine maintenance, Link and resource locks it refreshes
State, checks conflicting committed/pending Links
(including unresolved WSS claims), and uses the existing live
`linux.CollisionInspector` contract for local interfaces, addresses, routes
and **both** locally bound UDP ports, including connected UDP sockets,
from an all-state IPv4/IPv6 socket inventory. It refuses shared strongSwan
UDP/500 or UDP/4500 when any committed/pending IPsec intent is present even if the
shared daemon is temporarily not listening: those fixed ports are not in
IPsec's per-Link exclusive claims. The actual live socket inventory is still
required regardless of persisted State, including when a daemon has no
per-Link record. Other unique per-Link helper, firewall and WG public-key
claims are proposals, **not** independently attested live host identities.

This check performs no QUIC staging, State mutation, journal, or runtime
operation. Its locks are released before it returns; a clean preview is not
an exclusive reservation, a service/binary/TLS attestation, global
cross-namespace WireGuard identity proof or permission for any host effect.

The separate **source-only** `Engine.PrepareQUICCrash` now reuses that
same canonical locked admission to durably write one **pre-effect QUIC
intent** in the existing private, atomic desired-State v4 FileStore. The
first journal is **for a NEW, uncommitted Link only**. It captures the
complete public endpoint-local role and physical QUIC/TLS Plan (not only
local UDP port projections), private Link Addresses, public WireGuard
configuration and exactly
derived provider + carrier claims, a unique Engine-issued nonce, the
**expected-only** role-specific TLS certificate/CA/bearer fingerprints,
helper-config SHA-256, and expected pinned-executable path/SHA-256/inode.
Before writing it the Engine validates local/peer private routes and rules
out the physical QUIC endpoint being swallowed by either private route.
The final State collision check and journal publication occur under
maintenance -> Link -> resource -> shared restore-persistence locks. The
restore lock also serializes ordinary last-Link Remove and empty-State
RestoreAll unit cleanup: both must retain an existing owned reboot restore
unit while any unresolved QUIC journal remains. Ordinary independent Link
removal still succeeds; the unit is retired only after no committed Link or
protected QUIC/WSS pre-effect reservation remains. A source-only QUIC journal
does **not** install a restore unit that was absent to begin with. These
locks and expected identities do not attest that credential files, the
binary, peer authentication or a process/kernel owner actually exist.

An unresolved QUIC journal survives State reload and publication
uncertainty, reserves its **full local resources** against unrelated Links,
rejects duplicate/new use of its Link ID, and blocks ordinary Ensure/Remove
and empty-State restore-unit retirement. Its content cannot be altered or
silently removed through the normal FileStore.Update path: **no automatic
replay, rollback, replacement, or deletion** of an uncertain QUIC generation
is authorized. The additive `quic_crash_operations` field uses the same
State v4 store; legacy v1-v3 documents cannot graft a QUIC journal during
migration, and older strict readers lacking this field fail closed rather
than silently ignore an unknown pending operation. Release-level State
compatibility must be verified before this source-only writer becomes
available in installed versions.

This first journal merely establishes the durable **pre-effect boundary**.
No CLI, installer, managed native-WG or Hysteria helper calls it; it does
not stage any protected file or perform host effects. In particular,
check-then-commit locks do not remain held after the call, and a stored
nonce/claim is **NOT** an actual port reservation, executable spawn permit
or proof of ownership. Later reviewed code must re-validate actual
credentials and binary/config under held locks, supply an ownership-aware
host-effect transaction and exact partial-effect recovery/remove/retirement
before exposing an operable QUIC Link.

A further **source-only** QUIC host-generation identity projection now
reuses the existing WSS nft ingress guard renderer, strict JSON verifier
and exclusive kernel WireGuard netlink create primitive. QUIC derives
distinct `stlquic_*` nft tables and nonce-bound rule comments, a
`stl:quic:<LinkID>:tx:<nonce>` kernel alias candidate and a separate
nonce-derived `q*` original-staging interface name. The projection
`linux.PlanQUICWGHostOrigin` binds all three to the same immutable journal
nonce and local kernel WG UDP port. Unlike legacy WSS read-only guard
plans, QUIC requires a valid nonce from the start; neither matching
table names nor markers prove their own creation. This change performs
no nft, netlink, systemd, helper or State operation. Before any future
host effect, the canonical Engine still needs its post-journal live
vacancy checks, exact original-object creation witnesses, positive
ifindex/guard/service ownership, dependency-ordered rollback and
reboot/reconciliation gates; a source-only plan is not a permit.

A shared, still **read-only** whole-host firewall-coexistence probe now
supports both WSS and QUIC candidate WG ingress guards. It reuses the
existing bounded five-query nft/IPv4+IPv6-iptables/legacy inspection and
its strict early-hook rejection. Only independently attested, exact
current WSS or QUIC sibling guards may be excluded, with a complete
nonce (when present)/port/table/rule live readback; missing, foreign,
drifted, duplicated, overlapping UDP-port or self-claimed NEW Link
guards fail closed. Separate WSS and QUIC
namespaces do not authorize automatic trust or cleanup. The future
canonical Engine must prove each committed sibling's original State,
host and generation ownership before supplying any exclusion; this
source-only probe cannot establish that evidence itself or grant an
nft transaction, kernel effect or host mutation.

The separate **source-only** `quic.StageHelperConfig` and read-only
`quic.InspectHelperConfig` provide checked, deterministic `helper.json`
publication for each Link's already-protected credential generation. Before
staging, they validate the complete role/local UDP claim proposal, admit the
exact official SHA-256-pinned Hysteria executable, read the appropriate
role's protected 0600 certificate/key/CA and bearer through private
descriptor-relative access, validate the TLS/Link identity and regenerate
the exact role-specific Hysteria JSON. `helper.json` is then created only
with no-replace 0600 semantics, and readback must match the exact freshly
rendered bytes. Existing differing or untrusted files, opposite-role CA,
permission/inode changes, or changed authenticated topology are refused
without deleting/replacing uncertain material. Only secret-free
`HelperConfigIdentity` evidence (config SHA-256, credential fingerprints
and verified executable inode/hash) is returned; plaintext authorization
never belongs in ordinary Link State, diagnostics or arguments. Opt-in
tests additionally exercise an **actual pinned official Hysteria binary**
for config staging/readback without spawning a helper.

The source-only `quic.PreviewHelperConfig` calculates the anticipated
seven-field public credential/config/executable identity from an in-memory
role-specific bundle, exact Plan and State root, using the same certificate,
bearer, Hysteria renderer and official executable admission as protected
staging. Preview performs no private-file publication. The calling
Engine workflow must first publish the complete immutable pre-effect
journal containing these expected values via `PrepareQUICCrash`; a preview
alone does not reserve a Link or establish ownership.

`Engine.StageQUICCrashMaterials` is the **source-only, non-runnable** canonical
writer for an already durable, unresolved QUIC journal. Its public
implementation now requires **positive create-time generation provenance** in
addition to seven expected fingerprints. It reconstructs the journal's exact
Plan, checks the immutable nonce, performs the same official-binary and
private-bundle preview before any protected Link directory is created, and
rechecks State under canonical maintenance -> Link -> resource locks.

A **fresh** Link credential directory is created with exclusive
descriptor-relative `mkdirat` (not reused merely because file contents
match). STL immediately opens and pins the original directory FD and
device/inode, checks the original canonical parent entry, then syncs the
parent. The FIRST creation of each of the five role-private 0600 files
uses strict exclusive `O_CREAT|O_EXCL` publication through **that pinned
directory FD**, recording the very inode created by each successful open,
synchronizing its data and directory, and verifying its original identity
against immediate and final no-symlink readback. Even byte-identical
`EEXIST` fails closed; generic no-replace/idempotent component staging is
**not** permitted to manufacture first-generation ownership. Before any
receipt publication STL rechecks all five original inode witnesses, the
complete inventory and the still-pinned originating directory/parent identity.
Only then does it publish the private 0600 `generation-owner.json` sidecar
(schema v1), also through exclusive create-only publication, and perform
same-FD receipt/inventory/inode readback. This sidecar binds the **Engine-issued immutable
journal nonce**, Link, role, expected seven-field identity and **all five
creation-generation inodes**. It does not contain plaintext keys or bearer.
Every idempotent retry is a separately gated **existing-generation** path:
it must inspect the same durable receipt and all five matching actual inodes;
it must NOT restage or adopt a pre-existing directory merely because its
credentials and helper JSON match the journal. The receipt, files and final
inventory are inspected with one held directory FD, rather than mixing
independent canonical-path resolutions. A crash after
exclusive directory creation but before the sidecar becomes durable leaves
uncertain files quarantined. No automatic deletion, adoption or blind retry
occurs. This approach changes no State v4 schema.

The read-only public `Engine.InspectQUICCrashMaterials` now requires both the
positive journal-bound receipt and actual protected config/credential and
pinned executable identity. Receipt, exact five-file inode witnesses,
private credential semantics and helper JSON are inspected using a **single
held generation directory FD**, with a final receipt recheck and canonical
credentials/QUIC/Link path identity revalidation. A replaced directory,
ancestor or same-byte foreign inode fails closed; an independent successful
read from another directory can never complete the ownership attestation.
The raw protected-storage helpers remain uncommitted building blocks, not independent ownership grants. Neither
successful staging nor inspection **consumes the journal**, proves any actual
systemd/kernel/nft object or Hysteria process ownership, authenticates the
remote peer or launches any helper. Future runtime implementation must
re-attest exact helper bytes and protected materials at the process
activation boundary and record positive host-specific create/absence witnesses.
Interrupted, unknown or foreign host effects keep the journal unresolved;
the existing restore/Engine locking must be reused rather than duplicated.
Changing a Dial TLS peer name cannot be inferred from its leaf certificate
alone: the exact journal Plan and rendered helper config remain binding.

A separate, **not yet wired to CLI, RestoreAll or a public Link backend**
QUIC ingress origin step now provides the first host-effect implementation:
`quicguard.StageOriginal(ctx, engine, linkID)` is the sole exported
production nft CREATE entrypoint, with no caller-selectable publisher,
Runner, plan, nonce or create-result witness. It calls
`Engine.WithQUICCrashIngressAdmission` synchronously to reuse the durable,
immutable QUIC journal and canonical maintenance/Link/resource locks. The
Engine callback is an *admission scope*, not independent proof of host
creation: success as an actual ingress creation witness requires the fixed
host command and complete strict readback inside the Stage entrypoint. It first
re-attests the original protected five-file credential/config generation
receipt and the exact SHA-256/inode-pinned Hysteria binary; the private
quicguard writer reconstructs the nonce/port-bound nft plan from Engine-
attested State; Linux read-only inspection reuses the
shared WSS/QUIC bounded nft table inventory and full five-query firewall
coexistence preflight, checks complete *current-host* WireGuard public-key,
listen-port and guard-namespace UDP listener/socket vacancy via the existing
WSS WG inspector plus an all-state (`ss -a`) UDP census for connected sockets,
then performs an exclusive `create table` nft transaction followed by strict
full-table readback. A missing/ambiguous/occupied live inventory fails
closed **before dispatch**; the previous journal's vacancy snapshot cannot
be reused as a present-time creation permit. As with all snapshot-based
admission, a foreign process can race a readback after it completes;
final runnable activation must still use its own dependency-aware original
resource ownership and post-effect checks. A **pre-existing table,
even with identical bytes/marker**, is never adopted as this attempt's
original. An unsuccessful or ambiguous dispatched nft operation is not
rolled back: the same QUIC journal and possible guard remain quarantined
without any inferred deletion rights. This is a **single-call creation
witness**, not a durable table-handle ownership receipt or permission to
retire the guard later. The current first-generation preflight deliberately
rejects other early WSS/QUIC hooks until their independently verified
original owner State + host evidence can be passed to the already shared
sibling coexistence machinery; do not work around this by disabling WSS.

A separate **read-only, journal-bound host observation** is available
internally as `quicguard.InspectPendingOriginal(ctx, engine, linkID)`. It
reuses the canonical Engine's existing maintenance/Link/resource locks and
requires the immutable original journal and current protected generation
attestation. It uses the fixed actual nft reader, a trusted kernel boot-ID
source and a before/after stable OS-thread-scoped network-namespace label
from `/proc/thread-self/ns/net`. The observer locks its OS thread for the
entire nft subprocess sequence, so the namespace label describes the same
thread context in which `nft` executes (unlike `/proc/self/ns/net`, which
can describe a different thread). The original guard CREATE also locks its
thread across live preflight, `nft` effect and strict readback and fails
closed on namespace drift (quarantining effects dispatched before drift).
Neither lock nor the label proves original ownership. The strict
nft table census and full exact table readback must agree on the original
object handles. The only successful statuses are **not visible in this
observed namespace** and **matching shape, ownership unverified** (the latter
includes Table/Chain/Rule handles). Any missing, changed or ambiguous input
is an error, not proof of absence or ownership. Kernel nft handles can be
reused, same-byte foreign tables may appear identical, and namespace-local
observation cannot prove absence on an entire host. This diagnostic never
updates State, adopts or removes a resource, starts any Helper, clears the
journal, or grants durable recovery/retirement authority. Its strict host
boot-ID source intentionally fails closed in unsupported nested PID/proc
mount environments; disposable namespace integration uses a clearly
synthetic boot-ID *test seam only*, with actual kernel nft operations.

This bounded source step has no CLI or runtime caller and is **not** a running
QUIC Link. Future implementation must add durable original nft generation
ownership, exact kernel WG/UDP and process/systemd witness, separate
activation-time executable/credential re-attestation, and dependency-aware
safe rollback/reboot/retirement before enabling a committed private L3 Link.

The adapter's opt-in disposable loopback compatibility test uses the
pinned, hash-checked official Hysteria binary with **Go-issued per-Link
TLS/mTLS credentials and bearer**, not manually authored helper JSON or
OpenSSL-generated identities. Both DNS and literal loopback IPv4 SANs
complete a genuine QUIC session and **100/100 byte-identical 1200-byte UDP
echoes**. Security-negative evidence is not inferred from UDP timeout alone:
the test requires the bad-bearer client's exact upstream HTTP 404 auth
failure, the foreign-client-CA client's QUIC TLS remote unknown-CA failure,
and confirmation that the forbidden client first authenticated and
then generated an exact server-side UDP WARN event with the ACL's `rejected`
error, matching that client's QUIC address and authentication identity.
The unlisted UDP destination must receive nothing; the original allowed
destination must still work. Every helper INFO log is checked for
credential leaks, and failure diagnostics never echo raw helper logs.
These are **local helper/serialization results**,
not physical WAN, kernel WireGuard L3 or STL-managed lifecycle acceptance.

A separate opt-in test-only
`scripts/e2e/quic-wg-private-l3.sh` lab now proves that the
same pinned Hysteria v2.13.0 config renderer, disjoint protected role
material, native kernel WireGuard devices and source-generated QUIC nft
guard can carry **real bilateral private-IP ICMP, TCP and UDP** across
a disposable veth underlay joining two network namespaces. Direct
physical-interface WG UDP is dropped by the isolated nft guard; private
traffic stops when the QUIC client helper is stopped and resumes on
restarting it with unchanged WG identity. It uses no managed Engine
activation: the test-only nft CREATE and WG/helper start are scoped
explicitly to the disposable lab and do NOT grant original resource
ownership, transaction/journal clearance, systemd/reboot recovery or
physical-host acceptance. The operational and reproduction contract is
in [DEVELOPMENT.md](DEVELOPMENT.md).

Before a public `wireguard-quic` (or equivalent explicitly approved) Link
is enabled, the original Engine must own compatible provider/carrier
composition and Link identity/State, an exact binary/credential trust
chain and optional offline helper installation, bounded helper systemd
ownership, physical UDP and loopback port reservation, the kernel WG
ingress guard, crash journaling, true wire 1-RTT and private L3 tests,
independent multi-Link coexistence, restore/remove and safe rollback.
Enable only one precise combination after validating these gates; do
not build a generic plugin API or a second packet Engine preemptively.

## WireGuard over WSS (implemented in Stable v0.1.10+)

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

### Dialer restart packet wakeup (Stable v0.1.12+)

An upstream wstunnel v11 UDP listener creates a WSS forwarding session only
when a UDP datagram arrives from its local kernel-WireGuard peer. After the
**dialer** helper is restarted externally, an otherwise idle WireGuard peer
may send nothing until the next configured keepalive. An observed v0.1.10
physical restart caused 30 missed half-second private probes (~15 seconds);
that measurement does not establish a universal delay or an STL defect.

A newly created managed Dial transient unit attaches a **bounded, best-effort**
`ExecStartPost` ICMP wakeup: eight small probes, 250 ms apart, with a
three-second hard wall-clock deadline (`ping -w 3`), bound to the
exact STL-owned WireGuard interface and sent only toward the selected private
peer Link Address. The command uses no shell, bearer, plaintext secret,
route change, kernel configuration change or continuous worker. The
ignore-failure prefix ensures an offline peer or missing `ping` executable
cannot make the WSS helper enter a restart loop. The authoritative health
check remains real private application traffic; a started helper or executed
probe never proves reconnection. The listener does not initiate this probe.

Unit readback must cross-check the legacy `ExecStartPost` and extended
`ExecStartPostEx` properties: complete path/argv, exactly `ignore-failure`
with no privileged, shell or environment-expansion modifiers. The main helper's
`ExecStartEx` must also have an empty execution-flag set. The same readback
checks that **all other executable service lifecycle hooks are unset**, including
Condition, StartPre, Reload, ReloadPost (where available), Stop and StopPost,
with their extended forms. A foreign hook cannot authorize managed Stop/Restart.
Verified legacy units with *both* post-start properties absent/empty remain
compatible; contradictory, partial or malformed command readback is foreign.
A rejected ownership gate that dispatches no `systemctl` restart must not
be treated as an ambiguous service mutation. Updating the STL binary alone cannot retrofit a
running legacy transient unit, and must not stop or replace it implicitly.
An owner-authorized, identity-checked helper refresh and real field measurement
are separate operational/acceptance gates. The reviewed source passed two
actual DE Dial helper-only restart trials on the original managed IR↔DE pair
([Issue #93](https://github.com/ach1992/simple-tun-link/issues/93#issuecomment-6454853897));
this does not prove every installation or reboot. No
zero-downtime claim or automatic Live-Link migration is implied.

### Ordinary committed WSS original-generation lifecycle (Stable v0.1.10+)

A committed WSS Link now durably records the **original host-kernel
Boot ID plus trusted source version** (`wss_kernel_boot_id`,
`wss_kernel_boot_source`) only when a NEW original WG generation was
actually created and verified during Ensure and the native host's initial
PID namespace and unshadowed procfs can be attested. A successful no-op
Ensure, or a sidecar-only repair with the original WG still visible, must
NEVER rewrite or retroactively promote a legacy/untrusted birth record,
even when today's host Boot ID is trusted. The result's `changed:false`
therefore never hides a promotion of future kernel-extinction authority.
In an untrusted container/unsupported host the fields remain absent. Such records are readable and an existing fully
attested visible original can still be managed, but a locally MISSING
original cannot authorize ordinary recreation/RestoreAll/Remove until an
independently verified generation transition is available.

Neither missing original WireGuard in the source namespace nor an absent
birthplace UDP socket (even with nft guard and helper externally deleted
BEFORE Remove) proves old-kernel extinction: a moved **DOWN** WG may remain
live in a second namespace and later reactivate. Ordinary committed Ensure,
RestoreAll and Remove therefore fail closed on a missing original unless
both the recorded and current kernel generations come from the trusted
host source and are DIFFERENT, and fresh strict global/current-namespace
vacancy proves no replacement, helper or guard is present. Same-boot and
legacy-unstamped cases retain the original Link, claims, private identities
and any existing guard without creating a journal or receipt.

A successful ordinary Remove may publish its fingerprint-bound receipt
ONLY after (a) deleting the exact nonce/ifindex original in that same
transaction or (b) proving trusted host-kernel generation extinction and
complete current-host vacancy. The versioned, durable receipt records
`wss_original_termination`: exact-ifindex deletion or trusted kernel
extinction (scoped crash compensation is a third, separately authenticated
recovery proof). Legacy WSS receipts without this field remain readable
but are INELIGIBLE for credential retirement, even when `wg`, `ss` and
nft inventory appear empty. Receipt-bound retirement rechecks the original
private files and host absence independently; root-level State tampering is
outside the declared privilege boundary. The kernel-generation witness
NEVER authorizes deleting an nft guard or unowned current-boot object.

Original-object crash compensation of a committed repair can delete the
original nonce-tagged WG while retaining its committed Link. This is not a
certificate that all possible hidden same-kernel generations are extinct;
without a trusted new host-kernel generation, subsequent ordinary RestoreAll
must refuse to recreate the WG even after its Crash Journal was safely
consumed. The disposable `committed-repair` E2E asserts this denial, while
fresh-Engine/FileStore unit tests prove the positive different-kernel case.

A genuine host reboot admits legitimate original-link RestoreAll only
when the preceding committed Link has valid recorded birth provenance,
the new Boot ID is independently trusted, and all conflicting current-
boot resources are absent. Deterministic Engine tests prove transitions;
rootless namespace tests deliberately cannot authenticate a physical reboot.
Host-local protected State/backups must not be copied to a different
still-active physical host and mistaken for proof the old kernel died.

A quarantined old WSS original must not become a global prohibition
on independently created Links. A NEW WSS Link with distinct Link ID,
fresh protected WG/WSS identities, distinct exclusive UDP/TCP/forward
ports, private Link addresses/subnet and per-Link host claims can use
the unchanged canonical Engine transaction and secure peer handoff
without a host reboot. Normal locks and committed/journal reservation
conflict checks still reject any reused original resources; the old
Link/journal and credentials remain untouched. The additive read-only
`plan-wss-replacement` CLI reports this operator workflow and
classifies uncommitted or committed crash journals, without attesting
hidden-original deletion or proving bilateral traffic. After an
independent WSS peer pair is committed and manually verified on both
hosts, `supersede-wss` requires explicit old-ID confirmation and
atomically marks the ORIGINAL committed State with a durable
`wss_superseded_by` successor ID. The original record, claims, boot
provenance, private issuance and any crash journal are retained.
The marker cannot be silently cleared or retargeted; subsequent
RestoreAll, RestorePersisted and ordinary Ensure fail/skip closed
rather than resurrecting the original in a new kernel generation.
The machine result reports `quarantined_old` and does not claim
a deleted original or verified peer traffic. Authorized original
compensation and receipt-bound retirement remain separate.
This does not create a second Link controller or auto-switch consumer
routes.

### R2 — durable WSS pre-effect crash quarantine (shipped in Stable v0.1.10+)

The canonical Engine prepares a secret-free `wss_crash_operations`
record in State v4, after final resource-lock admission and **before**
calling the WSS Backend Apply. It stores the endpoint-local public Link,
operation, random nonce, prior-commit flag, and complete planned resource
claims. This is a **reservation/quarantine**, not proof of nft/kernel/systemd
ownership and not authorization to delete a named object.

Journal publication and fsync must succeed before the first host effect.
In the current development candidate, the WSS journal writer also takes
the existing shared restore-persistence lock **after** maintenance, Link
and resource locks and holds it through durable State publication, just
like the source-only QUIC journal. This prevents last-Link Remove or
empty-State RestoreAll from deleting an existing owned reboot unit based
on a snapshot predating an unresolved WSS journal. The restore lock is
released before backend Apply; unrelated Links remain independent. This
synchronization correction is not part of the installed Stable v0.1.12.
Successful Ensure/Remove consumes the *exact* record in the same atomic
State commit as the Link change. Crash/failed compensation/unknown host
state retains the journal, blocks automatic Link replay and reserves
resources from other Links. Restore may continue independent,
non-conflicting Links; an empty State with a pending journal must not
remove the host restore unit.

`stl link reconcile-wss-vacant ID --confirm ID` is restricted to an
uncommitted initial Ensure. It locks the same resources and refreshes
the exact transaction but **cannot clear an uncertain original** using
only namespace-local absence. A transaction-scoped deletion witness or
trusted, explicitly armed cold-boot generation transition is required;
without one this read-only mode fails closed and preserves the journal.
It **never** modifies host objects, deletes secrets or adopts name-
matched objects.

A separately confirmed `stl link reconcile-wss-removed ID --confirm ID`
may finalize a committed Remove only with the exact original Link,
immutable owner claims, original credential fingerprints, intact pre-effect
journal AND positive original-generation termination evidence. Absence
of nft guard, kernel WG, loaded helper and original public key/listener
is necessary but never independently sufficient. An ordinary separate
process has lost any transaction-local original-index deletion witness;
this command therefore refuses source-local vacancy as retirement authority.
The Owner-gated armed cold-boot or verified `reconcile-wss-original`
compensation paths provide distinct positive recovery routes. No host
file/service/kernel resource is mutated by the read-only vacancy command;
`retire-wss` additionally checks the durable receipt's positive proof and
original file SHA-256 identities.

The Stable WSS recovery flow includes explicitly confirmed original-object
recovery without changing ordinary Link automatic replay:
- `reconcile-wss-repair-vacant` verifies the committed Link, original
  private-file contents, locked resource claims and complete host
  vacancy. Only its committed Ensure journal is consumed; desired State
  and original ownership remain intact. For LEGACY committed originals
  without trusted birth generation, journal-only repair vacancy cannot
  authorize a subsequent RestoreAll. It must keep the journal for the
  separately armed manual cold-boot route instead of silently clearing
  the only viable recovery checkpoint.
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
  retirement receipt; committed repair preserves its Link. When that
  committed original lacks trusted birth provenance, successful positive
  compensation MUST ALSO retain its ORIGINAL crash journal, never turn
  scoped deletion into a claim of full-kernel extinction, and never
  represent journal retention as a completed restore authorization.
  The CLI reports `journal_cleared:false` and
  `manual_cold_boot_required:true`. An independently trusted native
  host may later Arm that exact retained journal, obtain separate
  permission for a full-kernel reboot, and Reconcile into a one-use
  restore authority; untrusted/container origins cannot bypass this gate.

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
change before its atomic State transition. For a committed LEGACY
Ensure/repair lacking original birth provenance, the same atomic
transaction consumes the journal and issues a narrowly scoped
`wss_cold_boot_restore` proof containing the original attested Arm Boot
ID, verified reconciliation Boot ID and v1 source. It does NOT forge the
historical `wss_kernel_boot_*` fields or authorize ordinary Remove.
On a trusted later host generation, missing original WG and complete
current-host vacancy permit ONE new original creation through Engine
Ensure/RestoreAll. The proof is durably marked `spent` IN THE SAME
pre-effect transaction as its fresh crash journal, BEFORE Apply, so a
crash or namespace-migrated new WG cannot use it twice. Verified
successful recreation replaces the spent proof with an honestly
observed NEW original birth Boot ID. An interrupted attempt keeps its
journal and spent proof quarantined; a separately armed, approved
subsequent whole-host reboot is required before retrying the legacy
recovery route. The witness cannot be silently renewed by no-op Ensure,
ordinary reconciliation, local vacancy, or process/container restart.
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

For reproducible **36-scenario rootless real-kernel acceptance** on a
disposable amd64 Linux test host with the pinned local fixture already
prepared, run `bash scripts/e2e/wss-managed-wireguard-matrix.sh` from
a clean exact-HEAD checkout as an unprivileged user. It builds the
current tagged test CLI, serially reuses the existing locked namespace
harness, records per-case ignored local logs and prints exact HEAD/TREE.
This is an **opt-in acceptance script**, not a post-install action,
CI requirement or permission to change a physical production host.
The existing fixture/prerequisite admission still applies.

The two R9 cases extend the earlier 33-case suite with the actual
**no-reboot independent replacement** lifecycle: original WSS peer pair,
a simultaneously healthy unrelated STL-managed WSS peer pair, original
WireGuard moved **DOWN** into another isolated namespace while its
committed State, old ingress guard and protected credentials survive, and
denied reuse of its UDP reservation. They create an entirely new
per-Link WSS pair with fresh key and CA issuance and disjoint addresses
and ports. The success case proves genuine bilateral private-IP ICMP/UDP
traffic before separately invoking `supersede-wss` on both endpoints,
then checks old Ensure/status/credential retirement denial, independent
Restore, healthy sibling traffic and exact original resource retention.
The failure case injects an error **after new real helper/WG/guard Apply**,
retains its crash journal, and proves this failed new attempt cannot
supersede the protected old WSS original. The extension also requires
strict host-wide firewall admission of other **fully State-owned,
nonce-verified exact per-Link nft guards**: a foreign, modified or
unclaimed pre-guard hook still fails closed. These are disposable Linux
kernel tests with a systemd **shim**, not physical reboot, field two-host
acceptance, ARM64 WSS dataplane acceptance or automatic failover.

The R10 additional case exercises a **real original pre-commit WG crash**
where the old journal, original kernel WG and nonce-tagged nft guard remain
without any committed old Link. Only a byte-exact verified original journal
and structurally exact DROP-only old guard can coexist with a newly issued,
disjoint WSS peer pair. The new pair carries genuine ICMP and UDP traffic
without clearing the old crash journal/credentials/guard, adopting a foreign
host object, manufacturing a committed old Link or superseding an uncommitted
original. Host-wide firewall filtering never treats journal reservation or
table name by itself as deletion/ownership authority.

The rootless test `STL_WSS_R2_CRASH_TEST=1 bash
scripts/e2e/wss-managed-wireguard-r1.sh` sends SIGKILL after a
**real** nft guard creation and before Go State commit. It proves
durable journal reservation and fail-closed rejection of a guard-only
Crash without an original-kernel deletion witness; it does **not**
claim successful vacancy-only reconciliation or credential retry.
The same harness exercises original tagged partial WG compensation,
end-to-end genuine ICMP/TCP/UDP over WSS in normal Create/Remove,
and migrated WG objects both UP and DOWN via
`STL_WSS_R5_MIGRATED_WG_TEST=active|down` **with** the independently
fenced `STL_WSS_R2_REMOVE_CRASH_TEST=stop`: these R5 scenarios first
create a genuine, fsynced original Remove Crash Journal while the WG
is still visible, then move the surviving original across namespaces.
No synthetic/malformed journal is manufactured for their positive
quarantine checks. Neither namespace-local absence nor temporarily
missing UDP socket alone can retire an nft ingress guard or original
WSS credentials. Two
additional test cases move the committed original WG DOWN before any
ordinary operation, with its helper/guard respectively active or removed
externally before the first Remove. Ordinary Ensure/RestoreAll/Remove/
credential retirement all deny, leaving committed State, original
reservations, private identity and surviving migrated WG unchanged.
The harness uses disposable rootless kernel WireGuard+nft with a
systemd **shim**, not real PID1 reboot or physical two-host recovery.
