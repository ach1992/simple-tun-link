# ADR-0005: IPsec uses per-Link VICI calls; no global strongSwan reload

- Status: Accepted for the IPsec implementation boundary
- Date: 2026-10-10
- Controlling acceptance: Issue #7

**Current implementation checkpoint (2026-10-12):** The following
"source-only" and "future" sections document the historical safety work
that preceded the new conditional native-exclusive operational backend.
Those sections are not assertions that the current candidate remains
unregistered. The implementation is now integrated into the canonical
Engine/CLI on **attested, STL-owned native strongSwan service runtimes**,
with real isolated ESP/NAT-T, systemd restart/restore, scoped XFRM/VICI
ownership, durable uncertain-operation journals and receipt-bound
post-Remove protected PSK retirement. Ordinary runtime assembly still
does not install or start services or adopt foreign state. The acceptance
proof and unverified release/production boundaries are in
[IPsec real E2E](../operations/IPSEC-REAL-E2E.md).

## Context

The accepted v0.1 backend uses strongSwan/IKEv2 and Linux XFRM
interfaces with distinct Link identity, policy and credential ownership.
A host may run other users' independent strongSwan connections.

The ordinary swanctl --load-conns --file <single-Link-file> workflow is not
a per-connection load: upstream load_conns_cfg unloads daemon connections
missing from the file. Similarly, swanctl --load-creds reconciles and may
unload shared credentials missing from new input without a global --clear.
Those bulk operations must not be used for STL.

## Decision

1. Use strongSwan's VICI Unix-domain control interface, with a dedicated,
   reviewed Go client. The vendor-maintained MIT-licensed govici library
   supplies protocol framing; STL must not construct ad-hoc VICI wire bytes.
2. Only narrow load-conn / unload-conn and load-shared /
   unload-shared calls may eventually be used for one specific Link.
   Global load-conns, load-creds, clear-creds, daemon-wide
   reload/flush/restart and wildcard removal are prohibited.
3. Derive the same deterministic connection/child/shared-key and nonzero
   XFRM interface identities from the full canonical 128-bit Link ID.
   The XFRM ID is a 32-bit non-secret collision identity, NOT evidence of
   ownership; Engine claims and host inspection must reject accidental
   hash/interface truncation collisions.
4. Never replace an existing matching-name daemon object just because its
   name appears STL-shaped. The backend must establish durable, exclusive
   canonical Engine ownership and re-inspect after resource locks before
   any write/unload. A VICI response alone is not sufficient ownership proof.
5. Keep PSK material only in protected, descriptor-verified per-Link
   credentials and deliberately SENSITIVE Quick Link operations. Generate
   a fresh 256-bit PSK by default; never encode it in ordinary Link JSON,
   VICI inventory, status, diagnostics, stdout, logs or errors.
6. Scope child selectors to exact /32 Link Addresses on both peers and
   scope IKE endpoints/identities to the Link. Prefer ESP normally;
   force NAT-T encapsulation only when requested. Never negotiate
   0.0.0.0/0 as an implicit convenience.
7. Startup, rollback, unload, SA termination and credential retirement
   require independently verified owner-only effects and failure receipts.
   The preliminary reader/profile module intentionally enables no
   production mutation or new CLI option until those gates and real
   disposable IKEv2 traffic tests exist.

## Evidence and limitations

Official strongSwan VICI API documents per-object load-conn,
unload-conn, load-shared, unload-shared, get-conns, and get-shared.
govici has its own protocol implementation and MIT license.

References:
- https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadConns.html
- https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadCreds.html
- https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html
- https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md
- https://github.com/strongswan/govici

The initial PR proves only public identity/profile formation, read-only
VICI inventory handling and fail-closed unit behavior. It is not an IPsec
dataplane, IKEv2/ESP/NAT-T, secret-storage, restart, or release acceptance.
Issues #7 and #12 remain OPEN.

The follow-up protected-PSK storage milestone introduces a dedicated
no-replace, owner-private per-Link credential store with secret-redacted
values and a shared audited directory traversal guard used by WireGuard.
It deliberately performs NO VICI/Engine mutation, recipient import, credential
retirement, real IKEv2/ESP traffic or release acceptance. Engine ownership
and lifecycle proof remain mandatory before using the stored key operationally.
Issues #7 and #12 remain OPEN.


## Protected credential staging follow-up

Before any owner-verified operational VICI/XFRM change, the Engine
may stage an IPsec Quick Link and per-Link PSK through the canonical
maintenance -> Link -> resource lock order. The ordinary state stores
only the full public pending Link, endpoint role, and (for the sender)
the digest of the exact SENSITIVE v2 handoff; never the PSK or URL.
A missing public intent never grants permission to adopt an orphan PSK
with a matching filename. Sender pending state records offer.Link()
(creator-local orientation), not the recipient-facing Preview.Link.
Recipient state records offer.ReceiverLink() (exact opposite orientation).
Exact retry may continue a previously durable pending intent only after
verifying the *existing* protected PSK with a constant-time equality
check; missing material fails closed and is never silently recreated.

For backward compatibility, previously exported v2 IPsec Quick Links
with PSKs other than 32 bytes remain previewable but cannot be staged
or activated. This deliberately does not change the existing v2
pairing schema or imply silent migration/rekey authorization.

Staging alone authorizes no connection load/unload, SA termination,
Linux network change, operational claim, or public release.

## Read-only activation vacancy checkpoint

A follow-up source-only preflight requires exact durable staged public
identity and a protected PSK under canonical Engine locks, then refuses
existing same-name strongSwan connection/PSK objects, XFRM interfaces with
colliding names/32-bit IDs, and orphaned policies/SAs with matching if_id.
XFRM inspection accepts only verified JSON rows with unique relevant field
identities, complete policy/SA endpoints and valid `dir` / `proto`, or
semantically verified legacy iproute2 text with complete headers and valid
descriptor values. The Linux link inventory must also reject duplicate or
case-ambiguous ifname/linkinfo/info_kind/info_data/if_id identities at each
relevant nesting level and reject those identities if placed at the wrong
nesting level (even when an unrelated value might otherwise appear vacant).
A state selector's proto is not a second SA proto; only structurally located
top-level descriptor lines establish SA identity. Do not skip the selector
tail: parse recognized iproute2 protocol, sport/dport, ICMP type/code, GRE
key, dev and optional uid fields with bounded values; unknown, duplicate,
malformed, or misplaced if_id tokens must fail closed. Follow the actual
iproute2 output contract: decimal numbers have canonical formatting;
ICMP type/code are uint8 rather than uint16; an MH `(dport)` value has the
fixed-width lowercase `0x` plus four hex digits; foreign `dev` names follow
Linux `dev_valid_name` rather than STL's planned-interface alphabet.
Legacy iproute2 text parsing and successful-empty inventory checks must
use ASCII structural whitespace byte-by-byte, not Unicode-aware token
splitting/trimming: preserve non-ASCII bytes verbatim for the kernel
device-name check, rejecting `0xa0` while retaining Linux-valid sequences
like UTF-8 `c2 85`. Unicode-only nonempty inventory never means vacancy.
Selector protocol names derive from the file-backed host `/etc/protocols`
primary names as used by default Debian/Ubuntu iproute2/libc, not a static
IANA subset; unknown/unreadable names or ambiguous tables fail closed.
Non-file NSS overrides are not assumed equivalent without host evidence.
This scoped selector grammar follows the iproute2 source:
https://github.com/iproute2/iproute2/blob/e11870d5b9414b2e0770463bd6fc2399744dc734/ip/ipxfrm.c
and preserves the bounded Debian-bookworm text path. An absent `if_id` is harmless only after the row is
positively recognized; a null, conflicting or invalid present ID is unknown.
Never accept an inventory probe failure as evidence of vacancy. Kernel state
and temporary decoded JSON copies are sensitive and must be cleared, never
included in errors or logs.

The connection-name vacancy gate must check **both** VICI-exclusive
`get-conns` and the daemon-wide `list-conns` streamed `list-conn`
events filtered to the exact canonical IKE connection name. strongSwan
documents that `get-conns` excludes configurations loaded by non-VICI
backends, while `load-conn` updates/replaces a same-name connection.
The full filtered stream must be exhausted successfully; malformed,
duplicate, unexpected or interrupted events mean unknown vacancy, never
permission to overwrite a foreign config. A filtered stream is a
read-only collision check, NOT owner proof or a transaction with other
strongSwan writers. Source: the upstream VICI protocol README
(https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md).

## Host NSS protocol-name gate (non-operational)

Legacy iproute2 XFRM selector text prints the primary protocol name
returned by glibc `getprotobynumber()`, not necessarily the first name
in `/etc/protocols` when non-file NSS providers are configured.
For each named selector, first resolve the bounded file-backed primary
and then verify exact agreement with a read-only, absolute-path
`/usr/bin/getent protocols <decimal-ID>` NSS lookup. GNU getent passes
numeric protocol keys to the same libc function used by distro iproute2.
The call has a short deadline and bounded output; a per-inventory cache
and overall lookup budget avoid repeated unbounded slow-provider calls.
Disagreement, unsupported/missing NSS tooling, malformed reply and
timeouts fail closed. This preserves the supported `db files` Debian
configuration when its effective mappings agree, while refusing false
vacancy from custom non-file providers. A custom primary absent from
`/etc/protocols` remains unsupported until an independently reviewed
full-NSS resolver is added. No writer, system-wide NSS change or
activation permit is introduced.

References:
- https://man7.org/linux/man-pages/man1/getent.1.html
- https://man7.org/linux/man-pages/man3/getprotoent.3.html

A successful preflight is NOT persistent ownership proof, a reservation
against other administrators or a VICI/XFRM write permit. Any future
transaction must repeat fresh host checks while holding STL locks and prove
STL-owned effects with receipts/host identity before repair, rollback, unload
or credential retirement. In particular, public PendingIPsec and derived
VICI names alone NEVER authorize destruction of an existing daemon object.
No production runtime registration, VICI or kernel mutation is enabled by
this checkpoint. Issue #7 retains the operational backend and backend-focus
IKEv2/ESP/NAT-T acceptance; Issue #12 retains release-wide E2E.

## Durable VICI preparation and issuing journal (source-only milestone)

A follow-up, deliberately **unregistered** Engine pathway introduces a
public-only, durable per-Link VICI *operation journal*, with a random
nonzero transaction nonce and the **exact complete staged public intent**
(sender/recipient identity and sender handoff digest included). Its phases
are `prepared`, `issuing-shared`, `shared-observed`,
`issuing-connection`, and `connection-observed`. Every transition is
validated against the unchanged canonical PendingIPsec state; malformed,
orphaned and duplicate transaction records fail closed at state load.

`PrepareIPsecVICI` rechecks durable pending intent, protected PSK and the
complete daemon/XFRM collision surfaces under the canonical maintenance,
Link and resource locks, then durably records `prepared` without affecting
the daemon. **No real VICI effectful writer, constructor, production
Apply method or daemon-send path exists in this milestone.** The
`simulatePreparedIPsecVICI` method is defined **exclusively in a Go
`_test.go` file**: it passes fakes through the Engine-locked flow to
verify that pre-effect `issuing-*` phases, readbacks, interruptions,
missing acknowledgements and cross-phase drift fail closed. Those
tests do **not** constitute proof of actual strongSwan writes.

**Critical no-clobber constraint:** upstream strongSwan's
`load-shared` replaces an existing key with the same unique identifier,
and `load-conn` updates/replaces a connection with the same name.
A foreign VICI writer may insert the object after even the most recent
read-only vacancy check and before an STL effect. STL's maintenance,
Link and resource locks do not serialize non-STL daemon clients. **No
extra read-before-write inspection can make these operations atomic.**
Because neither an atomic load-if-absent nor another independently
proven exclusive daemon namespace exists in the accepted implementation,
the real writer is intentionally absent. Before operational activation,
select and verify an exclusive no-clobber ownership mechanism or a
security-reviewed isolated-daemon architecture and record any owner-level
decision. Neither a journal nonce nor a matching name is owner proof.

The journal reserves explicit phases: `prepared`, `issuing-shared`,
`shared-observed`, `issuing-connection`, and
`connection-observed`. In production currently only `prepared`
can be generated by the Engine. The remaining transitions are available
to the test-only simulation, which enforces adjacent-only transitions
and exact unchanged PendingIPsec binding. Every journal state that
could describe an interrupted future effect is non-authoritative and
requires explicit reconciliation; no automatic recovery or operational
Link commit is claimed.

**Forward/backward state compatibility:** This source-only milestone
adds the optional `ipsec_vici_operations` member under state schema
v2. The current reader accepts older v2 state with no member, but an
older binary with `DisallowUnknownFields` will reject a non-empty
journal-bearing v2 state. Until production activation, no standard
CLI/backend creates this journal; downgrade after a journal-bearing
state has been created is **not supported**. Before production
registration, choose an explicit schema migration/version bump or a
documented upgrade-only policy with automated compatibility tests.
No backward-reader compatibility is inferred from an unchanged version
number.

## strongSwan debug logging remains an activation blocker

Some strongSwan versions (verified in upstream `vici_cred.c` at
[5.9.5](https://github.com/strongswan/strongswan/blob/5.9.5/src/libcharon/plugins/vici/vici_cred.c)
and [6.0.0](https://github.com/strongswan/strongswan/blob/6.0.0/src/libcharon/plugins/vici/vici_cred.c))
have a CFG level-4 debug trace that formats the *raw* shared IKE key
(`DBG4(DBG_CFG, "key: %#B", &data)`). That exact trace was absent from
the checked upstream 5.9.1 source. Hiding plaintext from STL's own stdout/status
is therefore insufficient if the independently configured daemon uses
verbose CFG logging. Prior to production registration, the activation
contract must verify the effective strongSwan log configuration and
fail closed if it may emit PSK material; do not globally reconfigure an
unrelated administrator's daemon as a convenience. No production
writer exists at this checkpoint, so this mandatory future
activation prerequisite is **not satisfied**.

## XFRM interface alias is not atomic at creation

An isolated Debian 13 / Linux 6.12 disposable **network namespace** probe
with iproute2 6.15 showed that `ip link add name ... alias ... type xfrm
if_id ...` did not yield an `ifalias` in `ip -details -json link show`;
only a separate `ip link set dev ... alias ...` produced the alias.
This probe created/deleted only temporary test-namespace resources. A
future XFRM creation transaction therefore must first persist an uncertain
*pre-effect* phase and prove the actual STL-created kernel interface
identity, preserving the original ifindex/ownership evidence across the
non-atomic alias step. An alias on a restarted process is not sufficient
proof and an interrupted create must not blindly delete by derived name.

## Owner decision (2026-10-11): portable native-exclusive v0.1 runtime

The Owner accepted **one shared IPsec control-plane implementation** with
small, capability-selected Linux packaging/service adapters, not separate
IPsec engines for Debian/Ubuntu and not a mandatory privileged container or
network namespace. The first operational profile will have **one STL-owned
strongSwan daemon per host**, not per Link, with an STL-owned VICI/config/
credential boundary and standard IKE/NAT-T UDP 500/4500, reusing current
Link/Quick Link identity without adding remote IKE port fields.

This is an **operational target, not an implemented/verified feature**.
Before even attempting a daemon start, key transfer, VICI load or XFRM
mutation, separately prove exclusive configuration/service/socket/port
ownership, effective secure logging policy, controlled package install
behavior and durable owner-only kernel interface/SA/policy identity. Process
absence or an STL-shaped name/nonce is insufficient. No untrusted external
strongSwan service may be stopped, adopted, reloaded, or modified.

A preexisting or uncertain strongSwan owner, IKE port conflict, suspicious
configuration, ambiguous host identity or missing capability **disables only
IPsec** and returns a stable reason plus actionable operator guidance; GRE,
IPIP and WireGuard remain usable. The accepted v0.1 architecture does not
promise simultaneous foreign strongSwan coexistence. A separate isolated
runtime may be designed later after proven need and reviewed distro/version
compatibility. Extra read-before-write probes on a shared daemon remain
**explicitly rejected** as a substitute for ownership.

The project-wide observability contract in docs/ARCHITECTURE.md applies to
this backend: secure reason codes, operator next steps, bounded correlation,
read-only doctor, no sensitive daemon stderr/VICI payloads, and no CFG DBG4
raw PSK logs even during troubleshooting. Existing source-only journal and
no-effectful-writer constraints remain until the operational security and
real IKEv2/ESP/NAT-T E2E gates pass. Issues #7 and #12 stay OPEN.


## Source-only native configuration and IKE port observations (2026-10-11)

The next bounded source milestone creates a proposed `charon-systemd`
strongSwan configuration with an STL-private VICI Unix socket, no
external configuration includes, journald `default=1` / `cfg=1`
to prevent DBG4 PSK disclosure, and no daemon-managed route/virtual
IP changes. The config guard checks exact local bytes only. The
operational adapter must still pin a trusted root-owned inode/parent
chain, control `STRONGSWAN_CONF`, prove the active daemon's effective
configuration/logger state and exclusively restrict VICI and
`reload-settings` writers before loading any secret.

## Protected local native-config inspection (source-only follow-up)

`InspectNativeExclusiveConfig` is a read-only prerequisite for the
native-exclusive `strongswan.conf`: the exact reviewed local bytes, a
root-owned 0600 single-link regular file, root-owned non-symlinked
non-writable ancestors and root-private state/IPsec directories. It opens
each directory and the final file via pinned, non-following descriptors,
bounds content reads, and revalidates the file and each directory entry
against the opened inode after inspection. Replaced paths, changed
content/CFG level, hardlinks and ambiguous reads fail closed.
`stl doctor ipsec` exposes a stable additive `native_config` check.

This is **byte/path attestation only**, not affirmative STL-origin
ownership, durable publication, service/package adoption, process
`STRONGSWAN_CONF` selection, effective logger safety, a persistent
no-clobber lock or permission to load a secret. A foreign administrator
can supply byte-identical content, and a root actor can change the path
after the observation. Future service provisioning therefore needs an
origin-bound durable receipt/transaction with root-private atomic
publication and recovery, plus exact active executable/service/process
identity, effective logging, VICI authorization and kernel owner gates.
No effectful service or VICI writer has been added; Issues #7/#12 remain
OPEN. This adds a preflight observation, not a new owner-level decision.

## Prepared no-clobber native file publication and provenance checkpoint

A source-only, unexported filesystem primitive now stages the **exact**
reviewed `strongswan.conf` into a private, root-only future state path.
The algorithm writes/fsyncs a unique 128-bit origin-token xattr on the
original config inode, durably publishes a versioned 0600 receipt binding
nonce + device/inode + fixed config SHA-256 **before** the canonical effect,
then uses `renameat2(RENAME_NOREPLACE)` and parent `fsync`. Unsupported
user xattrs, no-replace semantics or fsync fail closed; a preexisting
canonical config is never replaced, even with identical bytes. Prepared
receipt without matching config, interrupted publication, receipt/xattr
replacement, changed paths and altered bytes require explicit operator
reconciliation. No blind rollback/automatic recovery or adoption exists.

`stl doctor ipsec` now also exposes additive, **read-only**
`native_config_origin` classifications, opening both receipt and config
under non-following pinned private directories and validating the original
inode, receipt/xattr token and canonical content. This provides bounded
STL-origin **publication evidence**, not an unforgeable credential against
arbitrary root writers. Even a positive receipt snapshot cannot prove
service/package/process ownership, `STRONGSWAN_CONF` selection, effective
CFG logging, VICI writer isolation, stable UDP 500/4500 ownership or XFRM
resources. There is deliberately **no production call site** for the
config writer and no service/VICI/kernel effect. This new code does not
expand acceptance or re-authorize any rejected unsafe daemon operation;
operational gates in Issue #7 and traffic gates in #12 remain OPEN.

The observational `stl doctor ipsec` now detects currently bound
UDP 500/4500 sockets via bounded, strictly parsed procfs IPv4/IPv6
tables from its own network namespace, with stable `blocked`,
`observed` and `unknown` reasons. A missing `udp6` table or partial
parse is unknown, and any non-observation remains only a dated
observation, never ownership or a bind reservation. No package scripts,
systemctl calls, daemon writes, VICI calls or network changes have been
introduced. Source tests and nonprivileged host inspection are
not a substitute for strongSwan 5.9/6.x, kernel, systemd, multi-Link,
IKEv2/ESP/NAT-T privileged acceptance under #7/#12.

## Proposed STL-specific systemd unit (source-only admission slice)

`NativeExclusiveServiceUnitV1()` now defines a reviewable, uninstalled
`/etc/systemd/system/simple-tun-link-ipsec.service` with
`Type=notify`, the proposed `/usr/sbin/charon-systemd`, an explicit
`STRONGSWAN_CONF` path, private runtime directory/UMask and **no** automatic
`ExecStartPost=swanctl --load-all`, reload action, installer enablement or
restart policy. Upstream `strongswan.service` has `ExecStartPost=... --load-all`
and `ExecReload=...`; blindly reusing it would violate exclusive VICI and
per-Link credential control. An additive read-only `native_service_unit`
doctor observation checks reviewed local bytes and protected pinned inode/path,
not STL origin or effective systemd state. This earlier slice contained
no unit publisher, installer, Engine/CLI activation or host service effects;
the follow-up below introduces a fixture-only publication primitive.

**Remaining operational gate:** wire a reviewed no-clobber STL-origin
publisher behind independently verified host admission and lifetime locks;
inspect loaded systemd properties and all drop-ins/generators and aliases;
attest the exact executable, process and `STRONGSWAN_CONF` selection; prove
secure effective journal/CFG logging and VICI writer confinement; assess
distribution package install/remove scripts and their automatic service
behavior before touching the host. A package-managed unit's mere presence
must not be mistaken for an STL-owned private daemon, and the current
`strongswan_service` inventory check intentionally blocks on that identity.
The proposed source profile is not ready to be installed or started.

## No-clobber service-unit origin transaction (source-only)

A follow-up adds an **unexported, uncalled in production** unit publisher
and a separate read-only origin diagnostic. Publication binds a new 0600
unit inode under the protected /etc/systemd/system directory to a fresh
nonzero inode-xattr token and root-private versioned receipt stored in the
existing STL IPsec state directory. The receipt is fsynced and committed
before renameat2(RENAME_NOREPLACE) exposes the canonical systemd unit
name; the relevant parent directories are synced. EEXIST, symlinks,
untrusted ancestry, absent xattrs, unsupported atomics, prepared-only
receipts, tampered unit bytes, replaced inodes, unsafe permissions and
ambiguous crashes never authorize overwrite, replay or adoption.
The stage inode's contents and xattr are fsynced and its identity
validated; critically, **its containing systemd directory is also fsynced
before any pre-receipt crash point or receipt creation**. Then the receipt
is fsynced, atomically published and its directory fsynced before the
canonical no-replace rename; the systemd directory is fsynced once more
after canonical publication. Two fixed, non-service staging names make
a pre-receipt interruption discoverable when all preceding durability
operations have succeeded and the filesystem honors those operations:
their continued presence blocks publication and even read-only
missing/vacancy classification until manual reconciliation. Any failed
required file/directory fsync leaves persistence uncertain and fails closed;
an on-disk fixture is not proof of power-loss recovery on all filesystems.

The additive tenth stl doctor ipsec check native_service_unit_origin
reports a verified receipt snapshot but never proves PID 1 loaded the
profile, the actual ExecStart/Environment, package provenance, secure
logging or exclusive VICI/port/XFRM rights. There is still **no** installer,
systemctl start/enable/reload action, package mutation, VICI writer, Engine
operational adapter or credential/SA lifecycle. No host root-level
publication test has yet been run. Those operational gates remain OPEN
under Issue #7, as does release E2E Issue #12. The prior paragraph's
“no unit publisher” refers to its earlier reviewed PR; this primitive
is strictly test-only and cannot install or activate the service.

Source references for configuration and logging:
- https://github.com/strongswan/strongswan/blob/master/init/systemd/strongswan.service.in
- https://docs.strongswan.org/docs/6.0/install/install.html
- https://docs.strongswan.org/docs/5.9/config/strongswanConf.html
- https://docs.strongswan.org/docs/latest/daemons/charon-systemd.html
- https://docs.strongswan.org/docs/latest/config/logging.html
- https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/vici_cred.c

## R1/R2 correction: non-loading systemd inventory and bounded capture

The original `systemctl show UNIT` implementation was rejected: upstream
systemd may resolve the unit object by loading an absent unit into PID 1,
so the resulting `LoadState=loaded` could be induced by the diagnosis
itself. The corrected **source-only** probe uses only `systemctl list-units
--all` with a fixed glob, which queries the existing in-memory unit list.
No second unit-object query is permitted: if the unit unloads between
steps, `show UNIT` could load it again. Empty list results mean only
no matching primary unit *at that instant* and block. Failed/masked
loaded entries block; canonical loaded entries remain **unknown**, not
`observed`, because the list cannot attest actual aliases, fragment,
generator, drop-ins, loaded-vs-disk drift, transient property, pending
reload, ExecStart/Environment or other effective settings. The existing
on-disk origin receipt checks also cannot prove PID 1's loaded
configuration. Safe fuller effective inspection is still a prerequisite
for operational IPsec, not a reason to weaken this diagnostic.

The `linux.BoundedRunner` stream primitive enforces separate 16 KiB
stdout and 1 KiB stderr ceilings **while the subprocess writes**. Overflow
cancels execution and returns an untrusted-output-free error; the diagnostic
fails closed if this bounded primitive is unavailable, instead of using
the old unbounded `bytes.Buffer` and a post-capture parser limit. Parser,
capture, and exact CLI safeguards have tests; no privileged systemd
service/daemon activation test is claimed. This is an implementation
correction within the accepted owner architecture and leaves Issue #7/#12
and `activation_allowed=false` unchanged.

Systemd behavior/source references:
- https://manpages.debian.org/bullseye/systemd/systemctl.1.en.html
- https://manpages.debian.org/bullseye/systemd/systemd.1.en.html
- https://github.com/systemd/systemd/blob/v247/src/core/dbus-manager.c
- https://www.freedesktop.org/wiki/Software/systemd/dbus/

## Issue #7 accepted operational implementation: crash-safe XFRM and scoped Remove (2026-10-12)

Historical sections above record earlier *source-only* milestones; their
statements that no effectful IPsec runtime existed apply to the respective
milestones, not the present candidate. Runtime activation remains conditional
on successful native-exclusive admission and externally provisioned STL-owned
service/config, without ever stopping/adopting a foreign daemon.

The operational Engine persists its public-only `ipsec_xfrm_operations`
before kernel interface creation. After a successful create it must durably
bind the original ifindex **before** setting the non-atomic alias and then
record alias/configuration completion. An `issuing-create` checkpoint with
no persisted original ifindex confers NO deletion authority, even if a
matching interface name and `if_id` are visible. The explicit
`reconcile-xfrm-ipsec` operation may abort only a durable, exact-owned
device while VICI issuance is still in its prepared stage; unknown
pre-index collision requires operator verification, not blind cleanup.

Per-Link Remove persists `ipsec_remove_operations` before effectful
SA/VICI/kernel teardown. Only adjacent, durable progress through SA
termination, exact connection unload, exact shared-key unload and verified
original-ifindex deletion allows canonical state commit. An uncertain
completion preserves the journal and original committed ownership, blocks
ordinary reapply and supports **explicit** `reconcile-ipsec` with fresh
native/VICI/XFRM validation and sibling isolation. No command performs
wildcard daemon unload or foreign resource adoption. After atomic Link
removal and non-secret digest receipt commit, `retire-ipsec` verifies
that receipt under maintenance+Link locks and safely retires matching
root-private PSK **without requiring a live strongSwan service**.

Native daemon executable trust now also demands root UID, regular file,
root-controlled non-writable path ancestry and original active-PID inode
identity. These gates complement private VICI/SO_PEERCRED, IKE port,
configuration origin and logger policy, not replace them. They are
time-local observations, not an absolute defense against independent
privileged root administrators.

No state/ordinary CLI version bump is made: private state stays schema v2
with additional optional operation journals, public machine JSON remains
schema_version 1. Journal-bearing state is **upgrade-only** until resolved;
legacy schema-v1 lifecycle fields, including post-Remove IPsec receipts,
fail closed on migration. Wider distribution/package/reboot/arm64 release
validation still belongs to Issues #11/#12.
