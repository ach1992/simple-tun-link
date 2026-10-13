# Security Model

## Security is backend-specific

The Link abstraction does not imply encryption.

- GRE/IPIP, including FOU/GUE encapsulation, do not provide confidentiality or peer authentication by themselves.
- GRE keys are identifiers, not cryptographic secrets.
- WireGuard provides encrypted/authenticated transport when configured correctly.
- IPsec/XFRM provides encrypted/authenticated transport when configured correctly.

The UI and JSON status must not label plaintext backends as secure merely because a key/encapsulation exists.

## No “undetectable” guarantee

The project may support transports that work across different network conditions, but it must not claim any backend is undetectable or guaranteed to bypass a censor/filter. Encryption and traffic distinguishability are different properties.

## Secrets

Never expose secrets through ordinary observability or machine-status surfaces:
- WireGuard private keys;
- IPsec PSKs/private keys;
- future bearer credentials;
- SSH credentials.

Rules:
- redact secrets from logs/status/diagnostic bundles/generic JSON;
- restrictive file modes for persisted secret state;
- a v0.1 Quick Link is an explicit, deliberate exception for pairing transport and may contain receiver credentials;
- secret-bearing setup links/configuration blocks are explicitly marked **SENSITIVE**;
- import preview shows secret presence, not the secret value;
- do not automatically write secret-bearing payloads to logs, shell history, diagnostic bundles, or world-readable files;
- when STL itself writes a secret-bearing export file, use restrictive permissions;
- after generating a WireGuard peer keypair for Quick Link, the initiator persists only the peer public key and must not retain the peer private key in ordinary state.

### WireGuard key-material boundary

The WireGuard adapter under `internal/backend/wireguard` supports a
credential-protected, Engine-owned per-Link interface lifecycle and v3
receiver import. Focused privileged traffic has been demonstrated in a
disposable environment, but the backend is **not yet release-qualified**.
It uses Go's standard X25519 implementation and clamped
`wg genkey`-compatible output. Generic JSON and
formatting do not serialize private bytes; deliberate `SecretWireValue()`
access is reserved for credential-specific pairing/file operations, never
status, diagnostics or normal desired-state storage.

`KeyStore` places a private key in a dedicated per-Link file under the
STL state root's private `credentials/` directory. It requires owner-private
directories, rejects symlink traversal, reads only a same-owner singly-linked
regular file with mode `0600`, and publishes a synced temporary key file with
an atomic **no-replace** hard link followed by directory sync. Concurrent
new-key writes for one Link must not overwrite one another. Publication
uncertainty must be reconciled rather than blindly deleting an existing key.
The store intentionally has no generic update/remove API. A verified,
read-only FD can be inherited by `wg set private-key /proc/self/fd/3`
without exposing the private key in argv, shell history, generic status or
normal JSON. `EnsureRecipient` is replay-safe only for an identical key.
Failed/uncertain activation preserves protected credentials for safe retry;
interface removal does not silently destroy a private key. Before a
**destructive** WireGuard Remove, the Engine-held validation and the immediate
Apply preflight both require a protected, safely readable private credential
whose public identity matches the persisted Link. Missing, permission-drifted,
or mismatched credentials refuse deletion of both the interface and firewall,
so an uncommitted Remove can still reconstruct the original owned state.
An explicit, identity-bound credential retirement action is available only
after a **specific durable successful canonical Remove receipt** for the
Link ID, WireGuard backend and exact local public identity, plus read-only
live host absence checks under the Engine Link lock. An unrelated committed
state file is never sufficient; indeterminate Remove and failed first Ensure
never issue retirement authorization. On a new Ensure attempt for the same
ID, any old receipt is invalidated *before* staging/Apply. Successful key
retirement marks the exact receipt retired as a durable idempotency witness;
normal Remove still preserves the key for rollback. A missing/unsafe file,
missing proof or live STL-owned resource refuses retirement. Safe
retirement is not secure physical-media erasure, and unexpected external
privileged filesystem changes still require operator reconciliation.

The caller must store the **local** private key only at its owning endpoint.
The initiator must never persist a generated *recipient* private key as local
state; that material belongs only in the explicitly SENSITIVE Quick Link
until protected receiver-side import.
Sender Create stages its **own** protected private key and a no-secret,
SHA-256-bound public `pending_senders` reservation in ordinary state **before**
allowing the recipient handoff to become visible. A successful canonical
Engine state commit consumes Pending atomically while publishing the Link.
After incomplete creation, exact Resume checks every field and the original
full payload digest, not just the sender's public key. An untrusted modified
and rechecksummed offer cannot become the original pending sender Link.
The pending record is public configuration, not a backup of either private
key; loss of a receiver handoff before publication requires explicit orphan
reconciliation rather than silent rekeying.
For hard-crash handoff temporaries, `link recover-handoff`
accepts only a verified intact original same-owner `0600` staging inode
under an owner-private `0700` directory, proves exact pending sender
intent/digest and matching protected local key under canonical Engine locks,
and publishes via same-directory, no-clobber rename with file/parent fsync.
Both WireGuard and IPsec sender credentials are supported; recipient-origin
IPsec staging and already-committed links do not grant recovery authority.
Unsafe, lost, mismatched or orphaned material remains preserved and
requires deliberate manual reconciliation; STL never guesses authorization
to delete an orphan key or invent a new peer secret. This private-file
recovery is not tunnel traffic, handshake or host-mutating repair.
Configured v3 receiver import provisions the local key under canonical
Engine locks. The guided sender generates its own protected private key and
a separate ephemeral receiver private key only for a deliberately exported
0600 SENSITIVE Quick Link; ordinary state retains only the receiver public
key. Real bidirectional WireGuard traffic, public handshake/counters and a
same-peer GRE/WireGuard coexistence fixture were observed in isolated kernel
E2E (PR #53, Issue #12). Broader failure, restart/persistence, multi-peer
and release-environment acceptance remain open under Issues #6/#8/#12.
Read-only status reports public handshake and counter observations; it does
not authenticate the setup URL sender or prove current bidirectional traffic.

### IPsec protected-PSK foundation (historical pre-operational milestone)

The pre-operational sections below preserve the original source-only security
constraints and test history, not the current state of conditional operational
IPsec. Current Engine/VICI/XFRM ownership and rollback boundaries appear in
[IPsec operational crash and key-retirement boundaries](#ipsec-operational-crash-and-key-retirement-boundaries-issue-7)
and [the operational E2E evidence](operations/IPSEC-REAL-E2E.md).

The IPsec module now has a separate Link-scoped protected PSK store under
the same descriptor-verified root's private `credentials/` directory.
It uses `<link-ID>.ipsecpsk` files, distinct from `.wgkey`, with strict
`0700` directories, owner-only `0600` regular single-link files, no-symlink
descriptor traversal, and atomic no-replace publication followed by directory
fsync. The shared `internal/credentials` implementation retains the existing
WireGuard path checks; two independent backend keys cannot overwrite one
another, including when their Link ID text matches.

The IPsec v0.1 store accepts **exactly 32 random bytes** (256-bit PSK),
rejects all-zero and noncanonical stored encoding, redacts generic Go
formatting and JSON, returns a private copy only through the deliberately
named `SecretBytes()` function, and requires the caller to clear that copy.
`EnsureExact` allows replay of the identical PSK but never silent rekey or
replacement. Publication errors after a no-replace write may leave an orphan
credential; this is deliberate fail-closed recovery preservation.

**Security scope boundary:** No production IPsec Engine registration, VICI
load/unload, IKE identity proof, live SA, XFRM interface, pairing CLI or
credential retirement is implemented by this storage milestone. A VICI name
match never proves ownership; future Engine operations must hold the
canonical maintenance/per-Link/resource locks and prove exact owned state
before any daemon mutation or removal. Legacy v2 Quick Link IPsec offers are
still preview-only; some older offers may contain bounded PSKs other than
32 bytes, but this protected store does not silently accept or mutate them.
Their eventual migration/import policy needs explicit compatibility handling
before exposing a user-facing IPsec import or rekey flow.

### Engine-locked IPsec credential intent (pre-operational)

A source-only canonical Engine staging transaction now reserves a full
public IPsec Link identity and its collision-sensitive resource claims in
`state.json` before an explicitly **SENSITIVE** Quick Link can be handed
to a peer. The sender reserves a SHA-256 digest of the exact legacy v2
Quick Link; the receiving endpoint requires confirmation of the exact
original previewed URL bytes, then records the fully inverted public Link
and role. Raw PSK and setup URL do **not** enter ordinary state.

The Engine acquires the existing shared maintenance gate, per-Link lock,
and resource locks. With no previous pending record it uses no-replace
PSK publication, then durable public-intent publication before invoking
an explicitly supplied sensitive handoff callback. A retry requires the
same complete public Link, original exact setup-link digest, and exact
**existing** protected PSK. A missing, unsafe or different key under an
otherwise durable pending intent requires explicit reconciliation, not
automatic regeneration (including if the sender/recipient Link and digest
match). The sender records the creator-oriented Link, while the recipient
records its exact inversion. Failed or uncertain publication preserves an
orphan PSK or pending record; it never guesses ownership or silently
adopts, removes, or rekeys the file. An explicit future operator reconciliation path is
required for orphaned keys without a matching durable public intent.

Existing v2 IPsec payloads still decode for preview; only exactly 32-byte
PSKs may enter the new protected staging transaction. Different-length
legacy payloads remain preview-only and require an explicit user decision
about rekey/import, not automatic coercion. The staged state is **not**
a committed live Link and cannot authorize VICI writes, XFRM changes,
SA teardown, credential retirement, or an operational success message.
No production IPsec CLI/backend is registered by this milestone.

### Read-only IPsec activation vacancy preflight (not ownership)

The VICI vacancy reader checks both the VICI-only `get-conns`
inventory and the daemon-wide streamed `list-conns` inventory. A
matching foreign connection loaded outside VICI is not vacant:
strongSwan `load-conn` can replace it by name. The exact-name filtered
event stream must complete with no error, duplicates or unexpected
entries. This does not reserve the daemon namespace against non-STL
administrators or authorize VICI writes.

Before any operational IPsec backend is enabled, a source-only
`Engine.CheckIPsecActivationVacancy` may inspect a staged Link under the
existing maintenance -> Link -> resource lock order. It revalidates the exact
durable pending identity and protected key, rejects committed/pending resource
collisions, and requires both strongSwan connection/PSK *name vacancy* and
XFRM interface name, 32-bit `if_id`, orphan policy and SA vacancy. A matching
foreign name or if_id is a **conflict**, never adoption permission. Missing,
malformed, ambiguous or unavailable inventory fails closed. JSON policy
and SA rows must have recognizable endpoints and a valid `dir` / `proto`;
duplicate field names, missing descriptors, and invalid/present-null `if_id`
are unverified, never absence evidence. Linux link JSON additionally rejects
nested duplicate or case-ambiguous ifname/linkinfo/info_kind/info_data/if_id
keys before comparing interface claims. Those reserved identity keys are
also rejected if they appear at an incorrect JSON nesting level, regardless
of whether their value matches the planned Link. Ordinary unrelated
non-XFRM links remain supported. Legacy policy/state text requires complete
headers and bounded, valid descriptors. The SA-level proto is distinct from
a selector's transport proto; every selector tail attribute must match a
supported bounded iproute2 token/value shape (proto, ports, ICMP type/code,
GRE key, device and optional uid), without duplicates, unknown tokens or
misplaced if_id. In particular, ICMP type/code are 8-bit, MH `(dport)` uses
the canonical four-hex-digit form, foreign `dev` values follow Linux
`dev_valid_name` rather than STL's stricter own-link naming policy, and
legacy text separators/empty-stdout checks are interpreted as ASCII bytes
rather than Unicode whitespace. In particular, UTF-8 Unicode whitespace
must never remove kernel-invalid raw bytes (such as `0xa0`) or split a
Linux-valid foreign interface name; a nonempty Unicode-only response is
not vacancy evidence. Named protocols are matched to the primary names in
a bounded, read-only `/etc/protocols` primary-name table, and checked
against the actual host glibc NSS `getprotobynumber` result via absolute
`/usr/bin/getent protocols <number>`. Numeric protocol identifiers remain
8-bit canonical decimal and need no NSS name. A customized non-file NSS
provider that returns a different primary, unavailable `getent`, malformed
or oversized output, lookup timeout, or unknown name fails closed rather
than accepting a false vacancy. Lookups share a bounded per-inventory
deadline, are cached only within that inspection, and never log raw output.
Hosts with non-file providers whose effective primary agrees with the
file-backed name remain compatible for the checked protocol IDs; foreign
names absent from the file remain conservatively unsupported. The original XFRM state bytes
and parser-owned JSON copies (which may contain key material) are cleared;
daemon and kernel error text is not reflected to ordinary output.

This is **observation only**, not a persisted authority token or authorization
to call `load-conn`, `load-shared`, `unload-conn`, `unload-shared`, initiate,
terminate, add/delete XFRM, or retire a PSK. A third-party strongSwan/kernel
writer is not serialized by STL locks, so the future activation transaction
must re-inspect and independently prove an STL-created resource before each
effect or cleanup. Do not infer ownership from `PendingIPsec`, filenames,
interface aliases, name-shaped VICI objects or derived `if_id` alone.

The inspector handles modern JSON XFRM and older iproute2 text inventory.
A successful *empty* XFRM policy/SA command can have no stdout on iproute2
6.1; command failures are never treated as empty. Real-kernel disposable
tests cover foreign interface-name/ID collisions and an orphan policy.
They do not establish IKEv2, ESP/NAT-T traffic, VICI mutation or the release
acceptance matrix. At this historical milestone, Issue #7 had not yet
reached operational acceptance; Issue #12 separately owns real-world release
and physical peer/router acceptance.


## Unregistered IPsec VICI configuration journal (historical pre-operational stage)

The Engine can now record an exact public PendingIPsec identity and
random nonce in a durable source-only journal. **The production build has
NO VICI `load-shared` or `load-conn` writer, no generally constructible
effectful adapter, and NO `ApplyPreparedIPsecVICI` entrypoint.** The only
production step is `PrepareIPsecVICI`, which rechecks protected PSK,
canonical locks and complete read-only daemon/kernel vacancy, then records
`prepared` without changing strongSwan. The existing public
`CheckIPsecActivationVacancy` also stays read-only and grants no
capability to perform a daemon mutation.

An exclusively **test-compiled** fake-operation simulator advances
strictly adjacent journal phases to exercise cancellation, fail-closed
publication ambiguity, concurrency and observation/error handling. It has
no real govici effectful transport. The journal phases `issuing-shared`
and `issuing-connection` are reserved for future owner-proof integration:
if they ever appear, their effect must be treated as uncertain; name
presence in `shared-observed` or `connection-observed` is still NOT
proof of ownership. No existing or prospective state entry authorizes
automatic retransmission, replacement, unload, deletion or retirement.
The protected PSK remains private and unchanged.

**Race finding and operational stop:** upstream strongSwan `load-shared`
replaces a same-ID secret and `load-conn` replaces/updates a same-name
connection. A foreign daemon client can insert that object after the
last `get-conns`/`list-conns`/`get-shared` read and before the write;
STL's locks cannot stop a third-party client. More inspection cannot
close this TOCTOU window. No real writer may be reintroduced until an
atomic load-if-absent/exclusive ownership protocol, or a separately
approved isolated-daemon strategy, is proven against foreign-writer
races. It must also pass all logging, credential and lifecycle gates.

The new `ipsec_vici_operations` member is optional under state schema
v2, so a current reader can load prior state. Older v2 readers with
strict unknown-field rejection cannot downgrade/read a journal-bearing
v2 file; currently no standard runtime path writes such a journal.
A schema migration or explicit upgrade-only support policy must be
settled before production enablement. No non-compatible downgrade is
silently attempted.

**Upstream daemon-log prerequisite:** strongSwan's VICI shared-key loader
contains a CFG debug-level-4 raw-secret trace (`DBG4(DBG_CFG, "key: %#B",
&data)` in `vici_cred.c`). STL deliberately neither logs raw PSKs nor
inserts them into ordinary output, but cannot prevent an independently
configured strongSwan daemon from logging them at this verbose level.
The future production activation contract MUST check/enforce a safe daemon
logging policy before transferring any PSK (or reject that environment),
including effective file/journald logging backends; absence of such an
attestation is not an authorized production key load. Do not mutate global
strongSwan logging policy merely to make an unsupported host pass.
Reference: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/vici_cred.c

A disposable Debian 13 netns test also established that passing an `alias`
when creating an XFRM link is **not** sufficient to atomically persist its
`ifalias`; setting the alias separately was necessary. Future kernel
lifecycle/rollback cannot equate a name-shaped or later matching alias
with proof that STL created the interface. At this historical stage the
durable XFRM write/cleanup lifecycle and IKEv2/ESP/NAT-T traffic were
still outstanding. Later conditional operational
evidence is recorded in Issue #7; external WAN/NAT-router testing remains
tracked in Issue #12.

## Setup-link safety

A setup link is untrusted input.

Decoder requirements:
- scheme/version validation;
- bounded input/decompression/decoded size;
- strict field validation;
- no shell evaluation;
- no arbitrary file paths/commands;
- no automatic apply without preview/explicit local action;
- reject incompatible backend/encapsulation fields;
- integrity/damage detection.

Encoded is not encrypted. In v0.1, Quick Link is the default one-step mode for secret-bearing backends, so possession of such a payload may grant tunnel access. Documentation/UI must clearly say so and treat the payload like a credential. The versioned schema must allow a later secure/local-key exchange mode without weakening or ambiguously reinterpreting existing Quick payloads.

## Host mutation

Network changes can affect host connectivity.

Rules:
- inspect before change;
- do not touch the AI Server Agent/control-plane network during tests;
- no firewall flush;
- no default-route replacement for ordinary Link creation;
- no global ip_forward enablement for host-to-host links;
- no global rp_filter disablement by default;
- track/restore only state the tool owns;
- validate interface identity before update/delete.

## Privilege

Creation/removal of Linux network links generally requires elevated capability/root. Keep privileged operations small and explicit.

Any future external integration that exposes privileged network mutation must provide appropriate authentication, authorization, input validation, and local policy boundaries.

## Dependency/supply chain

Keep dependencies minimal. Review additions to Go modules, CI actions, installers, and downloaded binaries as security-relevant changes.

## Reporting

Private vulnerability reporting is enabled for this public repository. Report suspected vulnerabilities through GitHub's private vulnerability reporting/Security Advisory flow rather than publishing exploitable details in a public Issue.

## Operator troubleshooting and logs

The accepted portable native-exclusive IPsec runtime must fail closed if
an unrelated/ambiguous strongSwan process, configuration, service, IKE port,
credential or XFRM resource is present. A successful read-only process or
package probe is **not** a service-ownership or host-resource proof. The
`stl doctor ipsec` read-only diagnostic is intentionally unable to activate
IPsec while its backend remains unregistered. Never terminate a foreign
process or reconcile external credentials as a troubleshooting shortcut.

Across all STL backends, human failure output should include a stable,
secret-safe reason and next action. Structured logs may retain public
operation/Link identity, stage, duration and outcome but must never serialize
credentials, setup links, full argv, untrusted daemon stderr, raw VICI
messages or SA key material. Optional verbose diagnostics must enforce the
same rules. Configure/check daemon log backends so raw PSKs cannot appear at
CFG DBG4 before any future actual PSK transfer. A safe `doctor` or `status`
operation never performs repair, reload, reconfiguration or service startup.

The source-only IPsec native-exclusive `strongswan.conf` builder pins a
proposed STL-specific VICI socket and native journald logging with
`default=1` and `cfg=1`; its byte-comparison guard refuses changes such
as CFG4, extra loggers or included configuration. **File bytes alone never
prove effective log safety.** Before any real PSK transfer, the operational
admission path must demonstrate that the *actual running* daemon loaded the
protected, pinned no-include configuration, that VICI/reload callers cannot
replace it or raise effective CFG debug levels, and that all active logging
backends satisfy the secret-safe policy. Missing proof is an IPsec-only
fail-closed condition. No service/config is installed or started by this
source-only component.

The additional read-only native-config artifact probe pins each parent
and the opened file, requiring root-only state/IPsec directory traversal,
root-owned exact `0600` single-link config, reviewed bytes, and
post-read identity checks. No arbitrary file contents or errors are
returned to the doctor. A positive check remains **insufficient** to
establish an STL-origin file or secure active daemon logging: matching
content can be foreign and its path can change after inspection.
Root-private publication receipts, verified systemd/process/package
provenance and VICI writer isolation remain mandatory before secrets
or effects.

The next source-only publication primitive (not exposed through Engine,
CLI or installer) prepares a root-private `strongswan.conf.origin` receipt
*before* atomically publishing `strongswan.conf` with Linux
`renameat2(RENAME_NOREPLACE)`. It first syncs reviewed config bytes and a
fresh 128-bit per-publication origin xattr on its private temporary inode,
then syncs the no-replace receipt containing the originating device/inode,
nonce and fixed SHA-256, then no-replace publishes the canonical file and
syncs the directory. It cannot overwrite a preexisting foreign file, even
one containing byte-identical config. A publication stopped after recording
the receipt is not automatically retried or adopted; an ambiguous failure
retains protected recovery artifacts for manual reconciliation. A missing
xattr, unsupported filesystem primitive, altered receipt, replacement inode,
unsafe directory or symlink fails closed. There is deliberately no
config-retirement, package install, systemctl, daemon start, VICI or kernel
writer in this milestone.

The separate `native_config_origin` doctor check verifies this receipt
**read-only**, including current inode, canonical bytes, origin xattr and
protected parent identities; it exposes only fixed classifications. This
provides stronger STL-publication evidence than byte equality, but still
cannot defeat a fully privileged root actor capable of altering both receipt
and xattr, cannot reserve the path after a read, and cannot establish the
actual running daemon's config, logging, VICI writer or port ownership.
No IPsec activation, key transfer or destructive resource effect may rely on
this check alone. Future integration must control Engine/host transaction
locks and prove ownership of the *actual* service before invoking any
provisioning on the real host.

The proposed STL-specific `simple-tun-link-ipsec.service` is currently a
source-only blueprint, not an installed or enabled unit. It explicitly pins
`STRONGSWAN_CONF`, lacks automatic `swanctl --load-all`/reload or `[Install]`
sections, and requests a root-private runtime directory/UMask. A new read-only
`native_service_unit` doctor observation checks its exact local protected
file bytes and inode/path; it cannot prove STL origin or actual loaded
systemd behavior. Package postinst/preinst scripts, distro-managed service
aliases, all drop-ins/generators, live process environment, executable and
CFG/journald effective log levels, VICI socket credentials and external
writers still require separate fail-closed admission proof. No effectful
unit publisher, `systemctl` mutator or daemon start has been registered.

`stl doctor ipsec` also observes UDP 500/4500 occupancy from bounded procfs
tables in the current namespace. It never dumps socket rows/inodes and never
converts a missing/unreadable/malformed table into an empty one; an
`observed` non-collision is not service/socket ownership or a bind permit.

## Source-only private systemd-unit origin checkpoint

A further unexported unit publisher is currently **unreachable from any
production CLI, Engine or installer path**. It stages the canonical
simple-tun-link-ipsec.service as a new 0600 inode in trusted
/etc/systemd/system, sets a fresh nonzero token xattr, and commits a 0600
versioned receipt in /var/lib/simple-tun-link/ipsec *before* atomic
renameat2(RENAME_NOREPLACE) exposes the new name. Both parent directories
are fsynced. Unsupported xattr/atomic/fsync support fails closed;
preexisting units are never overwritten or adopted, even if byte-identical.
After the staged unit's contents/xattr have been written and its inode
fsync and identity checks succeed, the provisioner explicitly fsyncs the
containing systemd unit directory **before** the pre-receipt
interruption point and before any origin-receipt creation. This ordering
makes the fixed pending pathname durable across a crash **only when both
file and directory synchronization succeed and the filesystem honors
their documented semantics**. The private receipt is then fsynced and its
parent directory fsynced before the no-replace canonical rename; the
systemd unit directory is fsynced again after that rename.

Fixed no-replace staging names prevent a successful pre-receipt stage
transaction from being silently forgotten: their continued presence
blocks future publication and any doctor vacancy claim. If any required
file/directory fsync fails, durability is unknown and the operation
returns a fail-closed error; it must never claim a durable pending name
or automatically retry, clean up, adopt or start a service. Fixture tests
check ordering and failure behavior, **not** real power-loss persistence. The companion read-only doctor check
native_service_unit_origin verifies only a time-local receipt, token, inode
and exact source bytes. The token is not an unforgeable root adversary
credential; even a positive result cannot prove PID 1's actual loaded
service, overrides, environment, logger, VICI writers, or network access.
No host service/package/network mutation was added.

## Non-loading systemd in-memory unit observation (source-only)

The source-only IPsec doctor now uses `systemctl list-units --all`
with a fixed single-target glob and *never* uses `systemctl show UNIT`.
The latter can resolve an absent unit object by implicitly loading
its metadata in PID 1. In contrast, list-units enumerates currently
in-memory primary identities without an explicit unit lookup. A successful
empty listing only means that the primary unit was not in memory **at the
time of the snapshot**. An explicitly masked/failed entry is blocked.
A normally loaded entry is still `unknown`, since the listing does not
prove effective fragment, aliases, generator, drop-ins, current
ExecStart/Environment, pending reload, native logger, process or VICI
rights. A second `show UNIT` after inventory is expressly forbidden:
the unit may unload between operations and the next lookup may load it.
All unverified override/identity conditions therefore remain unknown,
never an affirmative admission. Filesystem origin readers are separate
and cannot fill the effective-manager proof gap.

The new optional `linux.BoundedRunner` interface enforces **16 KiB
stdout and 1 KiB stderr stream capture ceilings before buffering** for
the manager probe; stdout/stderr overflow cancels the process and returns
a safe error without partial content. Without bounded capability the
diagnostic returns `unknown`, not an unbounded `Runner.Run` fallback.
Errors and raw untrusted manager output are never serialized. The
system may naturally load/unload units concurrently, so even a list
snapshot cannot reserve or certify a stable state. No service start/
stop/enable/reload, package, VICI, credential, file, network or kernel
mutation is performed. `activation_allowed=false` and doctor exit 4
persist when native-exclusive runtime is unadmitted; privileged disposable
operational acceptance remains separately required.

## IPsec operational crash and key-retirement boundaries (Issue #7)

The root-privileged native `charon-systemd` executable must itself be
root-owned, regular, non-group/world-writable and reachable only through a
root-controlled path. Its inode must match the observed systemd MainPID
`/proc/<pid>/exe`. A plain 0755 mode without UID 0 is untrusted, even
when every private service/config/VICI receipt is present.

An XFRM device exists only under the original recorded owner/ifindex
journal and verified `if_id`/alias. The gap between kernel create and
persistent ifindex is intentionally **unrecoverable automatically**:
STL cannot claim an unrecorded interface solely from its name. An aborted
or interrupted Remove retains original Link claims and a durable
step-by-step VICI/kernel journal until exact scoped reconciliation
completes. Neither Status nor Doctor performs repair. Unverified daemon
responses never authorize a matching-name takeover.

After a committed Remove's protected digest receipt, `retire-ipsec` is
a **local receipt-based credential deletion**, independent of systemd
availability. Missing receipt, pending/active Link, unexpected journal,
changed key inode/mode/owner or mismatched digest prevent deletion.
Deleting the credential does not imply physical disk erasure.
