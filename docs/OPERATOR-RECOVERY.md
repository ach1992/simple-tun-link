# Operator failure-to-recovery workflow

This guide describes the implemented canonical Engine/CLI behavior for
`stl link ensure`, `import`, `remove` and `restore --all`. Guided menu
operations reuse the same Engine. Read-only `status`, `diagnose`, and
`diagnose --all` provide observations; **none repairs a Link**.

## What is proven and what remains uncertain

A successful Engine operation (exit 0) has completed the backend's
verify-and-commit flow; `changed:false` means its backend plan needed no
mutation. Neither result proves peer replies, future availability or that a
remote operator accepted the setup link.

Failures of `ensure`, `import`, and `remove` retain the **existing
schema v1** fields `outcome:"unconfirmed"` and
`reconciliation_required:true`, including when the Engine can prove an
early rejection. This is intentional backward compatibility: existing
automation must not reinterpret the old fields. In addition, when a
trusted Engine stage is available, the existing `error` object contains
an optional `evidence` object:

| Evidence field | Values and precise meaning |
| --- | --- |
| `stage` | `preflight`, `inspect`, `plan`, `validate`, `apply`, `verify`, `persistence`, `state_commit`, `persistence_cleanup`, `credential_retirement`, `credential_provision` (or `rollback` for a standalone Engine rollback helper) |
| `host_mutation` | `not_attempted`: this Engine invocation has **not** called a host Apply/persistence publication; `attempted`: a call that may mutate was made, **not proof that anything changed**; `retained`: compensation deliberately skipped to preserve possible published intent |
| `desired_state` | `no_commit_attempted`, `commit_attempted`, `prior_verified` (previous snapshot reloaded), `visible_unconfirmed` (publication/durability or readback ambiguous), `committed` |
| `rollback` | `not_required` (no backend Apply compensation needed), `unavailable` (callback not yet established), `not_attempted` (compensation deliberately not run, including after a confirmed commit), `completed_unverified` (callback returned success, **not a separate full host attestation**), `incomplete` |
| `credential_provision` (optional) | `attempted`: protected per-Link key persistence was invoked separately before backend Apply; the exact key may remain even if backend mutation never started |

The `credential_provision` **stage** is emitted when protected key persistence fails before backend/network Apply; `credential_provision:"attempted"` separately witnesses that the key may remain. This is not an ordinary host/network mutation.

These values describe **this invocation only**. In particular,
`host_mutation:not_attempted` refers to backend network Apply and restore
persistence publication; it is **not** proof that protected credential files
or removal-receipt state were never written. Check the optional
`credential_provision` evidence before any credential-bound retry.
`not_attempted` does not
prove the host is free of pre-existing or concurrent external resources;
`prior_verified` is a state-store readback, not a proof of global kernel
state. Protected per-Link credential staging or cleanup may be deliberately
retained even when the network backend Apply did not run. Never use
`partial_result.changed` as authoritative proof of successfully applied
or durably committed host changes.

The `error` object also carries a safe `code`, precise
`reason_code`, `next_step` and, when verified, validated Link ID/backend.
No raw `stderr`, command arguments, credential values, display names,
arbitrary file paths or pairing URLs are published.

### Example: rejected before Apply

```json
{
  "schema_version": 1,
  "error": {
    "code": "inspect_failed",
    "operation": "link_ensure",
    "object_id": "lnk_0123456789abcdef0123456789abcdef",
    "backend": "gre",
    "detail": "Link operation did not complete successfully; inspect current Link status/state before retry",
    "reason_code": "kernel_module_not_loaded",
    "next_step": "Inspect the matching kernel module and supported host packages; load it only with operator authorization, then retry read-only checks.",
    "evidence": {
      "stage": "inspect",
      "host_mutation": "not_attempted",
      "desired_state": "no_commit_attempted",
      "rollback": "not_required"
    }
  },
  "outcome": "unconfirmed",
  "reconciliation_required": true
}
```

Illustrative response shape, not a real host observation. The stable output
contract is `schema_version:1`; additions live under `error` and do not
change old exit codes: 0 success, 2 invalid request, 4 unsupported, 1 other
failure. Unsupported/missing module diagnosis is not identical to an
unregistered backend and retains its existing error/exit category.

## Safe actions by classification

| `reason_code` | What to do |
| --- | --- |
| `rejected_before_host_apply` | Correct Link intent or conflicts, inspect saved/live identity, then explicitly retry when safe; no Engine backend Apply was invoked |
| `operation_deadline_exceeded_before_apply` / `operation_cancelled_before_apply` | An Engine stage timed out or was canceled before backend Apply. Inspect Link and protected credential state, lock contention/host availability, and retry only if still intended |
| `credential_provision_outcome_unverified` | A protected key write was attempted but the Engine did not confirm provisioning; inspect exact protected key and pending/committed Link identity before regenerating/retrying |
| `kernel_module_not_loaded` | The specific module was absent from `/sys/module` but `modinfo -n` found a regular kernel-module artifact; confirm supported host/kernel policy before separately authorizing any load |
| `observation_unverified` / `diagnostic_observation_unverified` | Retry read-only inventory; failure is **not** proof of absence, a free UDP port or permission to overwrite a foreign Link |
| `apply_outcome_unverified` | A host Apply was attempted without confirmed rollback; inspect owned kernel resources and stored intent before retrying |
| `rollback_completed_unverified` | The compensation callback returned without error, but recheck state and live identity before converging again |
| `rollback_incomplete` | An owned undo operation failed; stop further mutation until the precise residual resources and ownership are reconciled |
| `state_publication_uncertain` | State visibility/durability is uncertain; **do not** blindly undo or repeat Remove/Ensure, as this can destroy a published intent |
| `post_commit_cleanup_incomplete` | Desired state was committed, but final restore-unit cleanup or credential-retirement receipt is incomplete; verify the committed Link state and owned cleanup independently |

A missing GRE/IPIP/FOU kernel module can be identified **only when both
independent, read-only observations** support it: the expected
`/sys/module` identity is absent, and `modinfo -n <module>` resolves to
a real module artifact. This is *not* an assertion that loading will work.
Otherwise inventory remains unknown/generic; no automatic `modprobe`, no
claimed empty `fou` inventory and no claimed free conflicting port.
The check covers GRE Native (`ip_gre`), IPIP Native (`ipip`) and GRE/IPIP
FOU/GUE receive mappings (`fou`).

## Read-only inspection after persistence failure

If Create or Import fails at persistence, or rollback reports
`rollback_completed_unverified`, the result does **not** prove which
systemd or backend operation failed. A missing newly created Link
in saved State does not prove the kernel/network is clean. A rollback
callback reporting success is not an independent service or traffic
attestation.

On the exact authorized affected host (never a control-plane
or unrelated production server), run read-only checks:

~~~sh
sudo stl link list --json
systemctl --version
systemctl is-enabled simple-tun-link-restore.service
printf 'is-enabled exit=%s\\n' "$?"
systemctl show simple-tun-link-restore.service --no-pager -p LoadState -p UnitFileState -p FragmentPath -p Result
stat -c '%U:%G %a %n' /usr/local/bin/stl /etc/systemd/system || true
stat -c '%U:%G %a %n' /etc/systemd/system/simple-tun-link-restore.service || true
~~~

A known systemd variation may represent an absent unit with empty
`is-enabled` stdout and exit 1, requiring independently confirmed
`LoadState=not-found` and missing unit-file/fragment identity. Neither
an incomplete read nor local callback return alone authorizes cleanup.
Do not overwrite, delete, enable or disable an ambiguous service or
foreign kernel resource; reconcile exact State/owned inode identity
before any retry. Read-only status and Link probes can narrow a
failure without taking additional network authority.

## Operator walk-through

1. Identify the exact stable Link ID from `stl link list --json`; this
   reports desired state, **not** peer reachability. If a failed create
   never committed its intent, the Link may correctly be absent.
2. Inspect the specific saved Link with `stl link status <link-id> --json`
   when it exists; then use `stl link diagnose <link-id> --json` or
   `stl link diagnose --all --json` for point-in-time identity and traffic
   observations. A failed inspection must **not** be treated as vacancy.
3. For module prerequisites, use read-only `uname -r`,
   `modinfo -n fou` (or `ipip`/`ip_gre`), and
   `ip -json fou show` on the intended host. **Do not automatically load
   modules or change host networking as part of diagnostics.**
4. Inspect `error.evidence` and the typed `reason_code` before any new
   explicit mutation. For incomplete rollback or uncertain commit, reconcile
   ownership on that specific host and Link first; do not overwrite another
   Link, firewall rule or service. A Link restore is **itself mutating**.
5. If saved Links need recovery on an authorized host,
   `stl link restore --all` invokes the same Engine and reports completed
   count plus validated **per-Link failure reason, next action and stage**
   where evidence exists. It does not silently ignore failed siblings.
   Unrecoverable shared-state or rollback failure stops the batch.
6. For IPsec/XFRM, run `stl doctor ipsec --json` first to inspect
   native-exclusive service prerequisites. When **not** admitted, the
   operational backend stays unregistered and status/diagnosis is blocked.
   When admitted, read-only `status` and `diagnose` can verify owned XFRM
   identity, installed SA and bounded Link Address responses. Exact-owner
   XFRM **interface packet** counters are reported only when a separate
   read-only kernel stats probe verifies identity and both values; otherwise
   RX/TX remain "not measured", not zero. A diagnosed SA or interface
   packet count does not grant activation permission, authenticate an
   untrusted peer or prove sustained encrypted traffic. See [diagnostic semantics](DIAGNOSTICS.md) and [release evidence boundaries](RELEASE-ARTIFACTS.md).

Safe failures may not contain `evidence` if they occur outside the canonical
Engine or in a legacy entry point; absence of evidence means **unknown**,
never a verified no-op. The menu shows the same human-facing Engine result
and must not be parsed by automation. There is no new network daemon, repair
engine or credential/debug-log collection in this package.

## Verification boundaries

Automated tests inject deterministic failure stages, nonmutating module
probes, cancellation, rollback success/failure, uncertain state publication
and independent sibling operations; they are **not** a substitute for
real privileged kernel/module, multi-distro or traffic/restart testing.
Release-level privileged E2E is separately reproduced through the [cross-backend runbook](operations/CROSS-BACKEND-REAL-E2E.md) and recorded against the exact candidate.

## Unreleased WSS: unmarked pre-alias kernel staging quarantine

A managed-WSS Create can be interrupted after exclusive WireGuard
`RTM_NEWLINK` but before publishing the original owner `ifalias`.
The unpredictable, nonce-derived staging **name is not evidence of
creation**. An identical unconfigured WG interface may have been created
by another actor before STL dispatched `RTM_NEWLINK`, or may have
replaced the original interface later. Its empty/down state, type, name
and saved journal are not independently sufficient to delete it.

When `stl link reconcile-wss-original LINK_ID --confirm LINK_ID`
rejects an **unmarked staging object**:

1. Stop ordinary Create/Ensure/Restore retry for that Link. Preserve the
   exact protected original crash journal, the verified nft ingress
   guard, and the existing kernel object; do not adopt or re-label it.
   Read-only `stl link list --json`, `ip -details -json link show type
   wireguard`, `ip -json address show`, and public-only `wg show`
   can collect diagnostics, but **none establishes pre-alias creation
   provenance**.
2. This is a **separate, privileged, manual identity-attestation
   boundary**, not a weaker mode of `reconcile-wss-original`. Before
   any targeted manual kernel deletion, require independent,
   trustworthy evidence of the *actual original* exclusive NEWLINK
   creation and its exact network namespace plus ifindex/generation,
   and fresh evidence proving the currently addressed object is still
   that same object (no replacement or ifindex reuse). A log that
   merely records the requested staging name, or an ambiguous/missing
   ACK, is not this evidence. Have the Owner explicitly authorize the
   identified manual host effect and its impact on other active Links.
   STL does not currently create a durable pre-alias ifindex witness
   and **cannot ordinarily supply that proof itself**.
3. If this proof cannot be obtained, **do not delete the object**.
   Keep guard + journal quarantine. The implemented two-stage
   cold-boot recovery procedure below can establish the extinction of
   the old WG kernel generation across ALL namespaces without deleting
   a possibly foreign interface by name. It requires a separate
   Owner-approved full-host reboot, strict postboot readback, and
   checkpoint continuity; THIS command does not authorize any reboot.
   Never assume a reboot, teardown or absence from an unobserved effect.
4. The normal `reconcile-wss-original` command cannot retroactively
   prove a kernel deletion made outside its original, trusted
   nonce/ifindex-verified transaction. It must refuse to consume the
   journal merely because an earlier ambiguous or unmarked kernel effect
   has disappeared. The implemented and owner-gated
   `arm-wss-cold-boot` / `reconcile-wss-cold-boot` pair is
   the positive-evidence whole-kernel-reset alternative below; it never
   accepts a token, a fabricated boot ID or a namespace-local empty
   inventory as deletion provenance.
   Never remove a durable reservation or fingerprint from State based
   solely on a name or empty inventory. Foreign resources and
   unrelated nft/firewall objects remain out of scope.

When the original WG alias *was* published, the existing command can
verify its nonce and ifindex and compensate only intended original
intermediate configuration; extra keys, peers, AllowedIPs, addresses
or unexpected UDP listeners are refused. This manual pre-alias gate is
an honest limitation of this unreleased candidate, not a promise that
all pre-commit crash objects are automatically recoverable.

## Unreleased WSS: namespace migration and kernel deletion witnesses

A Linux WireGuard interface may be created in network namespace A and
moved to B while its UDP socket remains in its **birthplace** A. When
the moved interface is DOWN the UDP listener in A also temporarily
vanishes; bringing the same object UP in B recreates that socket in A.
Thus neither `wg show all` in A nor `ss -u -l -n` in A can attest that
the original kernel object was actually destroyed.

In this candidate, removing the WSS nft ingress guard requires the
same-transaction original nonce/ifindex verification and a successful
index-targeted kernel deletion **in addition** to a fresh, bounded
birthplace UDP socket readback. This also applies to Ensure rollback.
A separate read-only crash reconciliation cannot invent this witness;
a previously interrupted transaction with no trustworthy deletion
witness stays quarantined, even if its local inventories look empty.
The same restriction protects original receipt/credential retirement,
including the otherwise dangerous case in which nft guard and WSS helper
were removed externally BEFORE the first ordinary Remove. With a moved-
DOWN original the State, claims and protected credentials remain reserved.
Legacy retirement receipts without an exact-index deletion or trusted-
old-generation extinction marker remain readable but cannot retire files.
Do not temporarily drop the nft guard, move a foreign WG object,
recreate its listener, force-delete the journal, or retire private
material to make automatic reconciliation appear successful.

An externally moved or ambiguously deleted original WG object requires
a separately scoped, Owner-approved manual identity/recovery procedure
with proof of the actual original generation and all affected network
namespaces. Do not try to fix an unreleasable guard/journal by restarting
or modifying production networking; neither a reboot nor this command
is blanket authorization. The disposable real-kernel namespace tests
cover both moved-UP and moved-DOWN cases; physical host namespace
coexistence remains a distinct operator acceptance gate.

## Unreleased WSS: ordinary missing-original quarantine

For an already committed WSS Link, a missing local WireGuard interface or
empty birthplace UDP-socket inventory is **not** proof its original kernel
object died: it may have moved into another netns and been left DOWN. This
risk applies BEFORE the very first ordinary `link remove` and without any
Crash Journal, even if the original WSS helper and nft guard were externally
stopped or deleted. Ordinary `ensure`, `restore --all`, and `remove` now fail
closed instead of creating a second WG, erasing the committed owner State
or issuing a credential-retirement receipt. No automated remediation should
install a new original, delete a potentially foreign guard, or discard the
protected original key, TLS certificate or bearer material.

A successful native-host committed WSS Ensure records the verified host
`wss_kernel_boot_id` and versioned `wss_kernel_boot_source` in the exact
Link record (no operator override). On a **genuine full host reboot**,
ordinary RestoreAll may recreate an absent original only if the protected
record contains those trusted pre-reboot fields, the same host's current
source is independently trusted and different, and strict fresh current-
boot vacancy confirms no foreign replacement/guard/helper. An absent or
legacy/untrusted birth marker is not retroactively certified. Original
objects still visible can be managed under the usual full nonce/ifindex/
configuration attestation, but missing originals remain quarantined.

Ordinary successful Remove publishes a receipt with versioned
`wss_original_termination` provenance for an exact original-ifindex delete
or a trusted old-kernel extinction plus strict current-host vacancy.
Original-object crash compensation and separately armed manual cold-boot
recovery have distinct verified termination reasons. `retire-wss` refuses
legacy receipts without proof, even when the local interface, guard and
helper all appear absent. Preserve the exact State root and encrypted
backups; physically moving this State to a DIFFERENT still-live host does
not prove the original host kernel stopped. Establish an Owner-approved
manual recovery when the trusted generation is unavailable, and do not
manually edit or backfill UUIDs/receipts. The separate manual journaled
recovery below applies only when its own admission gates can be met.

## Unreleased WSS: executable manual cold-kernel-reboot recovery

**Use only for an unresolved original WSS Crash Journal whose ordinary
nonce/ifindex compensation cannot prove success**: guard-only initial
Ensure, interrupted committed repair, post-original-WG-deletion Remove,
or unmarked/possibly moved original. This procedure is a new, explicit
**whole-host operational maintenance gate**, not automatic crash
replay, not arbitrary State editing, not permission to reboot production.

A real Linux **kernel reboot** destroys every old-generation WireGuard
interface and socket, including interfaces moved to any network
namespace (UP or DOWN), and ephemeral nft/kernel resources. A process,
container or systemd-unit restart is **not** a kernel reboot. STL now
accepts `/proc/sys/kernel/random/boot_id` **only** from the original,
unshadowed kernel `procfs` mount in the **initial host PID namespace**
(Linux `PID_NS_INIT_INO`). It checks real filesystem type, complete
`/proc/self/mountinfo` coverage, absence of any bind mount/submount on
`/proc/sys/kernel/random/boot_id` or its ancestor path, and namespace/
mount stability around the read. A virtualized UUID (including
`systemd-nspawn`'s independently generated container boot ID), nested
PID namespace, missing procfs evidence, or ambiguous host setup is
**not** evidence of a kernel reboot. Such environments cannot arm or
reconcile via this manual path; original journals and credentials stay
quarantined. The same verified host-kernel source must yield a DIFFERENT
canonical UUID from the protected State checkpoint committed **before**
the actual full-kernel reboot. The checkpoint must also record the
versioned trusted-source admission marker `cold_boot_source` =
`linux-initial-pid-unshadowed-procfs-v1`, written in the SAME durable
transaction as the old boot UUID. A UUID alone from a previous STL
candidate is not authenticated host provenance and cannot be used by
this recovery route. This is old-generation extinction evidence, not
proof that other managers did not create NEW objects after reboot.

1. **Owner authorization and impact plan (outside STL):** obtain
   explicit approval for the affected host's full reboot, list other
   Links, SSH/out-of-band rescue access, web services, active namespaces
   and privileged network managers; reserve a maintenance window.
   Record a restore-tested, access-restricted backup of the canonical
   State root **including original journal, receipts and protected
   credentials**. Record all relevant namespace managers and prevent
   privileged concurrent replacement of the reserved WSS resources.
   Do not infer a safe restart from a green rootless test.
2. **Arm checkpoint on the currently running kernel (no host effects):**

   ```sh
   sudo stl link arm-wss-cold-boot LINK_ID --confirm LINK_ID --json
   ```

   Require `checkpoint_persisted:true`,
   `journal_cleared:false`, `host_mutated:false` and
   `reboot_performed:false`. This atomically writes the current kernel
   boot UUID **and the v1 trusted-source provenance marker** to the exact
   original, fsynced journal under canonical Engine maintenance/Link/
   resource locks. It does NOT remove the guard,
   alter kernel interfaces, touch systemd, reboot, remove private
   files, or release any reservation. A repeated arm on the SAME boot
   is idempotent only for a checkpoint already bearing the trusted-source
   marker; a subsequent re-arm in a different boot is refused.
   A checkpoint cannot be manufactured by CLI arguments, environment,
   uploaded evidence, empty WG/UDP observations, or operator text.
   If the process is containerized or its procfs origin cannot be
   verified, **stop**: re-running as root inside that container does
   not bypass admission and no synthetic boot ID may be substituted.
   A native, attested host execution environment is required before
   using this recovery path.
   **After successfully arming, make an additional private, verified
   backup of the now-checkpointed protected State**; a backup made
   before arming does not contain the checkpoint and cannot by itself
   authorize postboot reconciliation if restored. Protect access to
   both backups and reconcile any intentional restoration under the
   original recorded Owner maintenance plan. If the host had already
   rebooted before any checkpoint was armed, the CLI cannot backdate
   a lost boot identity: a further separately authorized full-kernel
   reboot is required for this conservative manual route.
3. **Separately approved full-host kernel reboot:** perform it using
   the Owner's established out-of-band change/rollback mechanism;
   STL intentionally offers **no reboot button or command**. A host
   reboot affects independent services and Links; include their
   reinstatement in the maintenance plan. Do not delete a guarded
   or unmarked original WG manually as a substitute.
4. **After restart, read-only verify first:** confirm the expected host
   and physical connectivity; inspect original Link/journal, loaded
   systemd helper unit, nft ingress guard, public-only WireGuard and
   UDP socket inventories, and privileged managers. Any NEW occupied
   resource matching a reserved port, identity or unit must be
   investigated rather than deleted or adopted by STL.
5. **Atomic protected State reconciliation only AFTER proof:**

   ```sh
   sudo stl link reconcile-wss-cold-boot LINK_ID --confirm LINK_ID --json
   ```

   The actual CLI reloads the exact journal and original committed
   Link/claims, checks original issuance-time private file SHA-256
   identity for committed operations, compares the current trusted
   boot ID with the durable pre-reboot one, refuses an unarmed or
   same-boot journal, and independently inspects helper, nft, WG,
   reserved key/listen port and UDP sockets for conflicting
   current-boot resources. With all proofs valid it performs ONE
   atomic State update and **no host changes**. For initial Ensure
   it consumes only that journal. For committed Ensure/repair it
   retains the identical committed Link, nonce, claims and protected
   credentials. A LEGACY/untrusted committed original has no trusted
   historical birth source: the reconciliation instead durably issues
   one `wss_cold_boot_restore` proof bound to the original journal's
   trusted pre-reboot Arm and the independently attested post-reboot
   generation, never silently backfills `wss_kernel_boot_*`. With a
   freshly trusted kernel source, no visible original and verified
   complete current-host vacancy, approved `link restore --all`
   can create one NEW WG original with the existing nonce, claims and
   private issuance. Before the first host effect its witness is
   atomically marked SPENT with a NEW pre-effect journal. Only a
   successful original creation clears it and records the honest new
   birth source. If interrupted, preserve the spent proof and journal;
   even after an apparently successful rollback, automatic repeated
   restore is NOT authorized. Arm that NEW journal and follow a
   separately approved full-host reboot before retrying. Without the
   manual verified generation, legacy committed repair-only
   `reconcile-wss-repair-vacant` refuses to consume its last journal;
   an ordinary no-op Ensure cannot promote a healthy legacy Link.
   For committed Remove it deletes only the original
   committed State Link and creates its immutable original credential-
   bound receipt; credential removal is still a SEPARATE
   `link retire-wss LINK_ID --confirm LINK_ID` operation after
   a fresh full-host absence and file identity check. Never reuse
   an already retired Link ID.
6. **Failure and rollback:** if the reboot did not actually occur,
   the boot-ID read fails, journal/owner/claims change, original private
   fingerprint mismatches, a helper/guard/WG/socket reappears, the
   original checkpoint has only a legacy UUID without trusted-source
   provenance, or the State commit is uncertain, preserve the original
   journal, reservations and credentials. Do **not** re-arm over a different
   checkpoint, remove a guard, edit State JSON, scrub secrets, blindly
   rerun RestoreAll for the blocked Link, or claim success. In a legacy
   committed repair, an interrupted first Restore leaves a spent
   recovery witness and NEW crash journal; the prior old-kernel proof
   cannot be reused to create another potentially hidden WG. Another
   explicitly authorized full-host reboot with a newly armed checkpoint
   is required to certify that interrupted NEW kernel generation extinct. Maintain
   the old protected backups for forensic restore with a separately
   authorized reconciliation plan. Reboot-before-reconcile is
   reversible at the control-plane checkpoint level only;
   reinstating unrelated host services is the Owner's explicit
   operations rollback responsibility.

**Legacy checkpoint quarantine (pre-provenance candidate):** an
original State journal with a valid `cold_boot_armed_from` but no
`cold_boot_source` remains fully readable for diagnostics and
strict original-object workflows; it does **not** authorize cold-boot
Reconcile. Even re-running `arm-wss-cold-boot` in a trusted environment
on the same observed boot will refuse to stamp a legacy checkpoint.
Do not erase, edit or manually add the marker, copy a fresh checkpoint
onto it, reissue credentials, force-delete guards or claim that another
reboot alone can unlock a legacy record. Preserve the exact State root
and protected backups and arrange a separate Owner-approved original-
object/State reconciliation plan. The normal two-phase cold-boot route
requires an initially unarmed journal and a fresh trusted Arm **before**
a separately approved actual kernel reboot.

**Coexistence/race limit:** this recovery proves old-kernel WG
generation extinction across ALL old namespaces without enumerating
each one. It does NOT grant exclusive control of the NEW kernel.
A privileged actor who replaces a resource, spoofs a nonce or swaps
an ifindex between readback and deletion can defeat the normal host
ownership assumptions. Establish exclusive scoped privileged host
ownership/maintenance and verify newly created namespaces separately.
A forged/mounted procfs boot UUID by malicious root is outside the
local-root trust boundary and not an attestation by an external verifier.

The disposable E2E attempts a **virtual Boot ID change** through a
bind mount strictly inside private rootless namespaces. The production
CLI must now reject both cold-boot Arm and Reconcile in that untrusted
PID/mount environment, leaving the actual crash journal, kernel guard
and/or private issuance untouched. Separate deterministic Engine tests
exercise post-reboot State transitions using injected boot-generation
values; these **do not** authenticate a physical host reboot.
No actual PID1/kernel reboot, service restore or provider WAN
acceptance is claimed.
