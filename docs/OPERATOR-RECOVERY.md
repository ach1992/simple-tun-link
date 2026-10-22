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
   Keep guard + journal quarantine and arrange separately authorized
   maintenance or an independently verified host/network namespace
   teardown under an impact and rollback plan. A host restart is not
   automatically safe for other Links, and is not authorized by this
   recovery command. Absence or a reset must be verified anew;
   never assume an unobserved side effect completed.
4. Only after the original unmarked effect has been independently
   resolved, use the existing `reconcile-wss-original` command with
   explicit confirmation. It still revalidates the original guard
   nonce, global WG interface/public-key/listen-port vacancy and final
   host absence before committing the journal/State transaction.
   Foreign resources and unrelated nft/firewall objects remain out
   of scope. If any required readback is incomplete, retain quarantine.

When the original WG alias *was* published, the existing command can
verify its nonce and ifindex and compensate only intended original
intermediate configuration; extra keys, peers, AllowedIPs, addresses
or unexpected UDP listeners are refused. This manual pre-alias gate is
an honest limitation of this unreleased candidate, not a promise that
all pre-commit crash objects are automatically recoverable.
