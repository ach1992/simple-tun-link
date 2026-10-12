# Operator failure-to-recovery workflow (Issue #10; shared evidence #9)

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
| `rollback` | `not_required`, `unavailable`, `not_attempted`, `completed_unverified` (callback returned success, **not a separate full host attestation**), `incomplete` |
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
6. For IPsec/XFRM, only `stl doctor ipsec --json` is currently supported:
   the operational backend remains unregistered, and no diagnostic is an
   activation permit. See Issues #7 and #12.

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
Issue #12 owns the separate release-level privileged E2E matrix.
