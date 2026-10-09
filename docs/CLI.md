# STL CLI — implemented read-only and explicit lifecycle commands

STL's broader task-first interactive interface and complete create/import/manage
workflow are still tracked in Issue #10. The versioned non-interactive
ensure/remove lifecycle is implemented but its remaining runtime/backend
acceptance is tracked separately. This page distinguishes **read-only**
observations from **explicit host-mutating** commands.

## Commands

- `stl help`
- `stl version [--json]`
- `stl link list [--json]`: read saved configured Links in stable Link ID
  order. An empty state file yields an empty list; listing does not construct
  backend runtimes, probe host interfaces, or alter network state.
- `stl link status <link-id> [--json]`: read one saved Link and inspect
  its live backend state. GRE is supported using its ownership-/ifindex-checked
  `DiagnosticState` adapter, including network interface counters. Unsupported
  backend kinds return a nonzero error rather than claiming health.
- `stl link diagnose <link-id> [--mtu <bytes>] [--json]`: explicitly
  probe the selected GRE Link's **peer Link Address** using bounded ICMP
  echo with IPv4 Don't Fragment. Reports actually observed RTT/loss/jitter
  and safe PMTU recommendations alongside the GRE interface counters.
  This command transmits diagnostic packets but makes **no** host network,
  firewall, MTU or desired-state changes. Requires a configured and
  identity-checked active GRE interface.
- `stl link preview --stdin [--json]`: decode and **redact** a
  versioned setup link supplied only through standard input, then display
  the **receiver-oriented** Link identity, addresses, encapsulation,
  exchange mode, and credential-presence flag without revealing any
  credential or applying network state. Never pass SENSITIVE Quick Links as
  command-line arguments, which can enter shell history/process listings.
- `stl link export <link-id> [--json]`: **read-only but intentionally
  disclosing**, export a canonical receiver Setup Link for a saved
  credential-free GRE Link, including encoded endpoints and display metadata.
  Unlike status/diagnostics, this command explicitly emits shareable setup
  material; refer to the export security caveat below.
- `stl link ensure --stdin [--json]`: **mutating** idempotent desired
  Link convergence via the existing Engine, accepting a strict versioned JSON
  request on standard input. Full request schema appears below.
- `stl link remove <link-id> --confirm <same-link-id> [--json]`:
  **mutating** Engine-owned removal after explicit stable ID confirmation.
- `stl link restore --all`: **mutating** host persistence/reapply
  operation for existing saved Links, using the same Engine.

`list` reports **configured desired state**, not actual network reachability.
`status` reports **interface_verified**, not end-to-end connectivity.
Its `connectivity` field explicitly says `not_measured`: a configured,
owned, UP GRE interface with counters alone is not proof of peer traffic,
working firewall policy, or PMTU. Real Link Address probes belong to
the read-only diagnostics path in [DIAGNOSTICS.md](DIAGNOSTICS.md).

## Machine output

`--json` emits exactly one object with top-level integer `schema_version: 1`.

- `link list`: `{ "schema_version": 1, "links": [...] }`; each entry includes
  only Link ID, backend, encapsulation, local and peer Link Addresses.
- `link status`: a projected Link entry, `interface_verified: true`,
  `connectivity: "not_measured"` and GRE's identity-checked counter view.
- `link diagnose`: the existing GRE diagnostics report with top-level
  schema version, Link ID, backend kind, identity-checked counter state,
  MTU result and quality result. `--mtu` overrides the **inner IPv4
  packet** MTU manually; oversized values are errors, not silently clamped.
  Without `--mtu`, MTU is selected by bounded DF probes, and an
  unverified fallback is explicitly marked unverified.
- `link preview`: one redacted object with CLI schema version 1,
  a separate `pairing_schema_version`, receiver-facing non-secret
  Link metadata, non-secret GRE configuration options when present,
  `has_credential`, credential kind and sensitive flag.
  The input setup link, private keys, arbitrary display names and decoding
  cause are deliberately excluded from JSON and human output.
- `link export`: explicit export JSON with CLI and pairing schema
  versions, Link ID, backend/encapsulation, credential/sensitivity flags
  and the complete intentional `setup_link` field. The encoded URL
  discloses metadata and MUST NOT be treated as ordinary status output.
- `link ensure` / `link remove`: versioned operation, Link ID,
  changed and removed fields on Engine success. Failure JSON remains
  nonzero and may include uncertainty/reconciliation signals.
- Read errors: `{ "schema_version": 1, "error": { "code": ..., ... } }`;
  raw state-file content, arbitrary backend output/errors, display names
  and credentials are not included.

Exit statuses for these read commands: `0` verified success; `2` invalid
argument or missing Link ID; `4` unsupported live backend; `1` state or
inspection failure. A failure cannot silently become a success even when
the requested Link exists in saved configuration.

Commands that require the local desired-state snapshot use the existing
private state store. The pure `link preview` command does not load
persisted state; access failures in the other read paths are errors, not
instructions to create/replace files.

Read-only `list`, `status`, `diagnose`, `preview` and
explicit `export` never change network configuration. Export is
**deliberately revealing** and not suitable for ordinary diagnostics/logging.
The distinct `ensure`, `remove` and `restore` paths are
explicit host-mutating operations. Interactive
create/import, optional throughput, non-GRE diagnostic adapters and the
task-first UI remain pending under Issues #8, #9 and #10.

## Explicit Link lifecycle commands — Issue #10

The following operations **change the selected host's network and durable
desired state**. They are not equivalent to read-only status, preview or
diagnostics. Use only with operator-approved local/peer address, source and
backend configuration on a host you are authorized to administer:

~~~sh
stl link ensure --stdin --json < /path/to/desired-link.json
stl link remove lnk_<32-hex-characters> --confirm lnk_<same-32-hex-characters> --json
~~~

`ensure` accepts one bounded **versioned CLI request**, not an internal
`domain.Link` object directly. The top-level integer
`schema_version: 1` is **required**. Its `link` member contains
the desired v1 Link fields: ID, backend, encapsulation, underlay endpoints,
Link Address endpoints, and optional display name / GRE options.

For example, this is a valid **request shape only**, not a recommendation to
configure the illustrative addresses:

~~~json
{
  "schema_version": 1,
  "link": {
    "id": "lnk_0123456789abcdef0123456789abcdef",
    "underlay": {"local": "192.0.2.10", "peer": "192.0.2.20"},
    "addresses": {"local": "10.80.20.0/31", "peer": "10.80.20.1/31"},
    "backend": "gre",
    "encapsulation": "native"
  }
}
~~~

**Compatibility boundary:** all accepted v1 fields are fixed, including
the nested `underlay`, `addresses` and `gre` objects.
Underlay and Link Addresses accept only `local` / `peer`; GRE v1
accepts only `key_enabled`, `key`, `ttl`, `tos`,
`disable_pmtud`, `checksum`, `sequence` and `udp_port`.
These names and their value types are the CLI contract rather than a
serialization of mutable internal domain structs. Unknown nested fields
are rejected, even if a later internal backend implementation gains them.
A future public field addition requires an explicit compatibility/version
decision; the existing version-1 reader must not silently widen.

The v1 outer schema is a separate CLI contract from internal Go state.
Missing, zero, null, non-integer or duplicate schema versions fail as
invalid (exit 2). Unrecognized positive future versions fail explicitly as
unsupported (exit 4), without silently assuming v1. A valid schema v1
request that selects a domain-unsupported feature (such as IPv6 Link
Addresses or an unsupported GRE encapsulation) also exits 4; malformed
or otherwise invalid configuration exits 2. An unregistered backend
is explicitly unsupported rather than accepted silently.

This input is **not** a `stl://` pairing link and cannot carry recipient
WireGuard private keys, IPsec PSKs or arbitrary commands. Duplicate/case-
variant keys (also inside the Link), unknown fields, arrays, null values,
trailing JSON values and oversize input are rejected before runtime
creation. Do not put sensitive setup links into shell command arguments.

`ensure` and `remove` both call the **same canonical Engine** used for
restore: inspect, plan, owner/resource-lock, re-inspect, validate, apply,
verify, commit desired state and persistence/rollback compensation. They
do not implement a second networking lifecycle. `ensure` is idempotent
where the backend supports convergence; `changed=false` means no backend
mutation was required after inspection, not proof that the remote peer
responds. Removing a Link requires repeating the **exact stable Link ID**
after `--confirm` and can remove only Engine-proven owned resources.
`remove` must never silently remove another same-peer Link.

`--json` success returns top-level integer `schema_version: 1`,
operation, link_id, changed and removed. A failure returns a nonzero exit
and redacted versioned error. When an operation may have changed host or
committed state, its JSON indicates `outcome: "unconfirmed"` and
`reconciliation_required: true`, with any Engine-provided partial
result in snake_case. These are conservative reconciliation signals,
not a claimed successful apply. Do not retry a failed stateful operation
blindly; inspect `link list` and `link status` first.

Exit codes remain 0 on verified Engine success; 2 for invalid input/usage,
4 for unsupported backend, and 1 for other operational, state or rollback
failures. The commands use a five-minute signal-aware deadline and the
Engine's cancellation-detached, bounded owned rollback. No global tuning
or unrelated host networking changes are permitted by this CLI layer.

These commands are not a replacement for the unfinished **interactive
Create / Import / Manage** user experience and protected secret-bearing
recipient import flow. They do not establish live FOU/GUE bidirectional
traffic or release E2E acceptance.

## Explicit plaintext GRE setup-link export (Issue #8)

`stl link export <link-id> [--json]` deliberately exports an
**already-saved GRE Link's** versioned `stl://2.` Setup Link for the
other endpoint. It uses the **same canonical pairing model and receiver
inversion** as `stl link preview --stdin`; no alternate encoder or
backend setup method is introduced. For example:

~~~sh
stl link export lnk_<32-hex-characters>
stl link export lnk_<32-hex-characters> --json
~~~

Human output contains a canonical pairing copy block and the encoded
URL; machine output contains integer CLI `schema_version: 1`, separate
`pairing_schema_version`, Link ID, backend/mode metadata and an
explicit `setup_link`. Both are **intentional export outputs**, not
status or diagnostic responses. The output reveals the Link's endpoints,
display-name metadata (encoded in the URL), GRE key identifiers and
other configuration. An included SHA-256 checksum detects accidental
damage, **not** authenticity. GRE does not encrypt or authenticate traffic;
share setup material with the intended peer rather than public logs.

The command is read-only and does not inspect, repair or apply the Link.
Existence in saved desired state **does not prove a working tunnel**.
Only currently credential-free GRE exports are supported. IPIP awaits its
complete backend contract; WireGuard and IPsec remain explicitly
Unsupported until reviewed secure recipient credential generation,
export, storage and apply exist. Export never silently omits private
keys/PSKs to manufacture a broken setup link. Confirm the configuration
via the existing `link preview` before a separate authorized apply
step. No new command automatically applies an exported setup link.
