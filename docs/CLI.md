# STL CLI — implemented read-only commands

STL's broader interactive task-first interface, create/import/manage commands,
and stable automation lifecycle are owned by Issue #10.
This page describes **only the implemented commands**; it does not promise
unimplemented functionality.

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
- `stl link restore --all`: existing host persistence/reapply command.

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
- Read errors: `{ "schema_version": 1, "error": { "code": ..., ... } }`;
  raw state-file content, arbitrary backend output/errors, display names
  and credentials are not included.

Exit statuses for these read commands: `0` verified success; `2` invalid
argument or missing Link ID; `4` unsupported live backend; `1` state or
inspection failure. A failure cannot silently become a success even when
the requested Link exists in saved configuration.

These commands read STL's existing local desired-state file. The state
directory typically belongs to a privileged operator; access failures
produce a structured error rather than creating/replacing files.

`link ensure`, create/import, optional throughput, non-GRE diagnostic
adapters and the broader interactive UX remain pending under Issue #10. No new mutation route is
introduced by the read-only commands.

## Explicit Link lifecycle commands — Issue #10

The following operations **change the selected host's network and durable
desired state**. They are not equivalent to read-only status, preview or
diagnostics. Use only with operator-approved local/peer address, source and
backend configuration on a host you are authorized to administer:

~~~sh
stl link ensure --stdin --json < /path/to/desired-link.json
stl link remove lnk_<32-hex-characters> --confirm lnk_<same-32-hex-characters> --json
~~~

For ensure, stdin contains one bounded, strict JSON object representing the
existing backend-neutral `domain.Link` (ID, backend, encapsulation, underlay
local/peer, Link Address local/peer, optional display name and GRE settings).
It is **not** a `stl://` pairing link and cannot carry recipient WireGuard
private keys, IPsec PSKs or arbitrary commands. An unknown backend is
explicitly unsupported rather than silently accepted. Duplicate/case-
variant keys, unknown fields, arrays, null values, trailing JSON values,
oversize input and invalid Link configuration fail before runtime creation.
Do not put potentially sensitive setup links into shell command arguments.

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
