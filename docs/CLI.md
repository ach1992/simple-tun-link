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

`link ensure`, create/import, active diagnostics commands and broader
interactive UX remain pending under Issue #10. No new mutation route is
introduced by the read-only commands.
