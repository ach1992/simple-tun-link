# Security Model

This document describes STL's **operational security boundaries**. The
[PROJECT-SPEC](PROJECT-SPEC.md) owns product intent;
[ARCHITECTURE](ARCHITECTURE.md) and
[ADR-0005](decisions/ADR-0005-scoped-vici-ipsec.md) own the Engine and
IPsec runtime design. Historical source-only implementation stages are
recorded in Git/Issues, not as contradictory live requirements here.

## Transport guarantees and operator choice

The Link abstraction is an IP connectivity abstraction, **not** a
promise of confidentiality, authentication, evasion or universal reachability.

| Backend | Confidentiality and peer authentication |
|---|---|
| GRE, IPIP, Native/FOU/GUE | None provided by the tunnel itself; a GRE key is an identifier, not cryptography |
| WireGuard | Encrypted/authenticated transport when properly configured |
| IPsec/IKEv2/XFRM | Encrypted/authenticated transport when properly configured |

STL must accurately expose these differences and allow informed
operator choice. Do not claim that any transport is "undetectable" or
will automatically traverse every provider firewall/NAT.

## Credentials, private files and sensitive Setup Links

Ordinary State, inventories, status, diagnostics, human errors,
structured logs and generic JSON must never reveal WireGuard private
keys, IPsec PSKs, raw private Setup Links or arbitrary untrusted
daemon/kernel output. No credential is recovered from display names,
filename patterns or logged command-line arguments.

- Each local WireGuard private key and each IPsec PSK belongs in its
  backend-specific owner-private credential store under STL's private
  State root. Reject symlinks, unsafe ancestors, wrong ownership,
  unexpected inode/link type, incorrect mode or mismatching key identity.
  Files are published no-replace and durably synchronized; a failed
  write/activation is not permission to delete an orphan credential.
- WireGuard local keys are provided to `wg` through a verified private
  file descriptor, not a process argument or arbitrary shell text.
  Never store a generated **recipient** private key in the
  initiator's ordinary desired Link State.
- IPsec uses a fresh 256-bit, Link-scoped PSK for supported operational
  Quick Links. It remains in a protected `0600` credential file and
  in intentionally sensitive pairing only; generic JSON has public
  identity/configuration, not PSK bytes.
- Guided WireGuard/IPsec sender creation retains the **original**
  receiver Setup Link separately under STL-owned
  `receiver-handoffs/` (`0700` parent, `0600` verified per-Link
  file). Retention lasts until an independently confirmed DELETE,
  including across import, reboot and Link removal. A later SHOW
  requires a real interactive terminal, fresh consent and exact
  matching of the still-committed sender identity. SHOW necessarily
  exposes the secret on the screen/scrollback; disclose this clearly.
- A saved receiver handoff is not regenerated from public State.
  Missing, altered or deleted sensitive originals require controlled
  recovery or a fresh authorized setup, not silent rekey or adoption.
  `recover-handoff` may republish only an original, safely retained,
  digest-matching crash-staged private offer with matching pending
  intent/credential; it performs no kernel/daemon activation.
- A Quick Link can contain the **receiver credential**. It is
  explicitly **SENSITIVE**, not encrypted merely because it is
  encoded and checksummed. Deliver it over a trusted channel and
  verify the sender independently. Import preview reports presence
  of credentials, not their value.

### Credential lifetime and removal

A successful local `remove` is not authorization to indiscriminately
destroy key material. WireGuard/IPsec key retirement is separate and
bound to the precise, durably successful canonical Remove receipt,
corresponding original credential identity and absence of active
owned Link resources. A failed/uncertain Remove, matching filename,
or missing saved Link does **not** authorize retirement. Removal and
retirement must be idempotent and fail closed on inode/credential
mismatch; file deletion does not mean physical-media sanitization.

WireGuard protected sender staging and IPsec protected pending intent
use public-only durable reservations and exact handoff digests. Resume,
activation and recovery revalidate the original complete Link identity.
An IPsec removal/retirement receipt reserves the old Link ID across
backends; neither a new WireGuard sender nor a new IPsec stage may
resurrect that retired identity. Orphan keys, receipts or unfinished
journals require deliberate operator reconciliation, never wildcard
cleanup or guessed consent.

## Untrusted input and machine output

- All `stl://` payloads are untrusted data. Validate scheme/version,
  bounded decoded size, known fields, mode/backend compatibility,
  checksums and exact sender/receiver inversion. Never evaluate shell
  text, process arbitrary paths or mutate the host during preview.
- Import is a separate, explicitly confirmed effect. Its digest/token
  binds the reviewed *exact* payload; it does **not** authenticate who
  sent that payload.
- Reject invalid/unsupported versions and unsafe or duplicate fields;
  neither unknown JSON nor a future schema silently changes the
  semantics of an existing consumer contract.
- Human terminal formatting must not modify, wrap or log opaque IDs,
  commands or sensitive URL bytes. Machine `--json` stdout is reserved
  for safe versioned data; raw subprocess output does not enter it.
- Machine lifecycle errors report bounded reason codes, stage and
  uncertainty rather than private desired state, credentials, raw
  command output or unexpected host paths.

## Canonical host-change authority

Only the canonical Engine and its qualified installation/service
adapters may change the host. Local diagnostics, `status` and
`doctor` do not install packages, load modules, start daemons, repair
configuration or assume remote connectivity. Explicit throughput and
quality diagnostics may transmit bounded traffic, but never silently
alter routes, MTU or firewall state.

Before mutation, inspect intended resources, independently verify
their identity, take relevant locks, re-inspect where state can change,
preview material effects and obtain the required operator approval.
Rollback and Remove affect **only proven STL-owned objects**. Unknown
or partially applied work must report an unconfirmed result and a safe
reconciliation route, not optimistic success or a blind retry.

Ordinary host-to-host Links do not justify a default-route rewrite,
firewall flush, global IP forwarding, globally disabled `rp_filter`,
takeover of a primary network manager or deletion of sibling/foreign
Link objects. Valid user-approved advanced settings are not prohibited
for arbitrary policy reasons, but they still require technical and
ownership validation.

## IPsec runtime and strongSwan safety

IPsec is conditionally available only after verifying the complete
STL-owned native-exclusive strongSwan runtime, **not** merely finding
`swanctl` or observing no UDP listener:

1. Verify protected, exact-origin native config/systemd publication
   and provenance (root-owned paths, secure inodes, xattrs and
   receipts), actual loaded unit with effective overrides,
   trusted root executable and process identity.
2. Verify exclusive process/VICI peer/socket ownership, IKE UDP
   500/4500 ownership, VICI namespace and Linux XFRM claims.
   Name-shaped objects, aliases and partial inventory are not proof
   of ownership; an absent/not-found private-unit placeholder is
   not itself a real foreign service.
3. Prove the **effective** running strongSwan logger configuration
   disallows secret-bearing CFG debug before PSK transfer. A
   byte-identical config file or read-only doctor result alone is
   insufficient; uncontrolled `DBG4` PSK traces are unacceptable.
4. Use per-Link VICI operations under the Engine's canonical
   maintenance/Link/resource locks and durable journals. Never bulk
   load/reload/unload another tenant's daemon credentials, terminate
   unrelated SAs, delete a name-matching unowned XFRM interface, or
   infer original ownership from an alias or `if_id`.
5. Before effectful package preparation, attest the supported trusted
   distro APT index and signature against the official archive keyring,
   and reject unverified systemd alias/drop-in/service ownership that
   could run during package hooks. Disclose that packages, unit state
   or interrupted dpkg may persist after cancellation/failure.
6. A verified **newly installed** vendor unit introduced by STL's
   exact authorized package transaction can be disabled only under
   matching provenance and verified admission. An independently
   verified **pre-existing official distro** `strongswan.service`
   may be stopped/disabled only with a *separate exact*
   `STOP strongswan.service` confirmation, an explicit
   warning that active VPNs may disconnect immediately, and fresh
   eligibility/identity checks under the exclusive maintenance
   gate. Generic `PREPARE` does not authorize service disruption.
   Other pre-existing, ambiguous or foreign services, ports and
   configurations must not be adopted, stopped, masked or overwritten.
   Offer manual remediation and explicit `RECHECK` when needed.
7. On interruption, VICI issuing journals, XFRM original-ifindex
   ownership and per-Link Remove receipts decide what can safely
   be reconciled. Incomplete provenance is a blocker for that
   IPsec operation, not a reason to disable GRE/IPIP/WireGuard.

Operational details and rationale belong to
[ADR-0005](decisions/ADR-0005-scoped-vici-ipsec.md) and
[ARCHITECTURE](ARCHITECTURE.md), not duplicate implementation
chronologies. `stl doctor ipsec --json` is a safe first inspection,
not proof of current IKE/ESP traffic.

## Failure output and diagnostics

Keep one backend-neutral, concise operator model: what happened,
what was verified versus unknown, what may have changed, a safe reason
code and one next action. Logs may include safe operation, Link ID,
backend, stage, duration and result; they must not include raw `argv`,
PSK/private keys, full Quick Links, VICI payloads, XFRM SA key material,
untrusted daemon stderr or unvalidated configuration contents.
Optional verbose/support modes obey the same exclusions.

A failed or ambiguous service read is not equivalent to a detected
foreign daemon. The operator must be able to distinguish absent,
unprovisioned, blocked, unknown and partly mutated situations without
turning read-only diagnosis into a privileged repair operation.

## Privilege, dependencies and vulnerability reports

Kernel interfaces and owned systemd services ordinarily require root
or equivalent capabilities; keep the privileged surface small and
explicit. A future network-facing integration must authenticate and
authorize its caller and enforce local permissions rather than
treating API access as an unconditional right to mutate the host.

Keep Go modules, third-party binaries and CI/installer dependencies
minimal and provenance-checked. Use GitHub **private vulnerability
reporting / Security Advisories** for suspected security defects,
rather than disclosing exploit details in a public Issue.

## WireGuard over WSS/TLS R1 (candidate security boundary)

WSS is a link-scoped carrier around the **real kernel WireGuard** backend,
not a second VPN engine or a generic bypass route. The listener requires
trusted mTLS: separate 2-month leaf certificates (server/client purpose),
a 3-month Link-specific CA, exact server identity/SAN and verified private
keys. One independently generated 256-bit per-Link bearer and fixed destination
restrictions protect each authorized WSS forwarding path. Do not assert
strict leaf-CN pinning: the per-Link CA **plus independent bearer/path scope**
is the accepted security model. CA signing material is never persisted.

All private keys/authorization files are owner-private 0600 beneath
verified descriptor-traversed directories; bearer values must never reach
argv, ordinary State, public diagnostics or normal logs. Wstunnel v11.0.0
must match the release archive and executable digests pinned in the installer;
foreign executables are never adopted. Installer ownership and path admission
are rechecked at runtime. Systemd starts exact link-owned transient processes
with bounded readiness and scoped stop; process running is not proof of
successful mTLS handshake or end-to-end traffic.

Before the kernel WireGuard UDP port is created, a Link-specific nftables
ingress guard drops non-loopback direct UDP to that port; only the loopback
forwarder may reach the socket. Host firewall coexistence, foreign services,
UDP/TCP port collisions and owner claims must be checked before mutation.
No global firewall flush or system-wide service restart is allowed. The
Engine journals/verifies its one Link; rollback/Remove can affect only
resources attributable to that identity. WSS Remove writes a nonsecret,
exact Link-specific credential-retirement receipt in the same durable State
transaction as Link deletion. It then verifies all host resources absent,
retiring the credential files; if interrupted, receipt-bound retire-wss is
the explicit recovery action. External user-chosen exported copies remain
the operator's data-retention responsibility.

Security is not bypassed by CLI/menu success messages. Real accepted mTLS,
kernel WG handshake, scoped ingress, private ICMP/TCP/UDP and cleanup must
be independently tested. In isolated tests the actual transport, kernel
networking and nft guards operate in rootless namespaces; a disposable
process supervisor **simulates systemd control only**, so those tests do not
prove a real host's systemd reboot restore. Physical two-server testing,
independent review, Main merge and publication remain distinct gates.

### R2 WSS crash-journal security boundary

The pre-effect journal records a public transaction reservation, **not
proof of original host ownership**. Neither a table name, ifalias,
systemd unit name, public WG key nor journal nonce alone authorizes
cleanup. A failed/uncertain journal fsync prevents Backend Apply.
Automatic Ensure/Remove/reboot replay cannot cross an unresolved
transaction. Vacancy-only reconciliation is read-only until an
exact journal-only State commit; any observed or uncertain host effect
blocks it. It preserves all private credentials and never changes
firewall, network or systemd state. Stronger orphan compensation
requires independently proven original-object identity and a separate
review/authorization gate.
