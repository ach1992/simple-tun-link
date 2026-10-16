# STL CLI — operator menus and stable machine commands

The complete guided operator interface ships with
[Stable v0.1.0](https://github.com/ach1992/simple-tun-link/releases/latest).
The historical [immutable rc.6](https://github.com/ach1992/simple-tun-link/releases/tag/v0.1.0-rc.6)
contains only its earlier feature subset. The older rc.2 retains a
different menu. Versioned machine CLI/JSON contracts remain unchanged.

## Interactive terminal presentation (Issue #93; rc.4)

The following improvements were developed after rc.3 for the rc.4
pre-release. They do **not** change an installed rc.3 executable or
prove live WAN connectivity on the Owner's hosts.

On a real compatible interactive terminal, STL redraws a single screen
at a time rather than appending repeated menus. Human output uses
semantic colors (blue section names, cyan selections/values, green
confirmed success, yellow warnings, red failures), aligned labels and
menu columns. Each action's result (including an incomplete operation,
recovery guidance or the complete copyable Setup Link) remains visible
until an operator presses Enter to return; confirmation for any mutation
still requires the separate fresh **YES/REMOVE/SHOW/DELETE** gates.

NO_COLOR (present even with an empty value), TERM=dumb and redirected
stdout disable all ANSI including cursor/screen-clearing escapes;
CLICOLOR=0 disables semantic color. This does not change machine output. To retain an append-only interactive
display for capture/troubleshooting, set STL_NO_CLEAR=1. Only the
visible screen is cleared, not scrollback. Machine CLI/JSON never
contains terminal color or screen-control escapes. Numeric input,
TTY-only secret disclosure, local-versus-peer health distinctions and
the canonical Engine's authority remain unchanged.

| Journey | Human-visible step | Important safety boundary |
|---|---|---|
| Home | Version, sanitized host, IPv4 candidate, saved count, aligned tasks | Saved is **not** connected; source route rechecked at setup |
| Create guided | Backend -> peer -> tunnel IPs -> optional Advanced -> clean preview -> YES -> result | No pre-confirmation mutation |
| Create manual | GRE/IPIP Native, reciprocal endpoints, optional numeric GRE receive key | GRE key is not encryption |
| WireGuard/IPsec | Capability and UDP setup -> review -> YES -> immediately copyable protected offer in rc.5 | Real TTY and verified saved identity; later Share still needs fresh SHOW |
| Import | Plaintext or hidden protected paste -> reversed IP preview -> YES -> result | Full link required; sensitive payloads never shown by preview |
| Manage | Numbered saved list -> selected Link actions -> result -> Enter | Status read-only; Remove is fresh TTY-only confirmation |
| Share / Delete handoff | One uncluttered copy line; protected SHOW or DELETE separately | Never regenerate deleted receiver keys |
| Diagnose | One Link/all -> read-only observations -> explicit next step | No automatic repair or false peer-healthy claim |
| Settings / maintenance | Read-only host detail, update/uninstall guidance | No implicit host modification |
| Incomplete operation | Stage, stable reason, rollback uncertainty, read-only next check | Never silently retry or delete a possibly owned unit |

For failure classification, the new source may identify the specific
trusted persistence check that failed (for example
restore_enablement_unverified or restore_unit_identity_conflict).
rollback_completed_unverified **still means** compensation reported
success but its resulting host state was not independently re-verified.
It is not the original fault. Never infer a live host's cause from that
recovery code alone; see [read-only host checks](INSTALL.md).

Core operator choices (rc.4):

- Start: stl menu (or stl in an interactive terminal). The new compact
  Home includes version, sanitized host, local IPv4 **candidate**, and
  saved tunnel count. More detailed OS/kernel/repository facts appear
  under Settings. The published rc.3 still prints a larger banner.
  Neither presentation is evidence of peer reachability.
- 1 Create tunnel: GRE Native (Enter/default), WireGuard, and IPIP
  Native. Less common FOU/GUE/IPsec live under Advanced. Without-Link
  GRE/IPIP Native lives under Manual connection. Accept suggested private
  Link IPs by Enter; THIS server's underlay source IP is detected from
  the kernel route. Or enter both private IPv4 endpoints directly.
- 2 Import setup link: choose **visible plaintext** GRE/IPIP or
  **hidden protected** WireGuard/IPsec. Invalid/malformed/truncated
  pastes can be retried. Import remains canonical preview/Engine apply.
- 3 My tunnels: choose a **number**, then Status, Test, repeatable
  Setup Link Share, read-only two-server Connection details, Remove
  or Delete saved protected receiver Setup Link. GRE/IPIP Share
  regenerates from nonsecret State. For WireGuard/IPsec the exact
  original private per-Link handoff is displayed **only after a fresh
  SHOW in a real TTY**, with ownership, mode and complete saved-Link
  identity checks. The separate explicit DELETE removes only the
  receiver handoff, not the active tunnel or local key.
- 4 Test connectivity: select a numbered Link or a for all; bounded
  observation only, not automatic repair.
- 5 Settings and 7 Uninstall are read-only/guided; 8 exits.
  In rc.6, Update can delegate to the canonical installer only
  after a positively immutable official release and fresh root/TTY/UPDATE
  gates; every unverified/mutable release stays manual guidance only.

A failed/uncertain menu operation must **not exit the terminal loop** or
automatically repeat the mutating command. Machine CLI and JSON contracts
remain independent of the menu's changing text.

### rc.5 operator UX enhancements (Issue #95)

The historical rc.4 artifact keeps its earlier screens. rc.5 adds
read-only per-type host availability hints
(`Precheck OK`, `Unavailable` or `Check needed`) in Create, with a separate
explanation choice; final Engine/strongSwan admission remains authoritative.
No prerequisite packages or services are changed by this menu check.

After successful, freshly **YES**-confirmed guided WireGuard/IPsec Create in
a real interactive terminal, the complete original sensitive receiver Setup
Link is shown **immediately** as one copyable line. It remains stored in an
owner-private file; retrospective My tunnels -> Share still requires fresh
SHOW. Scripts, redirected streams, JSON, status, errors and diagnostics do
not disclose protected links. Retained offers are never regenerated.

Local Status reports verified interface identity and **does not measure peer
connectivity**. Test connectivity reports five bounded ICMP echo quality
samples when probing can run, including replies/sent, packet loss, measured
min/avg/max RTT and consecutive-reply variation. It distinguishes no echo
reply (peer not confirmed) from unsupported/failed probing (unknown); no
five-sample result promises long-term stability. The suggested MTU is
labeled verified, manual or conservative/unverified; RX/TX are cumulative
interface counters, not proof of fresh successful traffic. A single-Link
connection test obtains cumulative counters from a **separate read-only Status
observation**, not from the quality JSON; an unavailable Status observation
does not invalidate separately verified ping samples. Check all Links uses
the existing all-Link diagnostic contract, not a second probe engine.
Semantic terminal colors have matching readable noncolor labels.

### rc.6 maintenance UX refinement (Issue #99)

These features first ship in rc.6 and are **not** included in the
historical published rc.5 executable.

- Capability badges no longer equate an unsuccessful read-only kernel/tool
  query with permanent lack of tunnel support. FOU/GUE share a single
  underlying prerequisite; IPsec ESP/NAT-T share XFRM plus `swanctl` and
  **still require separate STL-exclusive strongSwan operational admission**.
  A found `fou` module with a failed kernel query is `Needs setup`; other
  unconfirmed observations are `Check needed` until positively verified.
  Details group common causes and provide safe `ip fou show`, `modinfo fou`,
  `command -v swanctl`, `stl doctor ipsec --json` guidance without
  loading modules, installing packages or starting services.
- Operator Update lists at most three complete published official GitHub
  releases over bounded HTTPS (no tokens), **including mutable releases
  marked manual-only**. Only a positively confirmed `immutable:true`
  release can be automatically selected for root execution of its canonical
  installer. Missing, false or malformed immutability **fails closed**;
  asset filenames, HTTPS, a Bash syntax check or later binary checks do not
  make a mutable downloaded script trustworthy. An eligible automatic
  update additionally requires a forward same-line RC upgrade, actual root
  interactive terminal running installer-owned `/usr/local/bin/stl`,
  backups/quiescence and a fresh `UPDATE` confirmation. No parallel update
  or rollback engine exists. All other paths show manual verification
  guidance **without a privileged mutable-tag curl-to-shell command**.
  Historical rc.5 remains unchanged and `immutable:false`. rc.6's
  automatic Update requires an Owner-approved immutable GitHub release;
  older mutable releases remain manual-only.
- Operator Uninstall groups next steps and the existing read-only
  `stl maintenance pre-uninstall --json` and trusted installer guidance.
  It **does not perform an automatic mass deletion**: multi-Link resource
  ownership, uncertain rollback and separately retained sensitive receiver
  credentials make irreversible all-Link purging unsafe to infer from a
  single menu choice. Individual exact-identity Engine removal remains
  deliberate, and confidential leftover material needs separate retirement.
- Common human fields/notices wrap explanatory **prose only** on narrow
  terminals; copyable Setup Links, opaque IDs, URLs and shell commands
  remain exact. Machine JSON and CLI contracts are unchanged.

The controlling user report, accepted scope and tests live in
[Issue #99](https://github.com/ach1992/simple-tun-link/issues/99).
The historical published rc.5 remains unchanged; rc.6 contains these features.

### rc.6 on-demand GRE/IPIP module preparation (Issue #101)

For any backend, Create first takes a **read-only** selected package
inventory using the byte-identical canonical installer embedded in the
verified STL binary. Native GRE/IPIP and WireGuard dependencies can be
prepared on demand after an installed root terminal shows the exact
missing set and obtains a fresh `PREPARE` confirmation. The canonical
installer holds the exclusive installed maintenance gate and rechecks the
missing package set before APT. **Missing strongSwan packages are manual
administrator work**: STL refuses unattended IPsec APT because a vendor
package's systemd hooks may start foreign aliases, drop-ins or generated
units that cannot be safely excluded across supported distributions.
Installing the packages never authorizes STL's separate private service.
Non-root or redirected selections remain observational and cannot
start package mutation. Final Engine admission remains authoritative.

#### Stable v0.1.0 / #105: one-consent native IPsec setup

In Stable v0.1.0 (not the historical immutable rc.6 release), selecting
**Advanced → IPsec ESP/NAT-T** on a supported clean installed-root terminal
presents the signed distro APT package/dependency plan, checks foreign systemd
unit/daemon/configuration and UDP 500/4500 occupancy, and requests exactly one
fresh **PREPARE** for package installation **and** qualified private strongSwan
provisioning. During distro package installation, a newly introduced vendor
service may be temporarily started/enabled by signed distro hooks; STL stops
and disables only the verified new vendor unit before attempting its own
receipt-bound private unit. It verifies actual runtime admission and resumes
the selected IPsec Create. A separate **YES** still controls Link creation.

**Cancellation/partial failure:** before PREPARE, no effect. After PREPARE,
APT effects can persist even if later stages or the Link Create are cancelled;
the UI must not describe them as rolled back. The selected APT index must be
verified against the official distro archive signing key, not merely an APT
trusted key or an Origin label. Alias/prefix systemd drop-ins are checked
before package hooks. An interrupted APT transaction reports observed
package/dpkg and vendor state, blocks automatic retry, and skips private
service admission. Partial package, vendor-unit or
private-receipt states are preserved for targeted diagnosis; **stl doctor
ipsec --json** is read-only. Unknown/foreign ownership blocks only IPsec,
not other tunnel backends. The installed rc.6 release does **not** provide
this flow.

After selecting GRE/IPIP FOU or GUE (or a native GRE/IPIP type with a
missing kernel driver), STL separately rechecks the selected modules.
If a required module is verified **on disk but inactive**, the shipped
rc.6 path asks an installed-root operator for a separate `PREPARE`.
In **Stable v0.1.0 / Issue #106**, when missing packages and missing
modules affect the **same selected GRE/IPIP tunnel**, one PREPARE preview
discloses both the exact APT dependency plan and the possible selected
kernel modules. After package preparation, independently verified,
loadable missing modules can be loaded under that same consent without a
second PREPARE; otherwise module-only preparation still requires its own
fresh PREPARE. Link Create always retains a separate YES. The selected
`ip_gre`, `ipip` or `fou` module is loaded only under an installed shared
maintenance lease that rechecks executable identity after waiting. The
single controlled loader uses `modprobe --config /dev/null --ignore-install`
with a sanitized process environment and a bounded dependency preview,
rejecting foreign install hooks and any dependency that cannot be
attested as root-owned under the running kernel's module tree. Unknown
or ambiguous states fail without loading. The kernel is rechecked before
the ordinary Create wizard resumes.

The preparation step does **not** create a Link, edit State, routes,
firewalls, services or packages. It is not triggered by opening a menu,
running diagnostics, returning to a selection, redirected input, or
cancelling a prompt. Kernel loading is a host-wide action which may
outlast this invocation; STL deliberately does not auto-unload after
failure, since another process may use the module. Availability still
does not prove network reachability.

After a Link has been successfully committed, the canonical owned
`simple-tun-link-restore.service` and Engine restore locks can load only
that **committed GRE/IPIP Link's** allowlisted, proven-on-disk missing
driver(s), then re-run the canonical Engine for actual kernel/Link
verification. No global `modules-load.d` file, startup shell or implicit
module unload is created. Unknown or failed module loads fail the affected
Link while independent Links continue. Whole-guest reboot/traffic
acceptance is still tracked under
[Issue #101](https://github.com/ach1992/simple-tun-link/issues/101).

rc.6 adds a separate **opt-in** IPsec service source preparer after
successful package checks. Only an installed root real terminal can freshly
confirm `PROVISION-IPSEC`: the program first requires no existing/conflicting
native publication records, no foreign daemon or IKE UDP ports, and only
inactive/disabled known vendor strongSwan units. It takes an exclusive
installer/Engine maintenance gate, uses the receipt-bound no-clobber
config/unit publishers and does `daemon-reload`
without starting the daemon. The EFFECTIVE loaded unit (including
FragmentPath, drop-ins, execution directives and controlled environment)
must pass PRE-START admission before the first private service start.
Only after successful post-start process/VICI/UDP admission is the
STL-owned boot enablement edge durably published and rechecked. A
foreign override or partial publication never authorizes later automatic
retry. Full native IPsec runtime admission still applies before any
IPsec Create. It NEVER stops/enables/disables/adopts any vendor service,
copies foreign configs, or installs packages in this
step. If any origin publication or service transition is partial or
uncertain, **do not retry automatically**: the exact protected artifacts
are retained for an administrator to reconcile. No unverified service
is declared ready. Disposable-guest service and traffic acceptance
remain a separately required gate.

These features first ship in rc.6; the historical rc.5 binary does not
contain them.
Installing `swanctl` alone cannot satisfy the IPsec runtime gate.

### Manage Links — confirmation and privacy

Remove is available **only on a real interactive terminal**. A
Link-specific read-only preview is followed by freshly typing REMOVE.
Queued input is discarded first. The Engine compares the preview's saved
intent under its Link lock before removing only owned resources; concurrent
changes block removal. Ordinary scripting still uses the exact-ID
stl link remove <id> --confirm <id> command, not terminal parsing.

GRE/IPIP Setup Link re-export from saved nonsecret State is
repeatable through the canonical CLI export operation. The guided
WireGuard/IPsec sender automatically retains its **original** receiver
handoff in a separate STL-owned private state directory:
receiver-handoffs/ (0700 parent, per-Link 0600 file). This is
intentionally distinct from ordinary desired State and local sender
credentials. Guided Share requires a real terminal, fresh SHOW, a
no-follow/single-link/owner-private file check and complete match
against the still-committed sender Link and credential kind. The
default menu does not reveal the URL, and normal errors, inventory,
status, diagnostics and JSON never emit receiver secrets.

Deleting this file is a separate freshly confirmed DELETE operation;
it does **not** rekey or tear down a working tunnel. Removed tunnel
State does not automatically erase the handoff; only the operator may
remove it. Old rc.2 or explicit CLI handoffs at other filenames are
not automatically searched/adopted. Do not treat a missing or deleted
receiver credential as reproducible from the normal Link State.

### All-Link diagnostics center (read-only, issue #9/#10)

The CLI now exposes one coherent operational view of **every saved Link**:

~~~sh
stl link diagnose --all
stl link diagnose --all --json
stl link diagnose --all --timeout 10m --json
~~~

The rc.3 menu's **Test connectivity** task accepts a Link number or
`a` for all; degraded/unsupported results return to the task menu instead
of exiting it. Ordinary per-Link `stl link diagnose <link-id> [--mtu <bytes>]
[--json]` remains available with the **same** backend capability,
identity/counter validation and Link-scoped non-fragmenting ICMP probes.
There is no parallel probing implementation, no administrative control
command and **no automatic repair**.

The v1 batch JSON contains `schema_version:1`, `operation:
"link_diagnose_all"`, `outcome` (`complete` or `interrupted`),
`total`, `observed`, `blocked`, `unknown`, and ordered `checks`.
Each check identifies a Link by safe ID/backend/mode/address summary and
provides a stable `status`, `reason_code`, `summary` and `next_step`.
On successful measurement it also contains a compact `observation`
with PMTU selection, bounded quality samples, **when measured**
owned RX/TX counters and their units, plus a last-observed WireGuard
handshake timestamp when available. Conditionally admitted IPsec can
verify an owned SA and Link Address response; it optionally reports
read-only **XFRM interface packet counters** only when exact ownership
and actual kernel stats are independently verified. Otherwise its `rx`,
`tx` and `counter_unit` keys are **absent**, not misleading zeroes;
human output says "not measured". A verified measured zero on any
measuring backend remains numeric `0`.
Arbitrary Link display names, sensitive setup links, private keys,
credential files and raw subprocess error/output are **not** included.

The statuses distinguish **evidence**, not persistent health guarantees:

- `observed/link_peer_replied` means a verified interface received one or
  more peer echoes in a short sample; it is not a future availability SLA.
- `unknown/link_probe_no_reply` means an attempted probe got no reply;
  ICMP policy or path issues may explain this, so the transport is not
  categorically declared down.
- `unknown/link_probe_incomplete` or
  `unknown/diagnostic_observation_unverified` means the probe or identity
  observation was incomplete.
- `blocked/diagnostic_capability_unavailable` and
  `blocked/ipsec_runtime_not_registered` describe unavailable backends;
  IPsec is **never activated** or inferred healthy. The latter has the
  **same exact `next_step: "stl doctor ipsec"`** as per-Link IPsec
  `status` and `diagnose`: this is the supported, read-only prerequisite
  inspection command, not permission to activate strongSwan.
- `unknown/diagnostic_interrupted` includes the unprocessed Links if the
  batch is canceled or exceeds its configured total time budget.

The report uses a single time-local saved-state snapshot, stable Link-ID
ordering and independent per-Link checks. Each Link gets its existing
**35-second maximum probe budget**; there is no fixed cap on the number of
saved Links. For a large collection, optionally set the **total** `--timeout`
to a positive Go duration such as `10m` or `1h`; the flag rejects
ambiguous/malformed durations. The deadline starts **before saved-state
inventory loading and diagnostic runtime initialization**, not just before
Link probes; those stages and all child Link probes share the deadline.
If the inventory is known when the deadline expires, the interrupted batch
retains every Link ID with incomplete observations marked unknown; neither
the current Link nor unprocessed siblings can be promoted to healthy.
If the deadline expires **before a trustworthy inventory was loaded**, the
command instead emits the existing version-1 `error` envelope with
`reason_code: "diagnostic_interrupted"`, an explicit next step and exit
`1`—it **does not invent an empty batch**. Synchronous filesystem
operations may need to return before cancellation can be reported, but
their elapsed time still consumes the requested total budget; no later
live probe is started after expiry. This does not guarantee an atomic
host-wide snapshot: Links may change while observation runs.

Exit statuses are `0` when every observed Link received a peer reply (or
when the saved inventory is empty, explicitly marked as such); `4` when
one or more Links are blocked but none is unknown; and `1` when any Link
is unknown or the run is interrupted. Invalid flags return `2` with the
ordinary v1 error envelope. A `0` code on an empty inventory means that
the inventory query completed, **not** that a network Link is healthy.

### Operator recovery fields (shared status/diagnose/mutations)

See [operator failure-to-recovery workflow](OPERATOR-RECOVERY.md) for
Engine stage evidence, rollback confidence, and read-only recovery checks.

The existing public v1 `error` object now consistently emits
`reason_code` and `next_step` through a shared safe fallback for
invalid/unsupported/conflicting/inspection/plan/apply/verify/state/rollback
errors. Backend-specific validated codes, such as
`ipsec_runtime_not_registered`, retain precedence. Human errors print the
same code and a `Next:` action; lifecycle JSON still marks unconfirmed
mutation results as `outcome:unconfirmed` and
`reconciliation_required:true`. This additive guidance never claims that
a partially applied or rolled-back Link is safe to retry without inspection,
and it never copies backend/tool causes into operator output.

### Guided creation and straightforward GRE Native pairing

In the **rc.3 operator-first menu**, choose 1 Create tunnel ->
1 GRE Native (or press Enter to select the default). The user enters
the OTHER server's reachable IPv4; STL detects THIS server's
underlay/source IP from a local kernel route. The wizard automatically
suggests two unused private Link IPs: **Enter accepts the pair**,
or the user can enter both local and peer private IPs directly
(including valid 10.235.1.1 and 10.235.1.2 /30 hosts). Before
confirming, STL verifies local route, capabilities, saved Link
reservations, peer-underlay exclusion and protocol compatibility.
Remote conflicts cannot be inferred without inspecting the peer.

GRE receive keys are nonsecret identifiers (NOT encryption). Standard
Create automatically chooses a key and generates a plaintext versioned
Setup Link. The peer simply selects Import -> GRE/IPIP, pastes that
line visibly, reviews its reversed local/peer IPs and enters
**YES** to apply. A persisted GRE/IPIP sender can later re-export
the exact Setup Link through My tunnels -> number -> Share.
Manual -> GRE Native (or IPIP Native) avoids Setup Links only when
both hosts are deliberately configured with reversed IPv4 endpoints
and matching numeric GRE key, or unkeyed GRE on both. Open IP
protocol 47 for GRE and 4 for IPIP in the relevant firewalls.

The wizard shows a concise preview and requests a **fresh YES**
before invoking the existing strict versioned link ensure command
and canonical Engine. The menu itself owns no networking resources.
Auto MTU is a local pre-creation estimate; real end-to-end
connectivity and PMTU require both peer interfaces first.
An uncertain persistence/rollback result returns to the menu but
requires read-only reconciliation, never blind automatic retry.

The rc.3 guided Create -> WireGuard task uses the canonical
protected v3 receiver handoff; IPsec uses protected v2. Ordinary
Status/JSON never displays either credential; rc.3/rc.4 guided Create
only offers later SHOW, while rc.5 displays the protected offer after
successful real-TTY Create/YES as described above. GRE/IPIP
FOU/GUE, WireGuard and conditionally admitted IPsec live under one
human Create menu; Advanced and Manual are separate submenus.
Noninteractive STL without arguments still prints help, not a menu
automation protocol.

For Import, the operator first chooses visible **plaintext** GRE/IPIP
or hidden **protected** WireGuard/IPsec. The full Setup Link is a
bounded single-line input; invalid/truncated/oversized input offers
retry without jumping out of STL. The backend-neutral CLI preview
returns the receiver-oriented addresses and safe credential-presence
metadata before the menu asks for fresh **YES**. Queued confirmations
are discarded first. The canonical CLI import then checks the
SHA-256 exact-offer token and the Engine enforces Link identity
under locks. A valid plaintext token intentionally appears in the
operator's terminal echo, so use protected mode for sensitive offers.
No Input/preview error echoes credential bytes or tries automatic
host mutation. Old rc.2 retains its older separate menu and prompt
contract; rc.4 retained rc.3 pairing semantics and rc.5 changes only the
consented human display timing.

Quick Link payloads provide **no confidentiality or authenticated sender**;
verify the offer with the intended peer through a trusted channel. Sensitive
WireGuard v3 offers show credential presence as **REDACTED** and additionally
show public keys/ports/keepalives before exact Link-ID confirmation.
For strict IPsec v2, it displays only PSK presence and warns that activation
requires an already attested STL-exclusive strongSwan service; successful
local import does not initiate IKE or prove protected traffic. Legacy
WireGuard v1/v2, IPsec v1 and IPsec v2 with non-32-byte PSKs remain
preview-only.
The menu makes no separate promises about working peer traffic or complete
pairing. Settings and Uninstall are observational/preparatory; rc.6
Update may delegate to the canonical installer only after
positively immutable release trust and fresh root/TTY/UPDATE consent.
Mutable or unverified releases remain read-only guidance. Menu text
and selection numbers are human UI, not automation contracts; existing
versioned `--json` commands remain the automation interface.

## WireGuard sender creation, recovery and credential retirement

In the rc.3 guided Create -> WireGuard flow, THIS server's
connection IP is detected from the route to the other server,
the suggested private Link IP pair can be accepted by Enter,
and both default UDP ports can be accepted by Enter. The menu
automatically chooses one private receiver handoff filename per
immutable Link ID; it never asks the beginner for a filesystem path.
After the fresh YES confirmation, a protected directory is
prepared and the existing canonical sender Engine stages the
owning sender key and publishes one exact original receiver offer
with 0600 no-clobber semantics. A failed or uncertain operation
must be reconciled, not blindly retried or rekeyed.

Advanced CLI automation is intentionally different: it still
requires an explicit chosen absolute private --output filename
and does not silently create a managed copy. It remains the
same versioned public-only request, with no private bytes in
JSON, and remains independent of the human menu's numbers.

For automation, create the SENSITIVE recipient handoff and local WireGuard
Link together through an explicit, versioned **public-only** JSON request.
The following sample addresses/ports are placeholders, not valid instructions
for an arbitrary host:

~~~sh
stl link create-wireguard --stdin --output /root/stl-recipient.stl --json <<'JSON'
{
  "schema_version": 1,
  "underlay": {"local": "192.0.2.10", "peer": "192.0.2.20"},
  "addresses": {"local": "10.80.50.0/31", "peer": "10.80.50.1/31"},
  "listen_port": 51871,
  "peer_port": 51872,
  "local_keepalive": 25,
  "peer_keepalive": 0
}
JSON
~~~

`link_id` is optional; when omitted, a fresh cryptographically generated
stable ID is used. Existing IDs must not be repurposed. Sender and recipient
keypairs are generated separately; only the sender's private key enters its
protected per-Link KeyStore, and only the **recipient public key** enters the
initiator's ordinary desired state. The receiver private key appears only in
its explicitly requested, checksummed v3 `stl://` Quick Link. The output
file contains exactly one such URL and a final newline; creation uses
same-owner, symlink-free private-directory traversal, atomic `0600`
no-replace publication and durable directory synchronization. Neither the
normal text output nor the JSON result contains the URL or private key.
The CLI requires an existing private parent; it does not silently create a
new export directory or overwrite a file.

Sender Create is now a single **canonical, Link-locked two-phase transaction**.
Before exposing the receiver URL it verifies there is no committed/pending
same-ID Link, durably stages the sender's protected **own** private key, then
durably reserves the exact public sender `domain.Link` together with the
SHA-256 of the precise sensitive v3 offer in the optional `pending_senders`
section of `state.json` (schema version 2 remains backward-compatible).
Only after both sender recovery records are durable may the SENSITIVE file
become visible. Local backend activation then uses the ordinary Engine
Validate/Apply/Verify and commits the Link **atomically with consuming its
pending sender reservation**. Concurrent same-ID Create and ordinary Ensure
cannot bypass this reservation or publish competing receiver offers.

If activation or even final handoff publication reports an error, inspect the
private output path and stored state. **Only when the original SENSITIVE
handoff exists** does exact Resume have the credentials and URL necessary for
recovery. Failed staging or a failure *before* handoff publication can leave
a protected local orphan key/pending reservation with **no receiver URL**;
that case requires explicit operator reconciliation, not regenerating a
competing same-ID offer. Never treat a pending record alone as proof of a
successful tunnel, or delete its matching sender key casually.

### Recover a crash-staged private Quick Link (WireGuard or IPsec)

A hard kill before atomic publication can leave a
`.stl-handoff-<32-lowercase-hex>.tmp` file inside the **same private
0700 handoff directory**, even when the requested output file does not
exist. Do not use wildcards for deletion, log file contents, or infer
an orphan is safe to retire. List only candidates in the intended directory
and identify the Link ID from already recorded **public** state:

~~~sh
find /root/private -maxdepth 1 -type f -name '.stl-handoff-*.tmp' -printf '%f\n'
stl link recover-handoff --source /root/private/.stl-handoff-<original-hex>.tmp \
  --output /root/private/recovered.stl --confirm <exact-link-id> --json
~~~

`recover-handoff` performs **no network, daemon, Engine Apply or new-key
operation**. It verifies the exact named source is a same-owner, regular,
singly-linked `0600` file in a symlink-free private directory and contains
a valid **SENSITIVE** Quick Link with the confirmed Link ID. Under the
canonical maintenance/Link lock it requires the **original exact URL digest,
whole sender-oriented public Link, sender-origin pending intent and existing
protected sender credential**. The IPsec path verifies the existing 32-byte
PSK with no replacement; WireGuard verifies the existing sender public
identity. Only then it makes the original source inode durable and performs
a same-directory atomic **no-replace rename**, fsyncs the parent, and emits
versioned redacted confirmation. Already committed Links, recipient-origin
IPsec pending, different/rechecksummed URL, orphan keys without pending,
unsafe/changed files and occupied destinations are rejected, leaving source
data intact where possible. **An IPsec removal/retirement receipt permanently
reserves the same Link ID across backends**, including for WireGuard Create,
Resume and crash-handoff recovery: use a new Link ID rather than treating
retirement as authority to reuse the old one. Contradictory legacy saved
state is refused for operator reconciliation; the private source remains.
Canonical-named FIFOs and other non-regular sources are opened non-blocking
and fail before payload decoding instead of hanging. A directory-sync error after rename is
**uncertain publication**, not success: check both paths, never rekey.

After recovery, an exact WireGuard pending sender may use redacted
`preview` then `resume-wireguard` using **the same recovered file**;
an IPsec sender may use `activate-ipsec <link-id> --confirm <link-id>`
only with independently admitted native-exclusive strongSwan. Neither
handoff recovery nor IPsec activation proves IKE initiation or peer traffic.
If there is only an orphan key or pending intent but **no intact original
URL**, STL deliberately refuses adoption/secret recreation. Preserve
evidence and reconcile the protected state and live host identity under
operator control; never silently delete credentials, pending state or
randomly regenerate a receiver key. Recovered exports remain SENSITIVE and
require a trusted delivery channel.


To retry the exact already-published identity, obtain the SHA-256 confirmation
token from a redacted read-only preview of that same URL and use:

~~~sh
stl link preview --stdin --json < /root/stl-recipient.stl
stl link resume-wireguard --stdin --confirm <import_confirmation> --json < /root/stl-recipient.stl
~~~

Resume does **not** generate new keypairs, overwrite saved credentials, or
adopt a changed same-ID Link. Before the first successful commit it requires
both the **identical complete original public Link** and **identical exact
handoff digest** from the durable Pending record, plus the matching protected
sender private/public identity. A modified and rechecksummed recipient offer
cannot change even an address, display name, port or keepalive. After a
successful atomic Link commit has consumed Pending, an identical committed
Link (and its same sender private/public identity) authorizes idempotent
reverification. Missing or conflicting proof fails closed. The confirmation digest is neither sender authentication nor
encryption. On the intended receiver, securely transfer the one-time file,
verify the public identities/out-of-band sender trust, preview, then run:

~~~sh
stl link preview --stdin --json < /path/to/received.stl
stl link import --stdin --confirm <import_confirmation> --json < /path/to/received.stl
~~~

A successful local Engine result is **not** proof of peer
handshake or data traffic. For the explicit CLI output file,
retain the original privately if a later second-server setup
may be necessary; delete it deliberately once it is no longer
needed. For the guided Create menu, the original receiver
handoff is retained until a separately confirmed Delete saved
receiver Setup Link action. Ordinary saved-state CLI export
remains GRE/IPIP-only: this feature does not add a new public
secret-bearing JSON/API. If the protected file is missing,
corrupt, removed or belongs to another Link, it is not
regenerated from public sender State.

`stl link remove` deliberately **retains** the protected local WireGuard
private key for rollback/reconciliation. After successfully removing the
Link and verifying its absence, the operator may separately retire the
specific local key, giving the expected **local public key** recorded from
status/desired state before Remove:

~~~sh
stl link credential retire <link-id> --confirm <link-id> --public-key <local-public-key> --json
~~~

The Engine holds its maintenance and per-Link locks. **Merely finding a
`state.json` for another Link or no active ID is never retirement authority.**
A `removal_receipts` record for the **exact Link ID, WireGuard backend and
expected original local public key** is published only *after* its canonical
Remove, durable desired-state deletion and associated restore cleanup return
confirmed success. Failed/indeterminate Remove and a failed first Ensure
cannot issue this proof. A crash after deletion but before receipt publication
can leave an intentionally unretirable orphan until operator reconciliation.
A new Ensure attempt for that Link ID durably invalidates the historical
receipt *before* provisioning/applying, including when that attempt later
fails, preventing stale receipts authorizing deletion of needed retry keys.

Retire requires the Link-specific receipt and absence of committed/pending
state, confirms no associated live kernel interface/ownership alias, public
WireGuard identity or STL-owned firewall entry, then verifies and removes
only the same-owner, regular, single-linked `0600` key whose derived public
identity matches the operator's confirmation. The receipt is then durably
marked `retired: true` for safe idempotent retries; a retired proof can never
authorize unlinking any subsequently reappearing key. A verified previously
absent key yields `retired: false`. Missing proof, ambiguous host inspection,
damaged credentials and live resources refuse retirement. No key material
is emitted. File deletion is **not physical flash media sanitization**.

On abrupt power loss, the current protected handoff writer can leave a
same-owner `0600` `.stl-handoff-*.tmp` in the explicitly chosen private
parent directory. This is not a public leak but may retain a second copy of
the receiver secret. Inspect that directory and reconcile/delete only
verified task-owned stale temporary files before treating the one-time
handoff as fully retired; do not perform unsafe wildcard cleanup.

Synthetic tests of these workflows alone do not prove real handshakes,
traffic, reboot restore or coexistence. Separate privileged evidence already
proves GRE/WireGuard traffic, distinct-peer and same-peer multi-Link
coexistence, native AMD64/ARM64 six-Link GRE/WG/IKEv2 ESP/NAT-T traffic
with Ubuntu/Debian userspaces, GRE systemd restart/reapply, and
GRE/WireGuard whole-guest reboot and abrupt-QEMU recovery (Issue #12).
The [PR #81](https://github.com/ach1992/simple-tun-link/pull/81)
full-guest KVM tests record a reboot that restored ESP and NAT-T automatically,
including renewed IKE/CHILD SAs and
bilateral encrypted packets; both ESP and NAT-T also passed abruptly
SIGKILL-terminated QEMU and automatic same-disk recovery. This does **not** prove a physical WAN/NAT-router peer. The historical
`v0.1.0-rc.1` pre-release predates PR #81; rc.2 includes those source
improvements and has its own tagged-artifact acceptance in Issue #12.
The physical WAN/NAT test remains an Owner-run post-publication activity.

## Explicit, optional TCP throughput — Issue #9

**Generates real TCP data only on direct operator invocation.** It is never
run by create, import, restore, `status`, `diagnose`, `--all`, the menu
or background recovery. Both sides must independently authorize the test.
On the already active peer, an operator may separately start an iperf3
server **bound only to that peer's Link Address** (not the public IP):

~~~sh
iperf3 --server --bind <peer-Link-address> --port 5201
~~~

On the local machine, after checking Link status/identity:

~~~sh
stl link throughput <link-id> --confirm <same-link-id> --seconds 3 --json
~~~

The canonical local Link ID is mandatory **twice**. Allowed duration is 1–10
seconds (default 3); only one outbound TCP client stream goes to the
committed peer **Link Address** and fixed TCP/5201 port. No arbitrary
destination, server launch, firewall change, UDP test, reverse traffic or
daemon control is possible through STL. Before sending TCP throughput,
STL checks a bounded local `iperf3 --version` response and accepts only
known-safe iperf3 **3.11 or newer in the 3.x family**. Versions 3.9 and
3.10 (including 3.10.1), unknown builds, missing tools and failed version
reads are **rejected without starting any throughput client**: upstream
iperf3 prior to 3.11 could bind the control socket while leaving TCP
data sockets unbound (esnet/iperf PR #1153). In accepted builds the client
uses explicit `--bind <local-Link-address> --bind-dev <exact-owned-interface>`;
on Linux this invokes `SO_BINDTODEVICE` on the data stream. Insufficient
bind privilege or failed route/identity/reachability preflight blocks
the test **without an unbound retry**. The command
holds the canonical per-Link Engine lock during the short traffic window;
STL-driven concurrent remove/reconfigure must wait.

The kernel route to the committed peer must explicitly choose that Link's
verified interface, exact local source address and no gateway; STL rejects
an underlay/default-route fallback. Output is bounded and projects only
version-1 numeric `sent_mbps`, `received_mbps`, total byte counts,
protocol/direction, duration, Link ID and backend. It excludes raw iperf
server output and all credentials. Failed/malformed data does not become
a measured zero. The short sample does not guarantee sustained throughput.
The peer iperf3 listener's exposure and eventual shutdown remain the
explicit responsibility of its operator. Never run an unapproved
cross-server/physical WAN test merely because this optional CLI exists.

## Commands

- `stl help`
- `stl menu`: explicitly open the human terminal menu; no JSON automation contract.
- `stl version [--json]`
- `stl link list [--json]`: read saved configured Links in stable Link ID
  order. An empty state file yields an empty list; listing does not construct
  backend runtimes, probe host interfaces, or alter network state.
- `stl link status <link-id> [--json]`: read one saved Link and inspect
  its live backend state. GRE, IPIP and WireGuard use ownership-/ifindex-checked
  `DiagnosticState` adapters with public state and interface/transfer counters.
  Unsupported backend kinds return a nonzero error rather than claiming health.
- `stl link diagnose <link-id> [--mtu <bytes>] [--json]`: explicitly
  probe the selected GRE/IPIP/WireGuard Link's **peer Link Address** using
  bounded ICMP echo with IPv4 Don't Fragment. Reports observed RTT/loss/jitter
  and conservative PMTU recommendations alongside backend interface counters.
  For WireGuard, it also reports public peer identity, handshake time and
  transfer bytes; a zero pre-probe handshake time does **not** prove a
  connection or a failure. This command transmits diagnostic packets but
  makes **no** host network, firewall, MTU or desired-state changes. Requires
  a configured, identity-checked active interface.
- `stl link preview --stdin [--json]`: decode and **redact** a
  versioned setup link supplied only through standard input, then display
  the **receiver-oriented** Link identity, addresses, encapsulation,
  exchange mode, and credential-presence flag without revealing any
  credential or applying network state. Never pass SENSITIVE Quick Links as
  command-line arguments, which can enter shell history/process listings.
- `stl link import --stdin --confirm <preview-token> [--json]`:
  **mutating**, accepts a reviewed credential-free GRE/IPIP, configured
  credential-bound WireGuard v3, or exact-32-byte-PSK IPsec v2 Quick Link via
  standard input. The required token comes from read-only preview of the
  exact URL. WireGuard stores its receiver private key under restrictive
  permissions inside the canonical Engine transaction. IPsec uses the
  protected PSK store and staged Engine activation **only after native-exclusive
  service admission**; it cannot adopt or stop a foreign strongSwan runtime.
  Legacy WireGuard v1/v2, IPsec v1 and non-32-byte IPsec v2 offers are
  preview-only.
- `stl link export <link-id> [--json]`: **read-only but intentionally
  disclosing**, export a canonical receiver Setup Link for a saved
  credential-free GRE or IPIP Link, including encoded endpoints and
  display metadata. Unlike status/diagnostics, this command explicitly emits shareable setup
  material; refer to the export security caveat below.
- `stl link ensure --stdin [--json]`: **mutating** idempotent desired
  Link convergence via the existing Engine, accepting a strict versioned JSON
  request on standard input. Full request schema appears below.
- `stl link remove <link-id> --confirm <same-link-id> [--json]`:
  **mutating** Engine-owned removal after explicit stable ID confirmation.
  If an owned WireGuard interface must be deleted, removal first requires
  its matching protected private key to be safe and readable for rollback;
  otherwise interface and firewall state are preserved for reconciliation.
- `stl link restore --all`: **mutating** host persistence/reapply
  operation for existing saved Links, using the same Engine.

`list` reports **configured desired state**, not actual network reachability.
`status` reports **interface_verified**, not end-to-end connectivity.
Its `connectivity` field explicitly says `not_measured`: a configured,
owned, UP GRE/IPIP/WireGuard interface with counters alone is not proof of peer traffic,
working firewall policy, or PMTU. Real Link Address probes belong to
the read-only diagnostics path in [DIAGNOSTICS.md](DIAGNOSTICS.md).

## Machine output

`--json` emits exactly one object with top-level integer `schema_version: 1`.

- `link list`: `{ "schema_version": 1, "links": [...] }`; each entry includes
  only Link ID, backend, encapsulation, local and peer Link Addresses.
- `link status`: a projected Link entry, `interface_verified: true`,
  `connectivity: "not_measured"` and the selected backend's identity-checked
  `gre_state`, `ipip_state` or `wireguard_state` (only its selected
  backend); WireGuard includes verified public identity, latest handshake
  Unix timestamp and byte counters, not a private credential.
- `link diagnose`: the GRE/IPIP/WireGuard diagnostics report with top-level
  schema version, Link ID, backend kind, identity-checked public/counter state,
  MTU result and quality result. `--mtu` overrides the **inner IPv4
  packet** MTU manually; oversized values are errors, not silently clamped.
  Without `--mtu`, MTU is selected by bounded DF probes, and an
  unverified fallback is explicitly marked unverified.
- `link preview`: one redacted object with CLI schema version 1,
  a separate `pairing_schema_version`, receiver-facing non-secret
  Link metadata, non-secret GRE configuration options when present,
  `has_credential`, credential kind and sensitive flag. For v3 WireGuard,
  preview also includes **public** local/peer keys, local/peer listen ports
  and keepalive settings, never the private key.
  The input setup link, private keys, arbitrary display names and decoding
  cause are deliberately excluded from JSON and human output. For
  importable plaintext GRE/IPIP and WireGuard v3 Quick Links, it returns
  `import_confirmation`: the full lowercase SHA-256 of the exact normalized
  input URL, to bind a subsequent explicit import to the reviewed payload.
- `link export`: explicit export JSON with CLI and pairing schema
  versions, Link ID, backend/encapsulation, credential/sensitivity flags
  and the complete intentional `setup_link` field. The encoded URL
  discloses metadata and MUST NOT be treated as ordinary status output.
- `link import`: same versioned Engine success/failure envelope as
  `link ensure`, with `operation: "link_import"`; this is confirmation of
  owned host-state convergence, not remote connectivity.
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
explicit host-mutating operations. Additional pairing/import recovery
(Issue #8), optional throughput and diagnostic acceptance (Issue #9), and
remaining task-first UI work (Issue #10) are separately tracked.
Native-exclusive IPsec is already conditionally operational (Issue #7 closed),
with real ESP/NAT-T E2E traffic.
The [PR #81](https://github.com/ach1992/simple-tun-link/pull/81)
tests separately established whole-guest KVM ESP/NAT-T reboot and abrupt
QEMU termination recovery. These source improvements are in the rc.2
candidate; **physical WAN/NAT acceptance remains unverified**, and the
historical rc.1 installer lifecycle (Issue #11) is separate evidence.

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
not a claimed successful apply. Early failures still use the conservative envelope even when no host Apply
was invoked. The optional additive `error.evidence` object now distinguishes
Engine `stage`, `host_mutation`, `desired_state`, and `rollback` without
changing existing schema-v1 top-level values or exit semantics. See
[OPERATOR-RECOVERY.md](OPERATOR-RECOVERY.md) before any retry or repair.

Exit codes remain 0 on verified Engine success; 2 for invalid input/usage,
4 for unsupported backend, and 1 for other operational, state or rollback
failures. The commands use a five-minute signal-aware deadline and the
Engine's cancellation-detached, bounded owned rollback. No global tuning
or unrelated host networking changes are permitted by this CLI layer.

The GRE Native guided Create, the guided WireGuard sender/Resume and
confirmed GRE/IPIP/WireGuard v3 recipient Import reuse the canonical Engine
instead of a separate menu lifecycle. Issue #12 records accepted real
GRE/WireGuard traffic, distinct-peer and multi-Link coexistence, native
AMD64/ARM64 six-Link E2E including conditionally admitted IPsec ESP/NAT-T,
GRE systemd restart and GRE/WireGuard full-guest reboot/crash recovery.
The [PR #81](https://github.com/ach1992/simple-tun-link/pull/81) tests
separately document real full-kernel KVM IPsec ESP/NAT-T automatic reboot
and both ESP/NAT-T abrupt-VM-crash recovery. **Physical/
external WAN NAT-router traversal** was not established by those tests
(Issue #12). Such source acceptance does not itself authorize integration
or publication of new release artifacts. The historical published `v0.1.0-rc.1` installed-artifact lifecycle
passed under Issue #11; rc.2 independently qualifies the later fixes
under Issue #12. A successful source/CLI test alone does not establish
peer traffic, WAN compatibility or release download integrity.

## Explicit plaintext GRE/IPIP setup-link export (Issue #8)

`stl link export <link-id> [--json]` deliberately exports an
**already-saved GRE or IPIP Link's** versioned `stl://2.` Setup Link for the
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
display-name metadata (encoded in the URL), and any GRE key identifiers.
An included SHA-256 checksum detects accidental damage, **not**
authenticity. GRE and IPIP do not encrypt or authenticate traffic;
share setup material with the intended peer rather than public logs.

The command is read-only and does not inspect, repair or apply the Link.
Existence in saved desired state **does not prove a working tunnel**.
Only credential-free GRE/IPIP Native/FOU/GUE exports are supported.
WireGuard and IPsec remain explicitly unsupported for **re-export from
persisted sender state**, because recipient private keys are deliberately
not retained. WireGuard uses the separate one-time Create/Resume
workflow. Export never silently omits private keys/PSKs to manufacture a broken setup link. Confirm the configuration
via the existing `link preview` before a separate authorized apply
step. Export never applies a Link; the explicit `link import` command
described below can apply either a credential-free GRE/IPIP offer or a
configured WireGuard v3 or strict IPsec v2 Quick Link after exact-payload
confirmation and IPsec-only native service admission.

## Confirmed GRE/IPIP, WireGuard v3 and IPsec v2 setup-link import (Issues #8/#10)

A receiving operator first reviews the inverted Link details and the
confirmation token; preview is **strictly read-only**:

~~~sh
stl link preview --stdin --json < /path/to/protected/setup-link.txt
~~~

For a credential-free GRE/IPIP, configured WireGuard v3 or strict IPsec v2
Quick Link with exactly 32 PSK bytes, the preview JSON includes
`import_confirmation`, a 64-character lowercase SHA-256 digest of the
exact decoded/line-terminator-normalized `stl://` URL. After verifying
the receiver underlay, peer address, Link Addresses, backend and GRE
options, the operator may explicitly apply **that same input**:

~~~sh
stl link import --stdin --confirm <import_confirmation> --json < /path/to/protected/setup-link.txt
~~~

A changed, damaged, truncated, oversized or different setup URL does
**not** match the confirmation token and is rejected before creating
runtime state or touching a network interface. Passing the confirmation
token is an explicit apply instruction, not an interactive prompt or
peer-identity authentication. Neither the setup-link SHA-256 checksum nor
this confirmation digest proves the sender is authorized: verify the
offer with the intended peer through a trusted channel. Plaintext GRE
and IPIP provide **no encryption or peer authentication**.

The importer calls the canonical `Offer.ReceiverLink` inversion, then
`Engine.EnsureImported` (plaintext), `Engine.EnsureImportedRecipient`
(credential-bound WireGuard), or staged `Engine.StageIPsecRecipient` /
`Engine.ActivateStagedIPsec` after native-exclusive admission (IPsec v2).
Plaintext and WireGuard import permit a **new Link ID** or an **existing
ID whose committed desired state exactly matches** the reviewed receiver
configuration; IPsec additionally requires exact protected PSK/ownership
intent and fails closed on uncertain state. If that ID already exists with *any*
different desired configuration (including a different backend, address,
GRE option or display name), import returns a redacted `conflict` and does
not inspect, reconfigure or remove the existing backend resources. This
conflict check runs **under the same per-Link lock** as normal `Engine.Ensure`
and `Engine.Remove`, closing the race between state preflight and apply.
To intentionally reconfigure an existing Link, use the separately authorized,
versioned `stl link ensure` workflow instead of pairing import.

`Engine.EnsureImported` reuses the canonical Engine's ownership,
per-Link resource allocation, idempotency, verification and rollback
behavior. It does not introduce a second networking lifecycle. The
importer never logs/prints the input URL, embedded display name or arbitrary
backend errors; structured success
returns `operation: "link_import"` and the normal versioned Engine
result. Failures after Engine execution are nonzero with
`outcome: "unconfirmed"` and `reconciliation_required: true`.
A successful Engine result proves local backend convergence, **not**
bidirectional traffic, MTU or peer cooperation.

WireGuard v3 import uses the protected KeyStore: private bytes travel only
through a 0600 key file and an already-verified inherited descriptor to
`wg set`, not generic JSON, argv or log output. Identical-credential retry
is allowed under Engine locks; mismatched credentials, unknown backend,
legacy WireGuard v1/v2, IPsec v1, and IPsec v2 with non-32-byte or all-zero
PSKs are refused for import. Failed apply may
leave a validated private key intentionally for reconciliation; removing
a WireGuard interface does **not** destroy stored credentials. Operators
must handle eventual key retirement deliberately. WireGuard public status
supports a verified interface, latest handshake timestamp and RX/TX bytes,
**not a proof of peer reachability or a packet-level E2E test**.
WireGuard guided sender creation, v3 recipient import and explicit credential
retirement are implemented. Real-kernel bidirectional WireGuard and same-peer
GRE coexistence were observed in PR #53. Native-exclusive operational IPsec
v2 recipient import is now conditionally admitted, with source-level strict
PSK staging and independently
verified ESP/NAT-T traffic/removal evidence (see
[IPsec real E2E](operations/IPSEC-REAL-E2E.md)). Its preview token
does not authorize service activation, authenticate the sender, initiate IKE,
or establish real WAN/NAT-router compatibility.
GRE Native and WireGuard automatic restore have additionally passed real
whole-guest reboot and simulated abrupt KVM process termination followed
by a fresh boot, with protected credentials unchanged
([Issue #12 evidence](https://github.com/ach1992/simple-tun-link/issues/12#issuecomment-6134259976)).
The [PR #81](https://github.com/ach1992/simple-tun-link/pull/81)
acceptance evidence separately records whole-guest ESP and NAT-T automatic
reboot restoration with live bilateral encrypted packets,
and genuine abrupt-QEMU SIGKILL followed by same-disk automatic recovery for
**both ESP and NAT-T**. **Physical WAN/external NAT-router traversal** remains
**unproven** under Issue #12. The historical `v0.1.0-rc.1` installer lifecycle was accepted under
Issue #11; the later fixes belong to rc.2, with separate candidate release
testing in Issue #12. Source acceptance, integration and publication
must still be evidenced separately.

## IPsec operational CLI and historical read-only diagnostic milestones

The opening paragraphs below describe **current** conditional runtime
admission and operational commands. Later paragraphs document historical
fail-closed diagnostic milestones from before operational admission was
implemented; their older statements that activation is always denied or
the publisher is not wired are **historical**, not the present CLI contract.
Use [real IPsec E2E](operations/IPSEC-REAL-E2E.md) and
[architecture](ARCHITECTURE.md) for the current ownership/activation boundary.

`stl doctor ipsec` is always read-only. Without a positively attested STL
native-exclusive strongSwan service, `--json` preserves
`schema_version:1`, `backend:"ipsec"`, `runtime_mode:"native_exclusive"`,
`activation_allowed:false` and stable `status`, `reason_code`,
`summary`, `next_step` fields, exiting **4 (unsupported)**. With
complete native admission it returns `activation_allowed:true`; this
only attests current runtime ownership, not IKE or encrypted traffic.
Invalid arguments exit **2**.

On admitted hosts the actual operational CLI is `stl link create-ipsec`
(256-bit PSK, root-protected SENSITIVE Quick Link), `preview`/`import`,
`activate-ipsec`, `connect-ipsec`, `ensure`, `status`, `diagnose`,
`restore --all` and exact `remove`. After a Remove receipt, local
`retire-ipsec <id> --confirm <id>` safely retries protected PSK retirement
even if strongSwan is stopped or unadmitted. An interrupted durable
Remove requires explicit `reconcile-ipsec <id> --confirm <id>`; interrupted
XFRM creation can be inspected and, only when original ifindex/ownership
allows, aborted via `reconcile-xfrm-ipsec <id> --confirm <id>`.
Every command supports the applicable versioned JSON surface; an
indeterminate kernel-create interval without a persisted ifindex refuses
automatic deletion/adoption. Commands never restart a foreign service.

The detailed read-only checks below record the historical source-only
diagnostic milestones and remain relevant **when native runtime admission
fails**. Historical `activation_allowed:false` and exit-4 statements
within that chronology do not describe a currently admitted runtime.
Historical source-only milestones predate the Issue #101 native-exclusive
provisioner included in rc.6, which calls receipt-bound publishers under
the installed maintenance gate. The earlier rc.5 binary remains unchanged. See
`docs/operations/IPSEC-REAL-E2E.md` for operational evidence.

The command observes `charon`/`charon-systemd` processes and known
Debian/Ubuntu strongSwan systemd/SysV service-file identities with
non-following `lstat`. It inspects bound UDP 500/4500 sockets in the
**caller's current network namespace** through bounded read-only
`/proc/net/udp` and `/proc/net/udp6` snapshots; it also checks
`swanctl --help` and whether a read-only XFRM interface inventory
can be obtained. In the tested **daemonless** Ubuntu 24.04 / strongSwan
5.9.13 and Debian 13 / strongSwan 6.0.1 packages, `swanctl --version`
returned exit 2 **because normal command dispatch first attempts a VICI
connection**, not because the `version` command is unsupported. Global
`swanctl --help` is handled before VICI connection and prints the local
version/help without a running daemon. A successful help probe establishes
only executable availability, **never daemon or IPsec readiness**.
Upstream dispatch: [strongSwan 5.9.13](https://github.com/strongswan/strongswan/blob/5.9.13/src/swanctl/command.c)
and [6.0.1](https://github.com/strongswan/strongswan/blob/6.0.1/src/swanctl/command.c).
On supported Debian/Ubuntu builds the doctor uses fixed system binary paths (`/usr/bin/pgrep`, `/usr/bin/systemctl`, `/usr/sbin/swanctl`,
`/sbin/ip`) rather than executing tools found through a user-controlled
`PATH`; other layouts require a validated distro adapter, not a fallback.

The additive service check `name:"strongswan_service"` reports
`blocked/strongswan_service_observed` if a known strongSwan/IPsec unit or
init-script identity exists (including a dangling symlink),
`unknown/strongswan_service_inventory_unverified` on unreadable/incomplete
file inspection, and `observed/strongswan_service_not_observed` only when
all known paths were absent. This does **not** claim package, daemon or
exclusive ownership vacancy and never calls `systemctl` or reads
third-party service content. Future activation must independently attest
an STL-owned service against actual package and process/kernel state.

The new additive `name:"native_service_unit"` check inspects ONLY
`/etc/systemd/system/simple-tun-link-ipsec.service` using pinned, non-following
root-owned directory and file descriptors. It accepts the exact reviewed
source-only `charon-systemd` unit bytes with safe file permissions and
single-link identity. The source profile selects `STRONGSWAN_CONF` explicitly,
uses a proposed private runtime directory and UMask, and has **no** distro
`ExecStartPost=swanctl --load-all`, `ExecReload` or enable/start command.
The separate read-only name:"native_service_unit_origin" check verifies
the independently recorded root-private receipt and exact original inode
xattr token, not just a byte-identical service unit file.
Classifications: observed/native_service_unit_origin_observed (receipt-bound
file snapshot only), blocked/native_service_unit_origin_not_provisioned
(both absent), blocked/native_service_unit_origin_conflict (foreign, changed,
or incomplete publication), unknown/native_service_unit_origin_unverified
(incomplete inspection). The writer has no CLI or Engine call site;
a positive result is not a systemd operational admission. Schema stays 1,
activation_allowed remains false and doctor exit code remains 4.

The additive `name:"native_systemd_loaded_unit"` checks only the current
**in-memory unit inventory** using fixed
`/usr/bin/systemctl --system --no-pager --no-legend --plain --full --all
--type=service list-units 'simple-tun-link-ipsec.servic?'`.
Unlike `systemctl show UNIT` (which may cause systemd to load an absent
unit), `list-units` enumerates units already in the manager's memory and
does not request loading the target. A successful empty result is
`blocked/native_systemd_unit_not_loaded`: no matching *primary* unit was
listed at that instant, **not** proof of absent files, aliases or daemon.
An entry with a known failed/masked load state is
`blocked/native_systemd_unit_conflict`. A loaded in-memory entry, incomplete
or malformed output, error, missing bounded-runner capability, unexpected
stderr or overflow is `unknown/native_systemd_unit_unverified`: the
single safe listing cannot prove actual fragment, aliases, drop-ins,
generators, source, transient status, pending reload or effective unit
configuration. No successful `observed` loaded-unit admission is claimed.
This is deliberate fail-closed behavior, not an incentive to call
`show UNIT` after listing: the unit may unload in between and be
implicitly reloaded. The runner enforces **16 KiB stdout and 1 KiB stderr
capture ceilings during execution**, terminating on overflow without
returning raw subprocess output. `activation_allowed` stays false and
doctor exit stays 4; PID 1 may independently change between snapshots.

Results: `observed/native_service_unit_bytes_verified` (file snapshot only),
`blocked/native_service_unit_not_provisioned` (absent),
`blocked/native_service_unit_untrusted` (conflict, unsafe path or bytes) and
`unknown/native_service_unit_unverified` (incomplete inspection). A positive
result is **not** STL-origin publication or effective loaded-systemd,
process/environment or secure logger attestation; the separate in-memory
inventory above remains blocked/unknown until effective properties can be
attested without an inducing unit lookup. The unit is
NOT published, installed or wired into Engine, CLI or installer; no operator
should copy it onto a live host. Future package installation must account for
distro-managed units and maintainer-script service side effects before any
privileged operation.

The additive `name:"native_config"` check reads ONLY the proposed fixed
`/var/lib/simple-tun-link/ipsec/strongswan.conf` artifact. It traverses
root-owned, non-writable, non-symlink parents through pinned directory
descriptors; requires the state/IPsec directories to be private, a
root-owned singly-linked `0600` regular file and exact reviewed config
bytes; and rechecks opened inode and every directory-entry identity.
Results: `observed/native_config_bytes_verified` (local bytes only),
`blocked/native_config_not_provisioned` (missing),
`blocked/native_config_untrusted` (unsafe file, parent, or content), and
`unknown/native_config_unverified` (incomplete inspection). These results
never report raw file contents, path details or underlying errors.
An unprivileged operator may see `unknown` when the root-private path
cannot be read; do not weaken permissions to make the check green.
Even an exact protected file is NOT an STL-origin publication receipt,
proof of `STRONGSWAN_CONF` selection or effective daemon CFG logging, nor
a service, VICI, port, package or XFRM ownership permit. Future admission
must prove those independently and revalidate them across restarts.

The additive read-only `name:"native_config_origin"` check independently
verifies a **durable prepared publication receipt** against the protected
configuration inode, its unique on-inode origin xattr, reviewed SHA-256,
root-private receipt bytes and current descriptor-pinned canonical path.
Results are `observed/native_config_origin_observed` (receipt-bound snapshot),
`blocked/native_config_origin_not_provisioned` (no receipt/config pair),
`blocked/native_config_origin_conflict` (orphan receipt, foreign config,
identity or permission drift), and `unknown/native_config_origin_unverified`
(inaccessible or incomplete probe). No nonce, xattr, bytes, raw host error or
untrusted pathname is emitted. The source-only, **unexported** no-clobber
publisher is not called by CLI/Engine: `doctor` does not create the receipt.
A successful receipt check is not authority to start strongSwan, load a PSK,
control VICI, adopt a service, reserve IKE ports or remove XFRM resources.
Root administrators outside STL are not serialized by the receipt; operational
admission still needs fresh service/process/writer and kernel proof.

The additional JSON check is `name:"ike_udp_ports"`. Its stable results are:
`blocked/ike_udp_ports_observed` when UDP 500 or 4500 is already bound,
`observed/ike_udp_ports_not_observed` when both inventory reads and parsing
completed without a matching binding, or
`unknown/ike_udp_inventory_unverified` when data needed to establish
non-occupancy is absent, incomplete, too large or malformed. A correctly
identified **bound** IKE socket remains `blocked` even if the other
snapshot is unreadable; non-occupancy requires both complete inventories.
All results provide a safe `next_step`.
Nothing is inferred about ownership from socket addresses, process names or
namespaces; two non-atomic observations never reserve a socket. An
`observed` result does **not** prove it is safe to bind or start anything.
The command does not probe other namespaces, hidden writers or effective
service/logging configuration. Missing `/proc/net/udp6` is **unknown**,
not automatically treated as IPv6 disabled.

`pgrep` absence, UDP non-observation, `swanctl` and `ip` success
**do not prove exclusive ownership, host readiness, configuration safety,
future IKE port availability, actual ESP/NAT-T support or cryptographic
connectivity**. Any detected daemon or standard IKE port collision is an
IPsec-only blocker; never stop/rebind/adopt a foreign process or socket.
No services, packages, credentials, routing, firewall, kernel objects or
state directories are changed.

When operational IPsec is not admitted, `stl link status <link-id> --json`
and `stl link diagnose <link-id> --json` preserve the
`schema_version:1` error envelope and `error.code:"unsupported"` with
exit **4**, but now also include optional, stable:
`error.reason_code:"ipsec_runtime_not_registered"`,
`error.backend:"ipsec"`, `error.object_id` (validated exact Link ID),
`error.operation` (respectively `link_status` / `link_diagnose`) and
`error.next_step:"stl doctor ipsec"`. Existing generic errors omit these
optional fields unless supported. Machine callers branch on the code and
reason, **not** on the human `detail`; `next_step` is the exact safe
read-only CLI command. The human error continues to explain why activation
is not available. With admitted runtime the same commands report bounded
live kernel/VICI and Link-Address observations, not generic unsupported.

IPsec remains unavailable when the native-exclusive service is absent or
unverified; on positively admitted hosts the canonical Engine registers its
operational backend. GRE/IPIP/WireGuard continue independently. The same program-wide
`reason_code` + actionable guidance and safe event-logging policy must be
applied to future setup, status, create/ensure, repair, remove and restore
workflows. See docs/ARCHITECTURE.md and Issue #9/#10 for that shared contract.
