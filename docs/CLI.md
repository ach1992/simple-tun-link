# CLI, terminal operator workflow and machine contracts

`stl` supports both human-guided local administration and **non-interactive
automation**. The terminal menu is not a machine API. This file is a command
reference, not a timeline of UI iterations, Issues or releases.

For Setup Link versions, inversion and payload security use
[PAIRING.md](PAIRING.md); for credential retention/retirement use
[SECURITY.md](SECURITY.md). Actual support on a host is subject to
[SUPPORTED-ENVIRONMENTS.md](SUPPORTED-ENVIRONMENTS.md).

## Interactive operation

Run `stl` in a real terminal or invoke `stl menu`. Without an
interactive terminal, `stl` prints help instead. The principal tasks are
Create, Import, My tunnels, Test connectivity, Settings, Update and
Uninstall. GRE Native is the default guided Create choice; WireGuard,
IPIP, manual configuration and advanced encapsulations/IPsec remain
discoverable.

- Creating a Link selects the **other server's** reachable underlay
  address, suggests this host's route-derived source, and offers an
  unused private Link Address pair or manual local/peer addresses
  (including valid adjacent /31 and usable /30 pairs).
- Preview before mutation shows selected backend, both endpoints,
  encapsulation/ports, endpoint-local MTU and effects. Selected missing
  trusted prerequisites can be prepared through one scoped, freshly
  confirmed `PREPARE` plan; actual Create/Import still needs a separate
  `YES`. A real existing official `strongswan.service` may be
  stopped/disabled only through the **separate** exact
  `STOP strongswan.service` prompt, warning about immediate VPN
  disruption and independently verified ownership. Foreign or unknown
  services require manual remediation and `RECHECK`.
- After successful local Create, show saved/local success separately
  from measured peer traffic. GRE/IPIP plaintext offers can be exported
  again. The original SENSITIVE WireGuard/IPsec receiver handoff is
  shown after successful creation in a real terminal, and retained
  separately for future Share with fresh `SHOW`. Explicit `DELETE`
  removes only that saved handoff, not the active Link or local key.
- My tunnels offers local Status, Link-scoped Test, Share, details and
  identity-bound Remove. For saved IPsec Links only, **Connect IPsec**
  starts IKEv2 through the canonical locked `connect-ipsec` Engine after
  a fresh exact `CONNECT` confirmation. IPsec Create/Import provisions
  both peers locally but never starts IKE automatically; after import
  on the other server, use Connect IPsec on either peer, then test.
  An already verified matching SA never triggers a second IKE initiation.
  **Test connectivity** never creates an SA, changes services or silently
  repairs. A human Remove requires a fresh `REMOVE`
  after preview. **Test connectivity → A Check all tunnels** uses the
  existing versioned all-Link diagnostic report, presented as a compact
  table of peer IP, Ping replies and time-local results. Unverified or
  blocked checks retain their reason/next step; detailed MTU, counters
  and latency remain in the one-Link view. Test connectivity and
  ordinary Status are not repairs.
- Protected Import tolerates only exact `Setup link:` clipboard labels
  and terminal bracketed-paste framing; the encoded URL remains strictly
  decoded and private, and unexpected/incomplete controls are rejected.
  The paste itself is never echoed or displayed.
- A verified IPsec SA requires BOTH inbound/outbound ESP tunnel states
  with the expected scoped XFRM ID, exact peer underlay endpoints, valid
  SPI and a common CHILD reqid. Partial, foreign and unreadable inventory
  remains unknown and cannot initiate IKE or authorize peer probes.
  Verified SA absence is reported as `ipsec_sa_not_established`, with an
  explicit Connect action rather than a generic ping outage.
- The interface presents short, actionable errors with distinguished
  missing, unknown, foreign and partly-mutated outcomes; no automatic
  retries of uncertain host effects. Color is semantic only. Preserve
  `NO_COLOR`, `TERM=dumb`, redirected output, exact copyable opaque
  values, and no secret-bearing or ANSI-contaminated machine output.
  `STL_NO_CLEAR=1` retains an append-only interactive display for
  troubleshooting.
- Update delegates only to an independently verified official
  **immutable** published installer for forward same-line Stable patch
  or forward RC releases, under the installed-root/TTY and fresh `UPDATE`
  gates. Major/minor migration, RC-to-Stable, mutable or unknown release
  artifacts require independent manual verification. Uninstall is a guided, individually
  authorized cleanup—not a mass Link or credential purge.
  Operator failure pages for selected packages and official releases
  give an authored, non-secret reason category and a read-only next check.
  Confirmed package PREPARE and immutable Update additionally classify
  only bounded, fixed child status/stage identifiers; raw APT or Bash
  output is withheld from human menus. The stage is explicitly reported
  rather than treated as proof of completed host effects.
  APT/installer failures can leave partial package or executable effects;
  neither a failed PREPARE nor a failed update grants permission for a blind
  retry. Machine-readable JSON and protected handoffs remain unchanged.

### Manual GRE/IPIP Native pairing (no Setup Link)

The interactive menu also supports configuring the pair **manually**
when the operators do not want to transfer a Setup Link:

1. On **each** server choose **Create tunnel → Manual connection →
   GRE Native** (or **IPIP Native**) and enter the **other** server's
   reachable underlay IPv4.
2. Set two non-overlapping private Link IP addresses. The values are
   **reversed at the peer**: if A's local/peer are
   `10.235.1.1/30` and `10.235.1.2/30`, then B's
   local/peer must be `10.235.1.2/30` and `10.235.1.1/30`.
3. For **GRE Native**, both sides must have the **same receive key**
   when keyed (including an explicit numeric key of zero).
   Press Enter at the manual key prompt on **both** ends for
   unkeyed GRE. Retrieve an existing peer's **nonsecret**
   key via **My tunnels → Connection details**. A GRE key
   is **not** encryption or authentication.
4. Permit **IP protocol 47** for GRE Native or **IP protocol 4**
   for IPIP Native on the respective provider and host firewalls;
   these are not TCP/UDP port numbers. Apply each local Link
   through its own preview and fresh `YES`, then test
   peer Link Address connectivity.

The manual menu is for **Native** GRE/IPIP. Use the canonical
**Share Setup Link → Import** flow for FOU/GUE so paired UDP
port and encapsulation settings are preserved. WireGuard/IPsec
receiver secrets cannot be reconstructed from Connection details;
use the original protected receiver handoff.

## Exact CLI commands

The executable's `stl help` remains the executable-level syntax source.
These commands use the **same Engine**, without independent UI/backend
lifecycle implementations:

~~~text
stl help
stl menu
stl version [--json]

stl link list [--json]
stl link status <link-id> [--json]
stl link diagnose <link-id> [--mtu <bytes>] [--json]
stl link diagnose --all [--timeout <duration>] [--parallel <1..4>] [--json]
stl link throughput <link-id> --confirm <link-id> [--seconds <1..10>] [--json]

stl link preview --stdin [--json]
stl link import --stdin --confirm <preview-token> [--json]
stl link export <link-id> [--json]

stl link create-wireguard --stdin --output <private-file> [--json]
stl link create-ipsec --stdin --output <private-file> [--json]
stl link resume-wireguard --stdin --confirm <setup-digest> [--json]
stl link recover-handoff --source <private-temp> --output <private-file> --confirm <link-id> [--json]
stl link credential retire <link-id> --confirm <link-id> --public-key <local-public-key> [--json]

stl link activate-ipsec <link-id> --confirm <link-id> [--json]
stl link connect-ipsec <link-id> --confirm <link-id> [--json]
stl link retire-ipsec <link-id> --confirm <link-id> [--json]
stl link reconcile-ipsec <link-id> --confirm <link-id> [--json]
stl link reconcile-xfrm-ipsec <link-id> --confirm <link-id> [--json]

stl link ensure --stdin [--json]
stl link remove <link-id> --confirm <link-id> [--json]
stl link restore --all
stl doctor ipsec [--json]
stl maintenance pre-uninstall --json
~~~

**Read-only/local observation:** `list`, `status`, `preview`,
`export`, `doctor`, `maintenance pre-uninstall` and `version`.
`diagnose` is host-state read-only but can send bounded ICMP probes.
`throughput` explicitly generates TCP traffic. `export` deliberately
discloses a plaintext Setup Link and must never be treated as an ordinary
diagnostic result. **Host/credential mutation** is explicit in create,
import, resume, activate/connect, ensure, remove, restore, retire or
reconciliation commands; recovery of an original private handoff
mutates only its verified protected file, not network state.

## Machine-readable response contract

Most commands with `--json` emit exactly one bounded object with
top-level integer `schema_version: 1`. The **output** version is
independent of a desired-link **input** version and of the Setup Link
pairing version. Consumers must branch on documented typed fields and
exit codes, not the English text of the terminal menu.

| Command | Data/meaning |
|---|---|
| `version` | Version, built commit and build date |
| `link list` | `links` in stable Link ID order, containing public desired state; not proof of live interfaces |
| `link status` | Link identity and an independently verified selected backend/interface/counters, with `connectivity: "not_measured"` |
| `link diagnose` | Verified Link, public backend observations, bounded ICMP quality/RTT/loss/jitter and measured/conservative MTU information |
| `link diagnose --all` | `operation: "link_diagnose_all"`, outcome, ordered checks, totals for observed/blocked/unknown |
| `link preview` | Receiver-oriented nonsecret metadata and credential-presence flag; eligible payloads yield `import_confirmation` |
| `link export` | Intentional `setup_link` disclosure plus pairing/CLI version and public metadata |
| `link ensure`, `link import`, `link remove` | `operation`, `link_id`, `changed`, `removed` on confirmed local Engine success |
| IPsec doctor | Backend, `runtime_mode: "native_exclusive"`, classified checks and `activation_allowed`; successful admission is not peer traffic |

A lifecycle error is a redacted, nonzero, versioned result with stable
`error.code`, `reason_code`, `next_step` and optionally safe
`evidence` about Engine stage, host mutation, desired-state commit
and rollback. Unconfirmed mutations use `outcome: "unconfirmed"`
and `reconciliation_required: true`; any partial result is
reconciliation evidence, not success. Exact payload bytes, arbitrary
display names, protected paths, private keys and daemon stderr are
excluded from generic errors/status.

Exit statuses are `0` for verified success, `2` for invalid
usage/input, `4` for unsupported/unavailable backend and `1`
for other state, operation or observation failure. For all-Link
diagnostics, `4` indicates blocked Links with none unknown, while
`1` means unknown/interrupted observation. An empty successfully
loaded Link list can yield `0`, but that does not prove network health.

### Desired-state input schemas

`link ensure --stdin` accepts **strict data-only JSON** (not a
`stl://` Setup Link). Version 1 fixes the public Link fields:
`id`, `display_name` (optional), `underlay.local/peer`,
`addresses.local/peer`, `backend`, `encapsulation`, and
`gre` options `key_enabled`, `key`, `ttl`, `tos`,
`disable_pmtud`, `checksum`, `sequence`, `udp_port`.
A GRE key value of zero and an absent key are distinct.

Example public **schema v1** request (illustrative addresses only):

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

**Input schema v2** deliberately extends the same frozen v1 Link
object by only an optional endpoint-local `mtu` policy, for example
`"mtu": {"mode": "auto"}` or
`"mtu": {"mode": "manual", "bytes": 1400}`.
`{"mode": "unmanaged"}` opts out. Omitted policy on legacy
requests is unmanaged; importing a peer Setup Link does not copy the
sender's endpoint-local MTU. An old schema-v1 request must not erase
a previously managed MTU policy by accident. Do not extend a frozen
nested wire contract just because an internal Go struct gets a field.

Both readers reject unknown nested fields, duplicate/case-variant
keys, invalid versions, nulls, arrays, oversized/multiple payloads
and invalid backend/encapsulation/address combinations. Unknown
future versions exit as unsupported rather than being silently
interpreted as v1 or v2. This input **never** accepts recipient
private keys/PSKs or arbitrary commands.

`ensure` and `remove` invoke the canonical Inspect/Plan/
re-inspect-under-lock/Validate/Apply/Verify/Commit Engine, not a
different implementation. `changed: false` describes local
convergence only. An existing Link ID cannot silently be reassigned
a new backend by the current Engine; replacement/failover is not an
implicit `ensure` feature.

## Pairing, export and confirmed import

Supply even plaintext Setup Links on **stdin**; never pass sensitive
Quick Links in `argv` or shell history.

~~~sh
stl link preview --stdin --json < /root/private/received.stl
stl link import --stdin --confirm <import_confirmation> --json < /root/private/received.stl
stl link export <saved-gre-or-ipip-id> --json
~~~

Preview does not mutate State or inspect/repair the active host. For
eligible plaintext GRE/IPIP, configured WireGuard v3 or strict 32-byte
PSK IPsec v2 offers, it returns a lowercase SHA-256
`import_confirmation` over the exact normalized URL. Import requires
that **same** URL and token, then recipient-oriented inversion and
a separate authorized Engine operation. Token matching detects a
different payload; it does **not** authenticate its author.

The regular saved-State export command is intentionally restricted to
credential-free GRE/IPIP; a valid sender's private receiver credential
cannot be reconstructed from stored public State. Guided sender
Share instead uses the original protected handoff after new consent.
WireGuard v1/v2 and IPsec v1 legacy offers, or IPsec v2 with
noncanonical/non-32-byte PSKs, may remain previewable but cannot
be activated by silently guessing or migrating keys. Exact backend,
address and full Link identity mismatch at import is a conflict;
the importer does not replace an existing Link of a different identity.
A successful import means local convergence, not peer traffic.

For exact Setup Link schema fields, legacy-version behavior and
receiver-side inversion see [PAIRING.md](PAIRING.md).

## Protected sender workflows

For automation, WireGuard and IPsec sender creation accept a
public-only versioned request via stdin and write one SENSITIVE
receiver handoff to an **explicit existing private absolute output
path**. The CLI does not choose a new export directory or overwrite an
existing file.

Illustrative WireGuard sender request:

~~~sh
stl link create-wireguard --stdin --output /root/private/peer.stl --json <<'JSON'
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

The guided menu chooses its own private per-Link handoff store; the
non-interactive command does not create that extra implicit copy.
Sender staging durably reserves the exact public Link/offer digest
and its own protected key **before** the original secret-bearing
URL is published through atomic `0600` no-replace output. A
failed/incomplete attempt can leave protected pending intent and
credential files; never assume it is safe to regenerate a receiver
secret, delete a key or reuse the Link ID.

If the original complete handoff survives, `link preview --stdin`
provides the digest and `resume-wireguard --stdin --confirm
<setup-digest>` can retry that same sender identity. A crash-staged
`.stl-handoff-*.tmp` may instead be published by
`recover-handoff --source ... --output ... --confirm ...` **only**
after exact matching pending sender identity, digest, original
credential and owner-private inode checks. That command performs
no Link mutation, rekeying, service startup or remote transfer.
Lost/unsafe/orphaned original material requires explicit operator
reconciliation, not wildcard deletion.

After successful WireGuard Remove and independent resource-absence
checks, `link credential retire` requires the exact removal receipt
and expected local public key; it cannot be authorized from an
absent Link alone. IPsec uses corresponding exact staged
`activate-ipsec`, `connect-ipsec`, explicit
`reconcile-ipsec`/`reconcile-xfrm-ipsec` and receipt-bound
`retire-ipsec`; PSK retirement does not require a currently
running strongSwan service. Unknown VICI/XFRM effects and absent
recorded original ifindex are not deletion authority. `stl doctor
ipsec --json` is read-only and distinguishes absent/unknown/foreign
from positively admitted private runtime.

## Diagnostics and explicit traffic

`link status` verifies a local owned interface and public backend
state/counters, **not** the remote peer's reachability. A
`link diagnose` probe can measure Link Address replies, RTT,
loss and jitter; ICMP rejection/no reply remains inconclusive.
Its local automatic MTU is a conservative bound until suitable
path measurement is available. `link diagnose --all` uses one
stable, ordered saved-State inventory and independent Link checks;
`--timeout` accepts a positive Go duration such as `10m`
and starts before inventory loading. Each Link has a bounded
probe budget; there is **no arbitrary Link-count cap**. The optional
`--parallel 1..4` (default `1`) observes up to four **independent**
Links concurrently using the same saved-State snapshot and overall
`--timeout`. This limits concurrent diagnostic subprocesses, **not**
the number of Links. Results always remain sorted by Link ID regardless
of completion order. More concurrent probes can increase short-lived
host/network load; no Link/route/firewall/service is changed.
If a run is interrupted, incomplete or unprocessed Links remain
unknown. An interruption before trustworthy inventory produces an
error, never a fabricated empty successful batch. The report
may omit unverified counters rather than reporting false zeros.

Throughput is an **optional deliberate traffic-generating test**,
not a cap on tunnel throughput. The remote operator must first
start a listener bound to the **remote server's own Link Address**.

On the **remote peer**, replace the example private address with
that server's actual Link Address:

~~~sh
iperf3 --server --bind 10.80.20.1 --port 5201
~~~

On the **local client**, substitute the saved Link ID obtained from
`stl link list` (the same ID is required twice):

~~~sh
sudo stl link throughput YOUR_LINK_ID --confirm YOUR_LINK_ID --seconds 3 --json
~~~

The current short-test operation permits 1–10 seconds and sends one
TCP stream only to the selected, interface-bound peer Link Address
on TCP/5201, after exact ownership, route/source and installed
iperf3 3.11+ (3.x) checks. No fallback to the physical
underlay/default route, unbound socket, arbitrary destination,
UDP or automatic peer listener setup is allowed. Output contains
only bounded numeric bytes/rates and request metadata, not raw
iperf output. Test duration bounds keep a diagnostic deliberate;
they do not impose any ongoing packet forwarding or Link
bandwidth quota.

For detailed MTU/quality semantics see
[DIAGNOSTICS.md](DIAGNOSTICS.md). For uncertain Engine outcomes
before retry see [OPERATOR-RECOVERY.md](OPERATOR-RECOVERY.md).

## Development R1 — WireGuard over WSS/TLS

This is the candidate behavior for Issue #142, not a declaration that R1
is in Stable. Start the **guided** path using STL menu:
Create tunnel → WireGuard / WSS + TLS. Choose the listener or dialer,
route-derived local/public addresses, private Link IPv4 /30 or /31 pair,
WireGuard UDP listen/peer ports, WSS TCP port, private forwarding UDP port and
TLS server identity. The menu checks the optional pinned helper, shows an
effect summary, and requires fresh YES before host mutation. On the receiver,
Import setup link → WireGuard / WSS + TLS uses hidden paste, receiver-facing
preview and a separate YES. Existing Native/FOU/GUE/IPsec menus are unchanged.

For noninteractive automation on the **listening** machine, place this public
JSON in a temporary input file or pass on stdin, with real interface/underlay
values. It deliberately contains **no credentials**:

~~~json
{
  "schema_version": 1,
  "underlay": {"local": "198.51.100.21", "peer": "203.0.113.22"},
  "addresses": {"local": "10.75.0.1/30", "peer": "10.75.0.2/30"},
  "listen_port": 51821,
  "peer_port": 51822,
  "role": "listen",
  "tcp_port": 443,
  "remote_forward_udp_port": 53001,
  "local_keepalive": 25,
  "peer_keepalive": 25
}
~~~

Create a private **0700** directory for the sensitive receiver file, then:
~~~sh
sudo stl link create-wss --stdin --output /root/private-stl/wss-receiver.json < public-wss-request.json
~~~
This generates both WireGuard identities, two separate TLS leaf keys signed
by a fresh ephemeral Link CA, and an independent 256-bit bearer token. The
**original** recipient file is sensitive: transmit through an authenticated
encrypted channel, never paste into Issue/PR/log/terminal history. On the
receiver, inspect the transported file's receiver address/role and obtain
the printed byte-specific preview digest:
~~~sh
sudo stl link preview-wss --stdin --json < /root/private-stl/wss-receiver.json
sudo stl link import-wss --stdin --confirm LOWERCASE_64_CHAR_SHA256 < /root/private-stl/wss-receiver.json
~~~
The receiver's private settings and role are inverted; the first server
does not need a second setup transaction. Both operations run via the same
canonical Engine and exact per-Link locks. Both locally ensured endpoints
are still not proof of an actual Link; check the following on **each**:
~~~sh
sudo stl link diagnose-wss lnk_0123456789abcdef0123456789abcdef --json
ping -I LOCAL_PRIVATE_IP PEER_PRIVATE_IP
~~~
Diagnostics report Helper/Guard readiness, kernel WG handshake timestamp
and transfer byte counts separately; process readiness alone cannot attest
mTLS or application delivery. The generic `link diagnose <id>` active
PMTU/ICMP implementation is **not** yet WSS-carrier-aware, and the
`link diagnose --all [--parallel 1..4]` health center marks managed WSS
Links as **blocked**, reason `wss_active_diagnostics_not_implemented`,
while independently checking supported native Links; neither command
claims WSS reachability without a verified active carrier adapter.
Use dedicated `link diagnose-wss` for local WSS status and separately
test TCP/UDP/private ICMP before workload routing. On a restarted host, the already
persisted Link can be reconciled through the existing Engine restore or a
versioned desired-State v3 Ensure request. Never regenerate a WSS offer to
resume an already allocated Link identity.

~~~sh
sudo stl link remove LINK_ID --confirm LINK_ID
# Only if Remove committed but returned an explicit retirement failure:
sudo stl link retire-wss LINK_ID --confirm LINK_ID
~~~
Remove first verifies owner-scoped helper/guard/kernel absence, then retires
the Link's protected TLS/bearer/WG secrets under the same Engine locks using
the durable exact removal receipt. A failed secret-retirement phase leaves
its receipt retryable; a retired Link ID cannot be reused. Arbitrary
**operator-selected exported handoff paths** remain operator-managed and
must be separately retired from their external storage after confirmation.
The state schema is v4; older binaries must not attempt to manage WSS Links.

### Ordinary committed WSS original-generation admission (unreleased)

A committed `wireguard-wss` Link whose original WG interface is missing
from the local network namespace CANNOT be automatically recreated by
`link ensure` or `link restore --all`, nor removed by `link remove`, from
that absence alone. The original may survive DOWN in a different namespace
and later reactivate. This is true even if its nft guard and helper were
removed externally before the first `Remove` (no Crash Journal yet).
STL preserves committed State, owned claims and credentials and reports
failure before mutation. On a supported native host, an earlier trusted,
versioned kernel birth checkpoint stored with the committed Link and a
DIFFERENT currently attested host kernel generation plus strict host vacancy
can authorize legitimate post-reboot recovery. Missing/untrusted legacy
birth records cannot be silently upgraded or used as extinction evidence:
a healthy visible original no-op Ensure or sidecar repair preserves these
empty fields and does not report a covert authority change. Only creation
of a verified NEW original can record its newly witnessed birth.
Successful ordinary WSS Remove creates a receipt containing explicit
`wss_original_termination` proof. `retire-wss` refuses legacy or missing-
proof receipts, not just live interfaces or matching keys. A full host
reboot or manual State reconciliation requires separate Owner action;
never edit State JSON or delete a foreign guard to force an apparent success.

### Owner-gated WSS whole-kernel-reset reconciliation (unreleased)

When a durable WSS crash journal has lost its original, in-process
kernel deletion proof, **do not** clear it from missing local WG/UDP
observations. A moved DOWN interface can become active again. A
real full-kernel reboot, separately planned and authorized by the
Owner, terminates ALL original kernel WG objects across namespaces.

```sh
# Before the separately authorized full-host reboot:
sudo stl link arm-wss-cold-boot LINK_ID --confirm LINK_ID --json
# After that real reboot and independently verified current host absence:
sudo stl link reconcile-wss-cold-boot LINK_ID --confirm LINK_ID --json
```

The first command durably checkpoints the kernel boot UUID into the
original protected journal together with the versioned trusted
`cold_boot_source` marker, **does not reboot**, changes no host
resources and retires no credentials. UUID-only checkpoints recorded
by earlier candidate builds lack this marker and cannot be re-armed or
reconciled by the cold-boot route: preserve their original protected
State/journal and follow the Owner-gated manual recovery plan. Both
commands fail closed unless
running in the initial host PID namespace with an unshadowed original
kernel procfs `/proc/sys/kernel/random/boot_id` (no bind-mounted or
container-generated UUID). A root shell inside a container cannot
bypass this safety gate; keep the journal and follow the operator
recovery runbook on an independently verified host. The second refuses the same
kernel boot or unarmed journal, rereads original State ownership,
claims and committed credential identity, confirms complete current-
boot helper/nft/WG/socket vacancy and commits the exact one-time
State transition without modifying host networking. For an original
committed LEGACY repair, it preserves all original identities and issues
a dedicated `wss_cold_boot_restore` one-use witness in State; it does
NOT silently invent original birth provenance. A subsequent authorized
`link restore --all` may create the missing original only with a trusted
current kernel source, independently empty host inventory and the
exact original committed issuance/claims. The witness is durably SPENT
alongside a new pre-effect crash journal before any host mutation;
successful creation replaces it with the actual NEW birth source.
If that restore crashes, the original journal and spent token prohibit
automatic replay until another independently armed and Owner-approved
full-host reboot. Ordinary no-op Ensure, Remove and legacy journal-only
clearance cannot consume or renew the authority. Committed Remove
produces a fingerprint-bound receipt; separate `retire-wss`
is still necessary and fail closed. For committed Ensure/repair the
committed Link and credentials remain intact for authorized restore.
Owner approval is **mandatory for the external whole-host reboot**;
the CLI never schedules, performs or authorizes it. Read full
preflight, namespace ownership, backup, failure and rollback plan in
[operator recovery](OPERATOR-RECOVERY.md#unreleased-wss-executable-manual-cold-kernel-reboot-recovery).

### WSS R2: crash-safe preparation and explicit vacancy reconciliation

Interrupted WSS Ensure/Remove or repair may leave a **durable,
nonsecret** pre-effect journal. Until resolved, the Link and its
planned resource identities are reserved against automatic replay and
conflicting allocations.

A **verified original-kernel deletion witness**, not merely the
absence of local `wg` interfaces, a socket or a helper, is necessary
before a previously interrupted WSS transaction can be cleared.
Namespace migration can hide an existing but DOWN WireGuard object
without leaving a visible UDP socket. The following explicit
reconciliation commands fail closed and retain the original journal
when that positive witness is unavailable, even if the local
inventories look empty. An initial, uncommitted Ensure with proven
original absence may otherwise have been eligible for an
exact-credential retry:

```sh
sudo stl link reconcile-wss-vacant LINK_ID --confirm LINK_ID --json
```

This initial-Ensure command never changes any host object or credential.
The present R5 safety implementation deliberately **does not issue a
retirement witness from namespace-local absence**; a pre-kernel,
guard-only crash can therefore remain quarantined even if the guard
was later removed externally. The explicit Owner-approved cold-kernel-reset
recovery path above is now implemented for a lost witness; without
its durable pre-reboot checkpoint and strict post-boot checks, the
original journal remains quarantined. No stale journal may be silently replayed.

For a **previously committed Remove**, whose host effects have entirely
disappeared, use a separate confirmation path:

```sh
sudo stl link reconcile-wss-removed LINK_ID --confirm LINK_ID --json
# Only after that State-only commit:
sudo stl link retire-wss LINK_ID --confirm LINK_ID
```

The Remove path requires the exact original committed Link, resource
claims, private TLS/authorization fingerprints and pre-effect journal.
Absence of helper/WG/nft resources is necessary but NOT sufficient:
this read-only recovery command cannot invent the original ifindex-
deletion proof lost with an earlier process. If no positive original-
object or attested kernel-generation evidence survives, it fails closed
without deleting State or publishing any receipt; use the separately
Owner-gated cold-boot or exact-object recovery path instead.
It does not mutate host networking or protected files. The receipt can
delete only SHA-256-matching original issuance-time TLS/auth material,
never a same-name or same-mode replacement.

If a host effect is present or ownership cannot be independently
verified, neither *vacancy-only* command is a general cleanup mechanism.
The unreleased R3 candidate adds two separately confirmed recovery modes.

For an interrupted **committed Ensure/repair** whose original host effects
are all absent, use:

`sh
sudo stl link reconcile-wss-repair-vacant LINK_ID --confirm LINK_ID --json
sudo stl link restore --all
`

The repair-vacant command confirms the original committed Link, claims
and actual issuance-time credential file contents. It does not issue
its own original WG deletion witness, so unknown previously interrupted
cleanup remains quarantined. A verified successful original-object
recovery may clear the pending journal without changing the Link,
object nonce, claims or fingerprints ONLY when the committed original
has trusted historical birth provenance. Legacy committed repairs
instead retain the original journal even after exact original-object
compensation and strict host vacancy. The JSON result truthfully reports
`journal_cleared:false` and `manual_cold_boot_required:true`;
use Owner-gated, separately armed whole-kernel reboot recovery to
create one future original rather than invent a birth identity.

For a **live, originally attributable interrupted host effect**, use:

`sh
sudo stl link reconcile-wss-original LINK_ID --confirm LINK_ID --json
`

The canonical Engine holds maintenance, Link and resource locks. The
128-bit original creation nonce appears in the nft guard rule, systemd
unit description and kernel WG alias. WG creation first uses an exclusive
unpredictable nonce-derived staging name; it is then tagged by ifindex
and only then renamed to the stable name. Linux does not publish
the alias atomically with the kernel NEWLINK. An unmarked staging
interface, even if nonce-named, empty and down, has no reliable proof
that STL created it; it may have been created by another actor between
the guard and STL's exclusive NEWLINK. The command **always rejects**
such a pre-alias object, retains the ingress guard and original journal,
and never deletes that possibly foreign interface. A genuinely original
pre-alias crash requires separate out-of-band identity-attested operator
recovery (see `OPERATOR-RECOVERY.md`); guessing from name or empty
configuration is unsafe. For a committed legacy repair, even after
precise original-object compensation and full host vacancy, the
original journal is RETAINED for separately authorized cold-boot Arm and
Reconcile: `reconcile-wss-original --json` reports
`journal_cleared:false`, `manual_cold_boot_required:true`.
A second compensation cannot consume that journal by missing inventory
alone; ordinary RestoreAll remains blocked. For a trusted birth-attested
original, the exact successful compensation may consume its journal
without falsifying old-kernel extinction or permitting same-kernel
recreation. Nonce-tagged originals instead permit only
verified intermediate subsets of the originally intended WG configuration.

Owner-verifiable effects are compensated in protective order: **collect
original helper, remove original WG by rechecked ifindex, remove original
nft guard LAST**. All three namespace-local WG inventories must agree,
AND a bounded UDP listener inventory must confirm that the protected
port is unoccupied in the guarded/birthplace namespace. These checks
are necessary but **not sufficient**: a moved DOWN WG interface has no
socket until brought back UP. Guard deletion additionally requires
a same-transaction, original-nonce-bound witness of successful,
ifindex-targeted kernel deletion; read-only vacancy reconciliation
cannot fabricate such a witness from State, alias, interface names or
absence. Without complete proof the nft guard, journal and credentials
remain quarantined, even if this rejects some formerly permitted
guard-only/after-delete crash recovery flows. Initial Ensure
releases its uncommitted journal; committed repair preserves original
Link/fingerprints; committed Remove commits the original retirement
receipt, to be consumed later with `retire-wss`.

Failures during compensation retain the journal for an explicitly
confirmed repeat inspection. Foreign same-name objects, incomplete or
contradictory readback and foreign global WG port/key owners never
authorize cleanup. Nonce labels do not defend against malicious local
root with access to protected State and arbitrary host mutation.
The rootless tests use real kernel WG and nft but a disposable systemd
shim; real-systemd reboot, two-host field use, ARM64 WSS and independent
review remain separate acceptance gates.
