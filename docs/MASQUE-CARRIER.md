# MASQUE CONNECT-IP Carrier (Stable v0.1.28+)

> **Version availability:** native MASQUE with default private mTLS first
> shipped in Stable `v0.1.28`. The **opt-in Public TLS / CONNECT-IP bearer**
> mode and first-party HTTP/2 GET/HEAD ship starting in Stable `v0.1.29`.
> Private two-host v0.1.28 CLI traffic and service-restore evidence does **not**
> validate v0.1.29 PublicTLS, fully guided pairing or cold physical reboot.
> Track outstanding field acceptance in [Issue #243](https://github.com/ach1992/simple-tun-link/issues/243)
> and [Issue #93](https://github.com/ach1992/simple-tun-link/issues/93).
> Stable `v0.1.30` additionally verifies the **original helper-owned TUN
> MTU** against protected Auto/Manual intent without applying a second
> kernel MTU mutation. The fix does not validate a higher physical path MTU
> or clear any earlier QUIC Remove quarantine; see
> [Issue #253](https://github.com/ach1992/simple-tun-link/issues/253).
> A Release, local-ready result or ping is not production approval.

## What it is

An **optional native STL Backend** for authenticated RFC 9484 CONNECT-IP
transport over **HTTP/2 + TLS/TCP**. It carries private IPv4 **L3 IP packets**
over a point-to-point TUN, with independent, per-Link client/server TLS keys.
A self-issued server CA and exact peer certificate identity are bound to the
original protected receiver offer. The normal **single Engine** owns the
Link ID, resources, locks, State, journal, rollback, recovery and persistence.
It does not create another Link controller, use a WireGuard interface, or
require a separately installed QUIC/WSS helper.

The physical listener uses a TCP port selected by the operator (usually 443),
and both physical endpoints must use the same address family (either IPv4 or
IPv6). The **private overlay stays IPv4 `/32`** even on IPv6 physical hosts.
The listener must accept inbound connections; no automatically assumed NAT,
CDN, firewall evasion or reverse tunnel is provided. The dialer reconnects
with bounded backoff and verifies the listener's TLS CA/name. The listener
requires the original matching client certificate identity **by default**.
An explicit opt-in `"public_tls": true` mode uses ordinary TLS without
a client certificate, but requires a fresh per-Link 256-bit
`Authorization: Bearer` value on the HTTP/2 extended CONNECT-IP
request **before** the private TUN can be accessed. The dialer still
verifies the listener's CA and certificate SAN. This request bearer remains
only in protected original per-Link material and the sensitive receiver
handoff, never in public State, Preview, Status, diagnostics or process argv.
Original mTLS Links and their protected file inventory remain unchanged;
switching authentication modes requires an explicit Remove and fresh
pairing, not an in-place Ensure.

An opt-in public-TLS listener offers a real first-party HTTP/2
`GET /` and `HEAD /` response with HTTP 404 on unknown paths,
on the **same TLS port**. These ordinary unauthenticated requests cannot
start CONNECT-IP or forward private packets. This is not a third-party
website impersonation, CDN proxy, public browser-trusted certificate or
proof of browser TLS fingerprint equivalence.

The public HTTP/2 listener advertises and enforces a per-TLS-connection
maximum of 64 concurrent active request streams. A new request at capacity
(including GET, HEAD and unsupported methods) receives HTTP/2
REFUSED_STREAM on its own stream, without retaining additional response
state or interrupting existing requests. Completed or canceled GET
responses release their exact pending-body slots. Only stream-window-ready
responses are scheduled for DATA, so zero-credit requests cannot cause
repeated full-map scans. HEAD and fully ended rejected methods finish
synchronously; unsupported requests with an open request body are reset
to avoid keeping unaccounted half-closed streams. This is an HTTP/2
per-connection resource boundary, **not** a limit on STL Links, servers,
throughput or data-plane packet forwarding. Unsupported public HTTP
methods receive an error on their own valid stream; reusing a closed stream
is an HTTP/2 protocol error rather than an attempt to send new HEADERS on
the closed stream. Malformed Capsule-Protocol values are rejected without
terminating the helper process, even when no bearer was sent.

A live authenticated CONNECT-IP stream sends HTTP/2 PING probes even when
neither side has private IP packets to transmit. Currently the dialer probes
every 20 seconds, and both endpoints close a session that stops delivering
HTTP/2 frames for 75 seconds. A silently interrupted TCP path therefore
releases the listener's single-client slot and triggers the **existing**
dialer reconnect loop using the same Link, credentials and owned TUN/route.
These are session-liveness defaults, **not** instant connectivity proof,
packet-loss measurement or a public recovery-time SLA. Legitimate private
traffic and PING replies refresh observed H2 activity; a healthy quiet
Link is not retired simply because its private IP is idle. The local Link
remains committed if the physical peer is down. The listener records
unexpected authenticated H2 session failures (including idle timeouts) in its
local systemd journal, without logging private keys or capsule payloads.

**Local-ready ≠ authenticated remote connection ≠ measured private traffic.**
`status` reports owner-verified systemd/TUN/route only. `diagnose` performs a
bounded five-echo private IPv4 check; it does not certify sustained throughput,
carrier PMTU or fault recovery. HTTP/2 over TCP can exhibit head-of-line
blocking, but a comparative performance benchmark is not a MASQUE release gate.

## Create, preview, import and recovery

On an installed Debian/Ubuntu host, **Create tunnel → MASQUE** checks the
canonical package plan before asking for addresses or issuing credentials.
**Import setup link → MASQUE** performs the same check after confirming
the offered receiver identity and physical local address, before staging
any private material.
MASQUE uses the built-in Go TLS/H2 implementation: its only installable
prerequisite is `iproute2`; it does not require WireGuard, strongSwan, nftables,
iptables, kmod, or an external MASQUE helper package. If `iproute2` is missing,
the interactive installed root terminal offers a separate **PREPARE** step
with an exact signed-APT preview and a fresh confirmation; Create asks for a
separate YES afterward. A running host `systemd` manager, TUN device, and
privileged service access are runtime capabilities, not permission to replace
the OS init system or perform global firewall/routing changes. Existing CLI
`create-masque` remains a noninteractive entrypoint and **does not silently
install packages**. A failed package preview should retain its real reason
and next action; no package installation is implied by viewing the menu.

Create on the **creator** (the role may be `dial` or `listen`; creator/receiver
is independent of network direction). This example uses non-routable
**documentation-only** IPv6 prefixes and must be replaced by addresses
actually assigned to the two authorized servers:

```sh
stl link create-masque --stdin --output /root/stl-masque-receiver.json --json <<'JSON'
{
  "schema_version": 1,
  "underlay": {"local": "2001:db8:1::2", "peer": "2001:db8:2::1"},
  "addresses": {"local": "10.252.98.2/32", "peer": "10.252.98.1/32"},
  "role": "dial",
  "tcp_port": 443,
  "tls_server_name": "2001:db8:2::1",
  "public_tls": false
}
JSON
```

The creator receives a **single owner-private `0600` JSON receiver offer**
whose SHA256 is printed, never its private key. Securely transfer the **exact
original file** to the receiver. Compare its digest with an independently
trusted communication from the creator; a SHA256 alone is **not** sender
identity or authentication. On the **receiver**:

```sh
stl link preview-masque --stdin --json < /root/stl-masque-receiver.json
stl link import-masque --stdin --confirm YOUR_REVIEWED_SHA256 --json < /root/stl-masque-receiver.json
stl link status YOUR_LINK_ID --json
stl link diagnose YOUR_LINK_ID --json
```

On the original sender, `resume-masque --stdin --confirm SHA256` takes the
**original** receiver offer and resumes only its already issued identity;
**never** manufacture new keys for a partially committed Link. `stl link
restore --all` replays saved committed Links under the canonical Engine.
For uncertain pre-effect host outcomes, inspect owned resources and use
`stl link reconcile-masque ID --confirm ID`; it is **not** permission to
silently reuse unknown foreign resources or mutate a different Link.
`stl link remove ID --confirm ID` performs canonical owned local removal;
`stl link retire-masque ID --confirm ID` is the distinct, receipt-bound
protected-material retirement step after verified removal. A successful
confirmed Remove also deletes the original receiver offer **only** when
its private menu-owned origin receipt matches the exact saved file
(including device/inode and digest); independent CLI `--output` remains
operator-owned and cannot publish into the reserved menu directory.
Historical unmarked offers are preserved for explicit inspection, not
silently adopted. Successful `reconcile-masque` of an interrupted Remove
performs the same verified original-offer retirement **after** proving
host absence and committing the recovered removal. If either an
ordinary confirmed MASQUE Remove or exact host-absence reconciliation
commits removal but original MASQUE mTLS retirement then fails,
the result remains `outcome=removed_cleanup_incomplete` and
`partial_result.removed=true` with
`reason_code=masque_material_retirement_incomplete` and stage
`credential_retirement`; the original receiver offer remains untouched.
After verifying the matching receipt and host absence, rerun **only**
`stl link retire-masque ID --confirm ID`, not Remove or Reconcile.
That exact receipt-bound continuation completes mTLS retirement, then
retires the original menu-owned receiver offer only when its inode,
content and origin receipt are still verified. If only offer cleanup
is incomplete, its distinct `protected_handoff_cleanup` stage is
reported and the unknown file is preserved. Incomplete Remove preserves
the original for recovery. Neither command removes anything on the
**other** server automatically.

The interactive menu offers **Create tunnel → MASQUE / CONNECT-IP** and
**Import setup link → MASQUE / CONNECT-IP**. Guided Create offers
**1. Private mTLS (default)** and **2. Public TLS (per-Link request bearer)**,
includes the choice in the pre-YES review and preserves it through the
receiver's private Preview and Import review. Guided Create also offers an
optional **advanced initial MASQUE TUN MTU**; entering 1400, for example,
is appropriate only after verifying that the physical path can carry it and
that any nested carrier's minimum underlay is satisfied. Normal standalone
Create still defaults to 1280. This value is embedded in the original
protected peer offer; there is no silent remote path-MTU measurement or
unilateral MTU change to an existing committed helper. The creator JSON field
`"public_tls": true` selects opt-in public mode; omission uses
mTLS. Neither mode needs a new external helper or a second Engine. On Import, enter the exact
absolute path to the original owner-private `0600` single-line offer file
(or paste its JSON). The existing protected file reader rejects symlinks,
foreign ownership, altered/partial content and unsafe permissions without
printing its contents. Protected paste masks terminal echo. Import requires
a fresh, operator-entered `YES`; guided Create saves the
exact original handoff privately for `My tunnels → Share Setup Link → SHOW`.
A CLI-created original can be disclosed only via explicit owner-private file
selection and matching saved Link identity; an imported receiver cannot
regenerate the creator's handoff. Do not paste secrets into shell arguments,
shared terminal transcripts, Issues or logs.

## Crash and ownership boundaries

- A pre-effect operation journal is durably published before starting any
  systemd/TUN service; uncertain effects block blind automatic retry.
- Staged credential files are exact Link/role/digest-bound and no-clobber.
  After a pre-host interruption, an **identical, complete** staged generation
  may be reused; incomplete, altered or foreign material is **not repaired**
  or deleted implicitly. Inspect and reconcile such a generation before
  deciding what to do. This remains a specific failure-recovery acceptance
  item for Issue #142.
- Owner checks verify the existing transient service, executable identity,
  protected material directory, TUN alias, interface address and private
  route. Another service, file or Link is never adopted by filename alone.
- Default private TUN MTU is 1280 bytes; physical-path PMTU is not
  established by local setup. A manually selected MASQUE MTU is embedded
  in the original protected helper configuration. The helper creates its
  own TUN at that value and applies the same bound to packet buffers; the
  canonical Engine verifies the owner-marked interface and effective MTU
  without a second, inconsistent netlink rewrite. Set matching endpoint
  MTUs through the original Create/Import offer; changing an existing
  committed MASQUE helper's MTU requires a fresh pairing rather than
  changing only its kernel interface.
  Small private TCP/UDP receipts prove application connectivity, **not**
  physical-path PMTU, sustained performance or reboot recovery. Do not
  infer those outcomes from local setup or replace the required functional
  journey with benchmarks.
- **QUIC over MASQUE:** Pinned Hysteria v2.13.0 independently timed out over
  a healthy IPv4 TUN with MTU 1280 in controlled testing. Its server
  attempted oversized UDP sends (`EMSGSIZE`); a public HTTP/3 test succeeded
  at MTU 1308 and failed at 1307 in that isolated setup. This is a measured
  compatibility boundary for that setup, not a universal path-MTU claim.
  When intentionally nesting QUIC, provision a fresh MASQUE parent with
  sufficient **verified** MTU (for example 1400 where the actual path permits),
  then test authenticated UDP, HTTP/3 and application traffic. Do not
  silently raise a committed parent's MTU or assume an ICMP Ping proves QUIC.

### Interrupted original with an active helper

A pre-commit `ensure` can leave a **pending journal and a live, uncommitted
helper** if the operator/process is interrupted after Host activation. In that
case `link list` may be empty, while the original transient service and TUN
still exist. `reconcile-masque` deliberately rejects a live or uncertain
original: it does **not** stop services or silently claim ownership.

For an explicitly authorized **disposable test Link**, recovery has two separate
steps, and neither may be skipped:

1. Independently inspect the exact pending journal and confirm its Link ID,
   resource claims, original executable/configuration, material generation,
   and intended owner. Verify the *effective* transient systemd identity
   (`Id`, `Transient`, `FragmentPath`, `Description`, `ExecStart`, `MainPID`,
   `ControlGroup` and process `argv`) against that Link. Verify the TUN owner
   alias `stl:masque:<id>`, the exact `/32` address and peer route. Check that
   no active consumer needs the helper. A unit name, process name, empty
   `link list` or absence of a remote connection is **not** sufficient proof.
2. Only when those checks positively identify the original test-only service
   and the operator has authorized retiring it, stop **that exact** unit with
   `systemctl stop` and verify both the service and TUN are absent. Then run
   `stl link reconcile-masque <id> --confirm <id> --json` from the executable
   bound to the **same State root**. Confirm a durable original retirement
   receipt, no remaining pending journal and no original credential material.

If the service is foreign, the original identity changed, a live consumer
remains, or the stop outcome is ambiguous, **do not stop/delete by guess**.
Preserve State, journal and protected files for independent owner review. This
is a deliberately manual recovery boundary, **not** a cleanup timer, automatic
service takeover or instruction to change the installed production binary.

## Publication and follow-up field acceptance

For **v0.1.28 private mTLS**, an authorized two-physical-server CLI pairing,
private ICMP/TCP/UDP and controlled service restore/remove passed; that
historical receipt does not validate the **new v0.1.29 PublicTLS mode**.
A new release requires exact-source review, verified artifacts and installed
version identity; **publication alone does not prove physical acceptance**.
For new-mode field acceptance, record the exact installed artifact,
independently confirmed original private receiver offer,
fresh Create/Import confirmation, authenticated bilateral private IPv4
ICMP/TCP/UDP, reconnect/restore of the same Link, and owner-scoped Remove
without foreign effects. Record any blocked or untested reboot truthfully;
an in-place restore does not prove a cold boot. Do not silently bypass
platform restrictions or treat release publication as permission to install
on production hosts. A GRE performance comparison, CPU/throughput scorecard,
synthetic performance threshold or soak is **not** a MASQUE prerequisite.
See [Issue #142](https://github.com/ach1992/simple-tun-link/issues/142)
for the current evidence and unresolved host-level gates.
