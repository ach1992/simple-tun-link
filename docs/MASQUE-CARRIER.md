# MASQUE CONNECT-IP Carrier (development candidate)

> **Unreleased.** This document describes the experimental candidate in
> [Issue #142](https://github.com/ach1992/simple-tun-link/issues/142), not
> a capability available in the published v0.1.27 installer. Do not infer
> production approval from a green local test or a successful private ping.

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
requires the original matching client certificate identity.

**Local-ready ≠ authenticated remote connection ≠ measured private traffic.**
`status` reports owner-verified systemd/TUN/route only. `diagnose` performs a
bounded five-echo private IPv4 check; it does not certify sustained throughput,
carrier PMTU or fault recovery. HTTP/2 over TCP can exhibit head-of-line
blocking; compare it to GRE Native with the same bidirectional workload.

## Create, preview, import and recovery

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
  "tls_server_name": "2001:db8:2::1"
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
protected-material retirement step after verified removal. Neither command
removes anything on the **other** server automatically.

The interactive menu offers **Create tunnel → MASQUE / CONNECT-IP** and
**Import setup link → MASQUE / CONNECT-IP**. Protected paste masks terminal
echo and requires a fresh, operator-entered `YES`; guided Create saves the
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
  established by local setup. Avoid treating a short TCP/UDP transfer as a
  sustained benchmark. Packet loss, CPU utilization, latency, restart and
  genuine reboot require separate measured evidence.

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

## Release gates

The unpublished candidate requires full Go tests/vet, independent exact-HEAD
review, public CLI acceptance on **both** authorized test servers, malformed
input/authentication/reconnect/foreign-owner/partial journal tests, reboot and
multi-Link recovery, and sustained two-way comparison with GRE Native under
equivalent conditions. Only the Owner can authorize merge, release and
Production; see Issue #142 for the authoritative latest pass/fail record.
