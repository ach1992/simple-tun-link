# Spoof Direct TUN Carrier — development candidate (Issue #262)

> **Release gate:** This document describes source candidates on the
> original `feature/262-spoof-carrier` and isolated
> `feature/262-smart-20261122` branches. It is **not** a claim that
> Stable `v0.1.33` has Spoof, or that public Internet anti-spoofing
> restrictions can be bypassed.
> Merge/release require independent review and the full Issue #262 acceptance.

## What is carried vs how the peers reach each other

Each Link is a managed, Linux-native private IPv4 **TUN /32 to /32** path,
with **Noise XKpsk0 + ChaChaPoly encryption and authenticated identities**.
The carrier's outer real destination is always one of the explicitly
operator-declared real peer IPv4:port receive endpoints in the one
confidential Setup Code; it may vary between a primary and any paired
alternates. STL never guesses destinations from incoming forged Sources or
generates an arbitrary unrelated destination. The **outer source** is
independently selected from the
operator-provided LOCAL `sources.txt` on each server. No Source list crosses
between peers and STL does not check ownership, country, provider, permission
or eligibility of Source IPs. It checks literal IPv4 syntax, that the Source
appears in this Link's current local file, and whether packets work.

Do not confuse the **inner application protocol** with the **outer
IPv4 carrier**. One encrypted TUN may carry application TCP, UDP and ICMP
over any working outer packet format.

| Outer STL profile | IPv4 protocol | What is actually sent |
| --- | ---: | --- |
| `udp` | 17 | Raw IPv4 UDP datagrams and a bound real-destination UDP receive port |
| `icmp` | 1 | Unsolicited ICMPv4 Echo Reply with per-Link receive identifier; no solicited kernel echo |
| `tcp` | 6 | TCP-header **RST-shaped raw datagrams**; **not** a TCP handshake, reliable TCP session or TCP/TLS tunnel |
| `gre` | 47 | GRE-shaped wrapper with an experimental EtherType and STL-owned Noise payload; not a general GRE interface |
| `ipip` | 4 | Nested IPv4 packet with experimental inner protocol number and STL-owned Noise payload; not general kernel IPIP interoperation |
| `proto58` | 58 | Bare STL-authenticated raw packets in IPv4 protocol 58 |
| `proto58-echo` | 58 | Echo-reply-shaped wrapper, **not** valid native ICMPv6 carried over IPv6 |
| `l2tpv3` | 115 | RFC 3931-style nonzero data Session ID preceding STL's own authenticated payload; **not** a native kernel L2TPv3 pseudowire or negotiated session |

The standard IPv4 protocol numbers are allocated by
[IANA](https://www.iana.org/assignments/protocol-numbers), and IP protocol
115 uses a [L2TPv3 Session ID data header (RFC 3931)](https://www.rfc-editor.org/rfc/rfc3931).
The experimental wrappers here are specific to STL. All eight profiles
have passed authenticated private ICMP in the two owned isolated Linux
containers; no blanket Internet/provider acceptance is implied.

**Default: `--outer auto`**. The creator's single offline Code pins the
original *permitted receive/discovery policy* for both ends. Each endpoint
separately chooses its **local outgoing** Source and outer profile;
there is no expectation that the two directions use the same pair.
`--tx-outer PROFILE` is an **endpoint-local override** usable with
`--outer auto` to pin that host's outgoing protocol; the other endpoint
may choose differently. Without an override both sides automatically
choose and rediscover independently. A fixed `--outer udp`, `icmp`,
or another named profile pins that profile for both sides by default,
without profile hopping. Neither kind of policy requires a live initial
control connection.

Automatic switching is **in the same Link**: changing the selected
source/profile/authorized destination neither reissues keys nor constructs
an additional Link or manager. Background authenticated path probes keep
discovering and saving verified backups at a lower rate while the Link
is healthy. Actual authenticated bilateral delivery is required before
status reports `CONNECTED`. Not all networks permit all packet formats.
Source-IP ownership is not inferred by the product from ASN, country
or address prefix; operators remain responsible for applicable network
authorization.

## Prerequisites and scoped changes

On **both** Linux servers: installed trusted root-owned STL executable,
root privileges, systemd, `/dev/net/tun`, `iproute2` and the relevant
raw socket capability (`CAP_NET_RAW`). The two **real** endpoint IPv4
addresses must have a path for the selected outer protocol. This is not
checked as a prerequisite for local Link creation; an offline peer is valid.

The Engine manages the original per-Link transient `systemd` service,
private /32 TUN address, exact peer /32 route, owned interface alias,
protected local X25519 material, restore unit, resource claims, and
durable removal receipt. It does **not** replace unrelated interfaces,
adopt foreign services or delete foreign network state. With explicit
per-endpoint `--manage-ingress --ingress-device DEVICE`, it may install
and remove only the original Link's own tightly scoped IPv4 INPUT rules
via a supported `iptables` CLI (legacy or nft backend) **only
when a relevant host INPUT-chain blocker is detected**. This covers
both the real-endpoint outer receive path and the **decrypted private
peer -> local TUN** INPUT path. A default INPUT DROP applies to
local TUN traffic too; an authenticated outer handshake alone does
not prove that inner TCP/UDP/ICMP reaches the application. If current
policy and rules already admit a path, STL adds no redundant rule.
It does not automatically flush a chain, change default policy
or manage foreign rules. Native nft
chains, external provider ACLs and `rp_filter` may still reject packets;
verified bilateral traffic remains the only delivery proof. Ingress
auto-management is OFF unless explicitly selected and requires the
trusted host `iptables` command before pairing.

The numeric `PORT` in `--creator/--recipient` is the UDP/TCP
destination receive port where applicable; for ICMP it is an Echo ID,
for L2TPv3-style data it participates in the session identifier, and
for other raw profiles it is a per-Link receive discriminator.
The canonical Engine reserves the actual resources for the selected
profile(s); `auto` reserves all necessary profile namespaces.
Keep endpoint identifiers nonzero and avoid collisions with other
services/Links.

## Current remediation — NAT, private L3 and recovery

**Simple host:** The original paired external IPv4:port endpoint is
locally assigned and is also the default receive-bind address. Nothing
special is needed.

**NAT / port forwarding:** When a paired external endpoint such as
`203.0.113.10:48001` is DNAT-forwarded by an operator-controlled
router to an assigned private address `10.10.0.3:49001`, use
`--bind-ipv4 10.10.0.3 --bind-port 49001` **on that server only**.
Optional `--bind-alts IP:PORT,...` declare more locally assigned
receive sockets, independent of original `--creator-alts`/
`--recipient-alts`, which remain immutable and authenticated
in the Setup Code. `--device` selects outgoing; `--ingress-device`
selects actual incoming NIC; these need not be the same. Use the
guided menu's `advanced` option. STL never configures the
external DNAT/port-forward mapping itself.

**Firewall:** Managed rules use
`--manage-ingress --ingress-device eth0` and target the actual
post-DNAT locally bound destination (plus exact private TUN input).
No unrelated host rules are removed. Independent nftables hooks can
still reject traffic.

**True private IPv4 status:** `CONNECTED` describes the bilateral
Noise outer transport. `runtime.private_l3_status` is separately
`UNVERIFIED`, `VERIFIED_ICMP` after real private IPv4 echo,
or `ICMP_PROBE_FAILED` after a failed check. Private evidence is tied to
its exact authenticated Session/Source/Profile/Destination generation: a
change in selected route immediately returns to `UNVERIFIED`, and delayed
results for an older route cannot revalidate a replacement. TCP/UDP can work
even if ICMP is blocked; validate separately using applications/
`link diagnose`.

**Reverse-path filtering (`rp_filter`):** `spoof-status` reports the actual
`all`, incoming NIC and effective `max(all,interface)` Linux policy. An
asymmetric return route may work under Strict if the reverse FIB matches;
never assume Strict itself proves a drop. When `rp_filter` is a likely blocker,
STL can modify the receiving server's settings after an **explicit preview and
operator confirmation**, without re-pairing or creating another tunnel:

```sh
stl link rp-filter plan LINK_ID --mode loose
stl link rp-filter apply LINK_ID --mode loose --confirm LINK_ID
# If Loose still cannot pass the asymmetric return path:
stl link rp-filter plan LINK_ID --mode off
stl link rp-filter apply LINK_ID --mode off --confirm LINK_ID
# Undo this Link's approved policy independently of other active STL Links:
stl link rp-filter restore LINK_ID --confirm LINK_ID
```

`stl menu` -> My tunnels -> Spoof tunnel -> **Fix rp_filter** provides the
same interactive `Loose (2)` / `Off (0)` / `Restore previous` actions with
fresh `APPLY` or `RESTORE` confirmation. Use `--interface NIC` if automatic
incoming NIC discovery cannot distinguish DNAT/multiple interfaces.
`plan` is entirely read-only. `Off (0)` may require both
`net.ipv4.conf.all.rp_filter=0` and the incoming NIC's value `=0` because
Linux uses the **maximum** of the two. Changing `all` can make effective
filtering on OTHER interfaces weaker **or stronger** depending on their own
settings: inspect the explicit host-level impact before approving. `Loose (2)`
usually changes the receiving NIC only. A global `all=2` may already
provide effective Loose without any NIC write; STL journals that shared
baseline and reports later foreign changes rather than silently overwriting
them. No version/provider/IP allowlist prevents the operator from selecting
Off.

Every confirmed change is journaled in STL's existing canonical State before
writing the kernel and verified by readback, with ownership-aware sharing
between concurrently active Spoof Links. It is reapplied during STL's owned
reboot Restore and returned to the verified original on Link Remove or
explicit `rp-filter restore`. After an interrupted Remove, repeat that
`restore` with the same original ID; unknown external sysctl changes are
reported instead of overwritten blindly. The same reboot Restore unit remains
installed while a removed Link has an unsettled `rp_filter` journal or exact
protected-material retirement receipt. Following a crash, `restore --all`
attempts both owner-scoped recoveries. Only after successful durable cleanup
of the last owner can STL remove the shared recovery unit.
This is an on-host Linux fix, **not** NAT traversal, provider-side anti-spoofing or a guarantee that the remote
network will accept candidate packets.

**Interrupted Remove:** The Engine can safely resume original
protected quarantine via `stl link retire-spoof LINK_ID --confirm
LINK_ID` only if the exact committed removal receipt is present.
Retry is idempotent; foreign or uncertain files are preserved. Its filesystem
retirement order durably syncs the quarantine parent after rename, the
protected-file unlinks while the exact receipt marker still exists, the
subsequent marker unlink, and the removed quarantine parent **before**
marking the State receipt retired.

## Interactive workflow

In an interactive terminal, run `sudo stl menu`, then
**Create tunnel → 10. Spoof / Direct TUN** on A or
**Import Setup Link → 6. Spoof / Direct TUN** on B.
Create offers an exact Source file **Recheck**, Auto or a manually fixed
raw outer profile, optional real alternate IPv4:port receiving endpoints
on both servers, an optional local outgoing override in Auto mode, a
local Auto/Manual TUN MTU policy, an optional explicitly confirmed
Link-scoped firewall management choice, review of real endpoints and
private addresses, and requires
typing `YES` before issuing the confidential Setup Code and the
locally managed pending Link. Import accepts the original **protected
file path**, rather than echoing a pasted secret, and also requires
a separate `YES` after reviewing the endpoints and profile.
Both paths delegate to the same CLI and canonical Engine, and creating
a local pending Link never claims bilateral connectivity.

## Initial setup

The following uses *documentation-only* endpoint values; replace
real addresses, private point-to-point addresses and chosen sources.

**On A**, choose local Source candidates separately:

~~~bash
sudo install -d -m 0700 /root/stl/spoof
sudo sh -c 'printf "%s\n" "198.18.0.11" "198.18.0.99" > /root/stl/spoof/sources.txt'
sudo chmod 0600 /root/stl/spoof/sources.txt
~~~

Create one pending Link (A need **not** wait for B or a live connection):

~~~bash
sudo stl link create-spoof \
  --creator 192.0.2.10:42001 \
  --recipient 198.51.100.20:42002 \
  --creator-private 10.245.62.1 \
  --recipient-private 10.245.62.2 \
  --outer auto \
  --creator-alts 192.0.2.11:42011 \
  --recipient-alts 198.51.100.21:42012 \
  --mtu auto \
  --sources /root/stl/spoof/sources.txt \
  --output /root/stl/spoof/setup.code --json
~~~

To constrain both sides to one carrier, specify `--outer icmp` (or
another supported name) instead of `auto`. To test **asymmetric**
manual directions with the same offline Code, use `--outer auto`
and `--tx-outer udp` on A; when B imports, pass
`--tx-outer icmp`. The local overrides are stored in separate
protected Link configs, not transferred as peer private keys.
For an interrupted `resume-spoof`, repeat the same `--tx-outer`
value used on the original side so original immutable topology
is preserved.

The output contains `link_id`, `provisioned=true`,
`peer_connected=false`, and the **path** of the private Setup Code.
It never prints the secret by default. A provisioned Link remains
pending until the peers authenticate *and* confirm bilateral delivery.
Protect the `setup.code` file as a credential. Deliver the exact
file from A to B **once**, using the operator's separately trusted
secure transfer mechanism. No STL network listener is required for
this offline handoff; do not post the Code into chat, Issues or logs.

**On B**, independently create B's own Source inventory. It can have
completely different addresses, order and count:

~~~bash
sudo install -d -m 0700 /root/stl/spoof
sudo sh -c 'printf "%s\n" "198.18.0.12" > /root/stl/spoof/sources.txt'
sudo chmod 0600 /root/stl/spoof/sources.txt
sudo stl link import-spoof \
  --setup /root/stl/spoof/setup.code \
  --mtu auto \
  --sources /root/stl/spoof/sources.txt --json
~~~

B generates its private identity **on B**. The Code transports no
private identity from either peer. After the first Noise-authenticated
B enrollment, A stores B's public key through the canonical Engine
State locks; a later unrelated B cannot silently rebind the Link.

Use these on either endpoint:

~~~bash
sudo stl link status LINK_ID --json
sudo stl link spoof-status LINK_ID --json
sudo stl link diagnose LINK_ID --json
~~~

Inspect **three different facts** rather than one vague `OK`:
`managed_helper_ready` (local managed TUN/route/process),
`authenticated` (valid cryptographic session) and
`bilateral_confirmed` (both sides actually exchanged authenticated
control datagrams). These do **not** prove that your application is
reachable: use an actual private ICMP/TCP/UDP test when needed.
`link diagnose` is explicitly invoked traffic-generating private
ICMP quality measurement; it does not prove outer-path PMTU.

## Recovery and retirement

Editing a Link's local Source file in place causes the original helper
to re-read it and rediscover candidate paths. A missing/invalid/empty
file must show no working path **without deleting the committed Link**.
If the peer later becomes reachable again, the same Link reconnects
without transferring a second Code. The canonical
`simple-tun-link-restore.service` recreates the original managed Link
after host restart/reboot. **When replacing the installed `stl` binary**,
stop or restart the *exact Link-owned Spoof helper services* under a
controlled maintenance window, so no old process retains a deleted
executable inode. Do not bypass executable identity checks to keep an
orphan helper alive; reboot/Restore also recreates original helpers.
Avoid changing protected topology, material,
addresses or the chosen outer protocol behind its back: those require
a separately created Link, not ad-hoc runtime mutation.

To permanently retire a particular Link:

~~~bash
sudo stl link remove LINK_ID --confirm LINK_ID --json
~~~

This locally removes only verified original resources, deletes the
matching protected identity after committed removal and reserves the
original Link ID permanently. Remove must work without the peer online.
Its fully retired original-identity receipt is intentionally preserved in
State as a permanent ID reservation; this does **not** prevent a normal
read-only `stl maintenance pre-uninstall --json` success when no Links or
other obligations remain. An **unfinished** Spoof retirement or a retained
`rp_filter` host-policy claim/journal blocks Uninstall until its original
STL recovery is completed. Inspect the reported reason and use the exact
`retire-spoof` or `stl link restore --all` reconciliation as applicable;
do not delete State records or edit sysctls to force Uninstall. The
confidential **operator-owned Setup Code file** is external to
STL's per-Link protected material: remove your original transferred
file from its trusted storage separately when you no longer need it.
Re-issue a fresh Link/Code if an unbound Code might have been exposed.
Never overwrite a Code file during idempotent retry; use
`resume-spoof --setup ORIGINAL_FILE --sources ORIGINAL_FILE_PATH`
(and the original `--tx-outer`, local `--mtu`,
`--discovery-pps`, `--background-pps`, `--manage-ingress` and
`--device` options, if used) on A if an earlier provision
attempt was interrupted.

## Source inventory scale and discovery

Each endpoint reads its own literal IPv4 `sources.txt`. Duplicate addresses
are deduplicated and the remaining unique addresses are **not capped**.
An inventory of 50,000 addresses has been parsed and a complete
50,000-candidate discovery traversal has been unit-tested without skipping
or repeating an address before the pass completes.

Every confirmed **(Source IPv4, outer profile, explicitly approved real
destination IPv4:port)** combination is saved
in root-only `history.json` under the original Link's protected
directory; success history is not subject to a time-based expiry or
arbitrary number of repeated outages. The original Link retirement
removes that exact owned history with its credentials.

When an authenticated session is lost, STL first tries recent
historically successful **paths** in most-recent-first order, three
bounded attempts over the cache. This is just a scheduling preference,
**not** three maximum retries or three lifetime attempts. Missing
Sources in the current local `sources.txt` are not retried, but do
not erase historical evidence. An unchanged working path reconnects
quickly after transient interruptions or a host restart; if the cached
paths fail, STL immediately returns to exhaustive discovery.

Complete discovery is **Source × enabled outer profiles × paired real
destination endpoints**, rather than one randomly chosen profile/port
per address. Its priority ordering
interleaves IPv4 /24 and /16 ranges to find varied candidates early,
but a failed sampled Source NEVER blocks the rest of its prefix,
another profile, or a future complete pass. No Source/provider country,
ASN, ownership, prefix or file-size policy is inferred.

Source lists are re-read after local edits and the ordered traversal
is rebuilt only when the inventory changes, not on each resend. While
disconnected the local token-bucket scheduler defaults to about **64
authenticated route probes/second**, with short bounded bursts; the
operator can choose a validated positive rate with `--discovery-pps`.
While healthy, **background** testing defaults to approximately **6
packets/second**, separately tunable with `--background-pps`. Both
are local to each endpoint, not an agreed paired global rate. No
maximum Source count is imposed. For 50,000 Sources, eight profiles
and two explicitly configured destination endpoints, one complete
traversal contains **800,000 combinations**, and repeated healthy
background passes can take many hours. This is **not** a timeout or
source-disabling limit. Candidate selection interleaves /24 and /16
ranges; historical known paths are periodically re-probed and promoted
only after Noise-authenticated peer acknowledgements.

Each session sends small authenticated keepalive/quality probes.
The runtime reports approximate **RTT**, jitter, sample loss and
verified backup route counts. A new path must exhibit multiple
recent confirmed good samples and materially better quality before
hysteresis permits a change. Selected routes are not switched merely
because a local raw send returned success or an unverified packet
appeared at the receiver. When an authenticated peer has gone silent
for approximately eight seconds, recovery testing begins immediately
while the original session and historical routes stay available; after
a longer interval with no response a new authenticated handshake is
attempted using the **same** offline Link identity. Persistent outage
never deletes the Link; host/peer reboots can reconnect without new
Setup Codes.

`--mtu auto` uses an independent private TUN policy and probes
descending size profiles from 1280 down to 576 IPv4 bytes. Each size
requires **two** authenticated end-to-end replies to a `DF`-flagged
outer packet before the original exact-owned private TUN MTU is
adjusted by verified ifindex, with readback. This conservative set does
not claim maximum physical PMTU or anything from a failed send;
`--mtu N` permits explicit 576..65431 MTU but does not guarantee
delivery. The Link's generic managed-native MTU manager never takes
ownership of this per-Link Spoof helper TUN.

\`--manage-ingress --ingress-device eth0\` is an optional endpoint-local
policy, not part of the original peer Setup Code. The incoming NIC is
**independent** of the optional outgoing \`--device\`; actual post-DNAT
receive-bind IPv4 addresses must be assigned somewhere on the local host,
but need not be assigned on that same incoming NIC. A working privileged
\`iptables\` CLI is required only for managed ingress. With Auto it
creates narrowly matched Link-owned rules for UDP/TCP destination port,
ICMP Echo Reply, and the supported raw IPv4 protocol numbers. For
non-port-based raw protocols, only the exact local destination,
interface and protocol can be matched by IPv4 firewall rules; cryptographic
authentication remains the actual peer check. The exact private TUN
exception, when needed, is limited to the original Link's TUN
interface, authenticated peer private /32 source and local private /32
destination; it does not open the TUN for foreign sources or unrelated
private destinations. When a relevant direct INPUT drop is found,
required exceptions are inserted ahead of the applicable iptables
INPUT denial, independently inspected on Ensure/Restore, and removed
during owned Link retirement.
On permissive INPUT chains there are **zero** added firewall rules. This cannot
override a separate nftables drop hook or an ISP filter and **is not**
a blanket firewall-opening promise. The menu requires explicit consent; an unavailable prerequisite fails
with a clear diagnostic **before** Setup Code creation. With explicit
operator approval on a known host, full firewall disable may also be
used as a **temporary diagnostic last resort** after snapshotting active
rules/managers and arranging verified rollback. It is not performed
automatically by the Link lifecycle and is not a required networking
condition. A firewall-wide shutdown increases exposure of unrelated
services, and may not affect separate nftables, cloud ACL or anti-spoof
barriers. No firewall on production has been disabled by this candidate.

`stl link spoof-status LINK_ID --json` distinguishes
`selected_source`, `selected_profile`, `selected_destination`,
`selected_rtt_ms`, `selected_jitter_ms`, `selected_loss_percent`,
`verified_mtu`, `mtu_status`, `tunnel_mtu`, `unacked_probes`,
`scanned_probes`, `recent_working_paths`,
`recovery_stage` (`RETRY_PREVIOUSLY_WORKING` or
`EXHAUSTIVE_SOURCE_PROFILE_SCAN`), available/failed local receiver
formats, inventory count, profile index, Source scan position and
completed full passes. These counters indicate scheduled attempts,
not proof that unselected paths were delivered.

For efficient, predictable operator updates, write a fresh inventory
into a protected temporary file and **atomically rename** it over
the old Source file. Interrupted in-place file edits may temporarily
show an empty/incomplete inventory; STL preserves the Link and retries.

## Smart multi-route isolated acceptance (2026-11-22)

The isolated successor worktree `feature/262-smart-20261122` is
**not** a Stable release. Its task-owned Debian system guests are
`stl-spoof-262-smart-a` and `stl-spoof-262-smart-b`; the
four original persistent Links in `stl-spoof-262-a/b` were untouched.
A complete disposable Link was created with one protected Setup Code,
two IPv4:port receivers on each host, Auto outer profiles, explicit
endpoint-local scan rates and private TUN addresses. On the first
private-lab run, removing the task-owned primary real IPs made each
peer select the alternate real receiver and 3/3 authenticated private
ICMP replies passed **in each direction**, with exact Link cleanup.

In a separate isolated run, explicit per-destination host routes capped
the outgoing path MTU at **1200** bytes. Both endpoints independently
found and verified a `1100`-byte private TUN MTU from authenticated
DF delivery. Removing the primary real destinations preserved a
bilateral CONNECTED Link over asymmetric Auto profiles, private 3/3
ICMP each way, **two verified TCP connections / 524,288 bytes** and
**20 verified UDP datagrams** in EACH direction. All test-created IPs,
host routes, transient Link material and Setup Code were removed.
The lazy Source × eight-profile × two-destination unit test completed
**800,000 unique combinations** from 50,000 Sources, without early
repeat/omission. Benchmarking reported 64-combination batch time
on the tested CPU and does not prove public-provider network scan speed.

Firewall acceptance first found that isolated guests lacked
`iptables` and lacked direct Debian repository access. Prerequisites
were subsequently acquired from the authorized Debian mirror via the
development host and installed **only into task-owned guests**.
The first full real firewall end-to-end run, with explicit independent
pre-existing DROP rules on the exact test receivers, passed: 14
Link-owned INPUT ACCEPT rules were installed on each guest, the
encrypted Link carried authenticated bilateral private ICMP/TCP/UDP
even after primary receiver deletion, and all Link-owned ACCEPT
rules were absent after removal. A new policy-specific **unit test**
verifies that an already-permissive INPUT chain needs **no** rules;
a new exact-binary, two-host permissive-policy E2E was pending **at
that historical checkpoint**. It was subsequently completed successfully
on native Debian 13 KVM guests (job \`1795318095403856835\`, exit 0).
The then-blocked binary replacement was resolved by using the authorized
task-owned private VM operation. Later PR #263 remediation testing verified
an independent nftables INPUT drop hook and actual lab DNAT (details below).
Public WAN, provider ACL, ISP anti-spoofing and physically distinct real
server networks remain unverified: no private-lab test proves them.

## Scope and validated evidence

In isolated Debian Incus system containers
`stl-spoof-262-a` / `stl-spoof-262-b` on a private no-NAT bridge
(no public forged packets), managed **UDP and unsolicited ICMP Echo
Reply** outer profiles were both tested with Noise-authenticated
end-to-end TUN traffic. The managed helper ran under original
per-Link systemd supervision, and the same Link recovered without
re-pairing after interruptions.

- Original UDP profile: private bidirectional ICMP, SHA-256 verified
  TCP and content-verified UDP.
- Corrected unsolicited ICMP Echo Reply profile: managed TUN
  `CONNECTED`, bilateral private ICMP, **10 MiB SHA-256 verified
  TCP in each direction** and **200 payload-verified UDP datagrams
  in each direction** on the previous datapath-identical candidate.
- The committed `3be1e65` datapath candidate was rebuilt, installed
  with verified root ownership and tested in both guests. Both profiles
  reconnected after canonical `RestoreAll`, and private ICMP,
  **2 MiB SHA-256 verified TCP** and **60 UDP datagrams** passed
  for each profile in the exact-candidate tests.
- Both profiles independently chose another local Source after an
  exact task-only filter dropped the previously working Source while
  it remained listed. They later automatically recovered after a
  bilateral full UDP+ICMP outage without new identity or Code.
- The profiles remained independent when just outer UDP or just
  outer ICMP was dropped; the other managed private Link remained
  authenticated and carried traffic in each direction.
- Test-only 12 ms mean plus jitter, 1% actual packet loss and 4%
  reordering on both guest interfaces: SHA-256 verified TCP was
  transferred over both carriers with no corruption.
- Two simultaneously managed Links maintained distinct identities;
  a third pending Link survived reboot before B's Import, was
  authenticated with its own offline Code, then removed on both
  endpoints with only its owned TUN/service/material retired.
  The original active Links were unaffected.
- `go vet ./...`, `go test ./...` and targeted race tests passed
  for the predecessor candidate, with exact-head CI for
  `fb2992a` subsequently succeeding in all five workflows.

**Additional candidate test campaign (after the original UDP/ICMP checks):**
The task-owned isolated Debian A/B guests received a newly built,
root-owned candidate. An `auto` Link with a single protected offline
Code independently selected `ipip` on both sides, passed encrypted
private ICMP 2/2 bidirectionally, and preserved learned history in
a protected 0600 per-Link file.

A separate isolated test campaign created, imported and tested
**all eight individual outer packet profiles** (UDP, unsolicited ICMP
Echo Reply, TCP-looking, GRE, IPIP, bare/echo-shaped protocol 58 and
L2TPv3-style 115). Each selected profile achieved Noise-authenticated
`CONNECTED` status and 2/2 private ICMP in both directions.
An expanded full-L3 campaign subsequently transferred **1,048,576 verified
TCP bytes and 50 verified UDP datagrams in each direction for EACH of
the eight outer profiles** (plus private ICMP in both directions). Both
client and server payload verification passed; the final task-owned
script reported `ALL_RAW_PROFILES_AUTHENTICATED_ICMP_TCP_UDP_BIDIRECTIONAL_OK`.
Each test-only Link was subsequently removed on both endpoints,
including its protected identity and history.

An Auto-receiving Link with locally pinned **A→B UDP and B→A ICMP**
achieved both independent outgoing selections and 3/3 private ICMP
without another Code; it later carried an **8 MiB verified TCP**
transfer and **250 verified UDP datagrams** A→B.
The task-only B-side filter blocking A's previous UDP Source `.11`
triggered genuine autonomous replacement with Source `.99` while B
continued on ICMP. When the operator's A-side file was changed to
drop `.99` (temporarily and atomically), the original Link recovered
through `.11` again, retained both previously authenticated historical
paths, and resumed private traffic. The original two-Source file was
restored and all test-only filter rules removed.

Another Auto/Auto Link originally selected IPIP/4 on both sides.
Blocking outer IPIP/4 inbound on task-owned B forced a same-Link
transport rediscovery; A selected L2TPv3-style/115 and B selected
bare protocol 58, and private ICMP again passed 3/3 each direction.
The task-only filter was then deleted.
After deploying the newest development binary with verified owner
root:root mode 0755 in both guests, canonical Restore recovered
four persistent Links. Restarting B's Incus system container also
recovered all four through the boot-triggered
`simple-tun-link-restore.service`; local and historical Source/profile
state remained private and reused. A manual Restore started immediately
while the container was still booting briefly reported
`observation_unverified` (inspection raced startup), but the boot
Restore reported success, the resulting services all became active,
a later manual Restore reported `restored 4 link(s)`, and bilateral
private ICMP passed. This is isolated container reboot evidence,
not an independent physical OS/kernel restart.

These are isolated Linux-container results, NOT WAN/provider
interoperability evidence.

**Large-inventory evidence:** a complete 50,000-address traversal
was unit-tested, and both managed UDP and ICMP Links remained authenticated
and successfully passed private ICMP with a 50,000-address Source file
loaded on A in the task-owned private laboratory. That file was restored
to its original two addresses after the test. The large inventory was
NOT exhaustively transmitted over the network; no real-provider
forged-source delivery is claimed.

**Not established by the container tests alone:** independent kernels,
public WAN/provider filtering, genuine outer TCP establishment, all
firewall/routing combinations or review/release readiness. The separate
VM campaign below provides additional kernel-independent evidence but
does not establish public-provider reachability.

## Independent-kernel KVM acceptance (2026-11-22)

The exact smart candidate
`900af8dda7a46f91dae5eafeb1e95e136425f44c` was built and tested
on **two separately booted Debian 13 KVM virtual machines**, not Linux
containers sharing the host kernel. The task-owned AI Test Server Incus
project is `stl262-spoof-private`, with guests `stl262-native-a/b`.
Both used Linux kernel `6.12.117+deb13-amd64`, real `enp5s0` NICs,
systemd and TUN. Their private bridge `stl262private` uses
`10.246.62.0/24`, with NAT and IPv4 forwarding **disabled**;
no public forged-source packets were transmitted. Binary SHA256 on
both guests:
`50c4bbb28963bfe39bbe1ce99b88c14dda2a428dfaeda7877dc019e3c5f5cc2f`.

The reproducible, task-specific runner
[`scripts/tests/spoof-native-vm-matrix-lab.sh`](../scripts/tests/spoof-native-vm-matrix-lab.sh)
uses these exact owned VM names and private endpoints; it is **not**
a general-purpose host/firewall provisioning script. On the
configured isolated Test Server, all **eight raw outer profiles**
(`udp`, `icmp`, TCP-RST-shaped `tcp`, `gre`, `ipip`,
`proto58`, `proto58-echo` and `l2tpv3`-shaped) individually
completed one offline-Code Create/Import, bilateral authenticated
`CONNECTED`, private ICMP 2/2 in both directions, and independently
SHA-256-verified private TCP 262,144 bytes and verified UDP 16
datagrams in **each direction**. Each temporary Link was removed on
both VM peers with no loss of the separate original Link. Test Server
root job `1795316401334192793` exited 0 with final marker
`ALL_EIGHT_PROFILES_NATIVE_VM_ENCRYPTED_ICMP_TCP_UDP_BIDIRECTIONAL_PASS`.
These are STL-owned raw packet shapes, **not** native interoperation
with arbitrary TCP, GRE or L2TPv3 peers.

Additional same-VM scenarios: A committed a pending Link before B
imported, without an online peer; the same confidential Code later
produced independently chosen outer routes and bilateral private
ICMP/TCP/UDP. A one-sided B VM shutdown changed A to
`RECONNECTING` with bilateral confirmation false; B's systemd
boot Restore recovered the original Link, protected 0600 history and
private traffic without a new Code. Independently rotating A's Source
file between previously authenticated candidates recovered the same
Link. Temporarily removing A's entire Source file accurately reported
`NO_WORKING_PATH`, zero candidate Sources and bilateral=false; restoring
the protected file reconnected both sides automatically, with private
ICMP 3/3 each direction (Test Server job `1795316613771542919`, exit 0).
Constraining A's underlay MTU to 1150 and B's to 1250 led to
different **authenticated DF-verified** private MTUs of 1024 and
1100 (including verified TUN kernel readback): 900-byte private
ICMP 4/4 each way, 2 MiB verified TCP each way, and 80 UDP
datagrams each way succeeded, followed by verified exact route cleanup.
Two concurrent Links also carried verified ICMP/TCP/UDP independently;
removing the second on B and A did not affect the first. A task-only
one-way blackhole of the actual remote destination correctly led
both peers to `RECONNECTING` / `bilateral_confirmed=false`;
removing the scoped block automatically restored bilateral private
ICMP. Finally, **both independently booted VMs were stopped and
started**, and both boot Restore services completed successfully on
the current binary, returning to bilateral CONNECTED with 3/3
private ICMP each way and unchanged 16 historical routes.

A real duplicate receiver-port test revealed that an earlier
candidate could reject a conflicting Link but leave uncommitted
per-Link protected material. The fix on `900af8d` defers only
Spoof protected credential staging until **after** final canonical
locked resource-collision admission. The same VM conflict was
reproduced after the fix: the conflicting Link was refused,
the existing Link stayed active and **no orphan material directory**
was created. Exact test-only leftovers from the original failed
experiment were retired after confirming ownership and no committed
or live Link. A further regression recognizes an iptables
`ESTABLISHED,RELATED` allowance as insufficient to admit an
unsolicited incoming Spoof handshake under default DROP.
On this candidate the full Go test suite, `go vet` and relevant
app/Spoof race tests all passed on Dev Server (job
`1795316244157195973`, exit 0).

**Native-VM firewall and fault acceptance after the previous checkpoint
(2026-11-22):** On the same two task-owned, independently booted Debian
13 VMs, using the exact pre-fix `900af8d` binary, managed ingress on a
permissive `-P INPUT ACCEPT` installed **zero** Link-owned rules while
bilateral authenticated private ICMP, 524,288 verified TCP bytes in each
direction, and 20 verified UDP datagrams in each direction passed;
exact Link removal returned to the same empty INPUT chain (Test Server
job `1795317457156824820`, exit 0). With independently injected
per-receiver UDP DROP rules, actual DROP counters incremented; STL
inserted exactly one original Link-owned exception on each guest before
the DROP, then the same private payload tests passed. All test-only
DROP/ACCEPT rules and Link material were verified absent afterward
(job `1795317525911905889`, exit 0).

A more representative stateful **default `INPUT DROP` with a
pre-existing `ESTABLISHED,RELATED` allow** exposed a previously
unidentified product bug: the managed outer UDP exception admitted
the encrypted handshake, so both sides reported `CONNECTED`, but B's
kernel silently dropped decrypted incoming peer packets from the
original per-Link TUN. Actual private A-to-B ICMP lost 3/3 packets.
The causal reproduction on the original isolated Link showed the
private ping failing with TUN INPUT blocked, passing 3/3 after adding
an exact `-i <Link TUN> -s <peer /32> -d <local /32> -j ACCEPT`,
and failing again after removing just that temporary rule; all
original policy/traffic were restored (job `1795317701386592920`,
exit 0). **Fix `0ef641b`** extends opt-in managed ingress with
one independent, exact-owned private-TUN rule **only when the same
iptables INPUT policy really blocks it**. This does not change
default policy, skip authentication, permit other TUN peers or
affect any independent Link. Unit tests cover permissive, direct
DROP, existing exact accept, stateful allowance, outer vs private
direction, and narrow protocol/port rules. With the rebuilt fix
(SHA256 `aaab81ec79d8c6d91f416bed66ce27c41b079cec263954be5aba094a33e480ee`),
the formerly failing native-VM test verified a real default-DROP
counter, exactly **two** required Link-owned rules on blocked B
(one outer and one private TUN, with the foreign stateful rule retained),
bilateral private ICMP 3/3 each direction, 524,288 verified TCP bytes
and 20 UDP datagrams in each direction, and complete exact rollback
(Test Server job `1795317985490694638`, exit 0 and
`STATEFUL_DROP_VM_EXACT_ROLLBACK_RC=0`). The **same fixed binary**
was independently re-tested on two permissive `INPUT ACCEPT` VMs:
zero added INPUT rules, bilateral private ICMP 3/3, 524,288 verified
TCP bytes and 20 UDP datagrams in each direction, and exact
Link/material removal (job `1795318095403856835`, exit 0,
`VM_PERMISSIVE_EXACT_CLEANUP_EXIT=0`). Neither VM needed a
global firewall disable. This fixed-commit runtime acceptance does not
by itself constitute exact-final-HEAD CI or independent PR review.

Further negative-path checks on the pre-fix private VM setup:
temporarily withholding A's protected Source file reported
`NO_WORKING_PATH`, then recovered the same bilateral Link automatically
after restoring the file (job `1795316613771542919`, exit 0);
forced asymmetric reverse-path filtering on B made the Link honestly
`RECONNECTING` before restoring its original `rp_filter=2`,
original routes and the bilateral private path (job
`1795316804393996134`, exit 0); a full bilateral underlay outage
for 65 seconds retained 16 historical paths, never reported false
bilateral CONNECTED, and recovered automatically when both task-only
blackhole routes were removed (job `1795316901709449135`,
exit 0). Exact task-only netem at VM B tested 12 ms delay
(3 ms jitter), 1% loss, 4% reordering, 1% duplication and 25 Mbit/s
limit: packet-drop counters recorded 20 actual drops and 2 MiB of
SHA256-verified TCP data in **each direction** passed; task-owned
root netem was removed and the original kernel mq/fq_codel qdisc
independently verified restored (job `1795317329185500594`, exit 0).

**Still unverified:** separate native nftables hooks/managers other
than inspected iptables-nft, multi-distro and ARM64 native Spoof VM,
real ISP/provider anti-spoof filtering, public WAN/NAT diversity, and
any production-site Firewall effect. Scoped guest permission tests do
not imply production authorization or a guarantee of provider
reachability. PR #263 requires exact final-HEAD GitHub CI, independent
strict read-only review, and explicit Owner approval for any
Merge/Release; public/production testing needs its own scoped
authorization.

## PR #263 remediation acceptance — native KVM, 2026-11-22

The unreleased remediation code at commit `70d8061` was independently
compiled from the PR branch on the Test Server, then exercised only
on the two dedicated `stl262-spoof-private` Debian 13 KVM guests.
The base bridge had NAT disabled; test-specific NAT and secondary
bridges/Interfaces were installed with exact rollback. No public
forged-source experiments or production/Stable modifications occurred.

- **R1 / crash-safe retirement:** An opt-in root test in a real VM
  reproduced partial protected-file removal after quarantine rename,
  then recovered the exact original receipt. The repeated retry was
  idempotent. A foreign file was preserved and `Retired=true`
  refused until a supported exact cleanup could complete.
  `STL_SPOOF_PRIVILEGED_ACCEPTANCE=1` explicitly gates the test.
- **R2 / real NAT and interfaces:** Under `iptables-nft` INPUT DROP,
  operator-controlled PREROUTING DNAT translated an advertised but
  nonlocal `10.246.62.250:48502` to the locally assigned receiver
  `10.246.62.245:49502`. The second advertised destination used
  a different local port and replaced the primary after it was
  blocked. Verified private bilateral ICMP, 262,144 TCP bytes and
  16 UDP datagrams each way passed, followed by exact rollback
  (job `1795321481132322286`, exit 0).
  A separate two-bridge/dual-NIC test proved ingress/egress
  `enp5s0`/`enp6s0` can differ while authenticated
  private IPv4 works (job `1795321874955966865`, exit 0).
  Engine resource claims were separately corrected to reserve
  actual post-DNAT Bind ports rather than advertised ports.
- **R3 / real private datapath:** The private application ICMP echo
  probe reported `VERIFIED_ICMP` while traffic flowed;
  an exact private INPUT drop preserved authenticated outer
  `CONNECTED` but reported `ICMP_PROBE_FAILED`.
  Removing it restored private verification automatically
  (job `1795321388733641146`, exit 0). An **independent
  native nftables INPUT hook** reproduced the same distinction,
  and its removal restored the same Link (job
  `1795321874955966865`, exit 0).
  ICMP failure is not a claim that TCP or UDP also failed.
- **Linux rp_filter:** Strict=1 succeeded with a valid reverse
  path; an isolated dummy NIC introduced a real asymmetric reverse
  route and strict filtering blocked the original Source packets.
  Changing only the incoming VM NIC to loose=2 restored bilateral
  private IPv4 on the SAME Link. Exact route/sysctl/Link rollback
  was verified (job `1795321738446299300`, exit 0).
  STL inspects effective max(all,interface) but does not silently
  change policy for other services on a shared NIC.
- **All eight raw outer Profiles:** Every one of
  UDP, ICMP, TCP-looking, GRE-shaped, IPIP, protocol 58 bare,
  protocol 58 echo and L2TPv3-style completed bilateral
  authenticated private IPv4 echo plus genuine two-way private
  TCP (262,144 bytes each direction) and UDP (16 datagrams each
  direction), with exact Link/material cleanup after every Profile
  (job `1795321954175288334`, exit 0).
- **Broad Go gates:** `go test -p 2 ./...`, `go vet ./...`,
  relevant `go test -race`, and `git diff --check`
  passed on the remediation code at `70d8061`.

The native tests prove the stated **private** scenarios, not public
WAN/ISP reachability, every distro or all provider ACLs. Exact-HEAD
**full guest restart/reboot was not rerun**: the required connection-risk
approval was not available for that operation. Previous-commit reboot
evidence is not misrepresented as new-code validation. Dedicated
iptables-legacy and additional Ubuntu/ARM64 guest acceptance were
not completed on this code; nftables + iptables-nft were tested.
Exact final PR HEAD CI, independent `APPROVE`, Merge, Release
and any production change remain separate mandatory gates.
