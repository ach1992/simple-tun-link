# Spoof Direct TUN Carrier — operator guide (Issue #262)

> **Availability and evidence:** Introduced in official Stable `v0.1.34`;
> `v0.1.33` and earlier do not contain this Carrier. The implementation
> passed exact-source independent reviews and isolated native-KVM acceptance.
> A bounded public-WAN test on official v0.1.35 also verified fresh pairing,
> private ICMP/TCP/UDP and same-Link recovery with a forged Source in one
> direction and a real Source in the return direction. This is evidence for
> that tested path, not every Source/provider combination. See
> [verification boundaries](#verification-boundaries-and-historical-evidence)
> and [Issue #262](https://github.com/ach1992/simple-tun-link/issues/262).

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

A host default route is not required when an explicit route reaches the real
outer peer endpoint. While the owned TUN is being configured, the private
peer route appears after the interface and address. Its temporary absence
is pending local readiness; unrelated command and parsing failures still
remain errors.

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
ICMP quality measurement **only after** a fresh, verified authenticated
bilateral path exists; it does not prove outer-path PMTU. Until then,
per-Link CLI, guided menu Check connection and `diagnose --all` report
`spoof_bilateral_unconfirmed` with a read-only `spoof-status` next action,
**not** an unexplained generic diagnostic failure or a fabricated ping.
Unverified original systemd helper/TUN/route ownership is separately
reported as `spoof_local_helper_unverified`. If a private ICMP measurement
fails after authentication, the separate result is
`spoof_private_icmp_unverified`; neither that result nor an unconfirmed
carrier is silently promoted to a connected private application path.

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
barriers. The Link lifecycle never disables the host firewall globally.

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

## Verification boundaries and historical evidence

**Shipped capability:** Official Stable `v0.1.34+` includes the managed,
encrypted Spoof Direct TUN. Both endpoints maintain independent Source
IPv4 inventories and authenticated outer-path histories; per-Link
recovery and ownership are handled by the common STL Engine.

**Actual evidence:** Two isolated Linux containers and two
independent-kernel Debian 13 guests verified bilateral private
ICMP/TCP/UDP for the supported eight outer packet formats, as well as
NAT, iptables/nftables, authenticated MTU/DF, same-Link recovery
and owner-scoped retirement. The independently reviewed source and
immutable `v0.1.34` package passed their separate QA gates. The
[canonical acceptance Issue #262](https://github.com/ach1992/simple-tun-link/issues/262)
holds the environment-specific test receipts and original evidence
comments; its [v0.1.34 delivery receipt](https://github.com/ach1992/simple-tun-link/issues/262#issuecomment-7084368793)
records exact source and artifact identity. Detailed historical
campaigns are recoverable from that Issue and Git history.

**Real-WAN evidence:** The
[2026-11-23 physical acceptance receipt](https://github.com/ach1992/simple-tun-link/issues/262#issuecomment-7090632162)
records official v0.1.35 on an authorized Iran/UK server pair. A nonlocal
Source sent by the Iran host arrived unchanged at the UK host, and Auto
formed a bidirectional encrypted Link using a real-Source return path.
Fresh one-Code pairing, same-Link Source rotation, managed-helper restart,
1280-byte private DF ping, 2 MiB SHA256-verified TCP transfers and
100/100 UDP datagrams in each direction passed. The test did not alter
global firewall, default routes or reverse-path filtering.

The [strict follow-up matrix](https://github.com/ach1992/simple-tun-link/issues/262#issuecomment-7090866179)
excluded both endpoint real addresses from both Source files and used 23
other operator-provided addresses per side. All 368 directional
Source/profile combinations were captured leaving their hosts: every
Iran-origin Source reached the UK in each of the eight profiles, while
none of the UK-origin combinations reached Iran. The UK emitted 7,957
current-Link handshake replies and Iran received none. Exact Link ID and
outer-header decoding found zero frames using either endpoint's real
Source or an address outside the configured inventories.

Strict bilateral-forged pairing therefore did not complete on that pair.
These captures distinguish host emission from arrival but do not identify
the dropping hop or establish a rule for every other Source or provider.
The earlier private-traffic success remains the asymmetric forged/real
case. The two directions can use different Sources and profiles; a
working forged Source in one direction does not require a forged Source
in the other.

**Still unverified:** Other provider/Source combinations, physical
translated-NAT and full host-reboot behavior remain separate field
qualifications. The large-inventory cursor test is not proof of initial
two-peer pairing when only sparse candidates work, and same-tuple path-MTU
changes need distinct validation. Short data transfers do not establish a
throughput SLA or long-duration stability. No software release authorizes
arbitrary third-party-source traffic, host-wide firewall shutdowns or
production deployment.
