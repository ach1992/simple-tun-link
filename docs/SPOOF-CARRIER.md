# Spoof Direct TUN Carrier — development candidate (Issue #262)

> **Release gate:** This document describes the candidate on the isolated
> `feature/262-spoof-carrier` branch. It is NOT a claim that current Stable
> `v0.1.33` has Spoof, or that public Internet anti-spoofing is bypassable.
> Merge/release require independent review and the full Issue #262 acceptance.

## What is carried vs how the peers reach each other

Each Link is a managed, Linux-native private IPv4 **TUN /32 to /32** path,
with **Noise XKpsk0 + ChaChaPoly encryption and authenticated identities**.
The carrier's outer real destination always remains the configured peer
IPv4 endpoint. The **outer source** is independently selected from the
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
source/profile neither reissues keys nor constructs an additional Link
or manager. Actual authenticated bilateral delivery is required before
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
adopt foreign services, delete foreign network state, or write firewall
or global network policies merely to make a test pass.

The numeric `PORT` in `--creator/--recipient` is the UDP/TCP
destination receive port where applicable; for ICMP it is an Echo ID,
for L2TPv3-style data it participates in the session identifier, and
for other raw profiles it is a per-Link receive discriminator.
The canonical Engine reserves the actual resources for the selected
profile(s); `auto` reserves all necessary profile namespaces.
Keep endpoint identifiers nonzero and avoid collisions with other
services/Links.

## Interactive workflow

In an interactive terminal, run `sudo stl menu`, then
**Create tunnel → 10. Spoof / Direct TUN** on A or
**Import Setup Link → 6. Spoof / Direct TUN** on B.
Create offers an exact Source file **Recheck**, Auto or a manually fixed
raw outer profile, an optional local outgoing override in Auto mode,
review of both real endpoints and private addresses, and requires
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
The confidential **operator-owned Setup Code file** is external to
STL's per-Link protected material: remove your original transferred
file from its trusted storage separately when you no longer need it.
Re-issue a fresh Link/Code if an unbound Code might have been exposed.
Never overwrite a Code file during idempotent retry; use
`resume-spoof --setup ORIGINAL_FILE --sources ORIGINAL_FILE_PATH`
(and the original `--tx-outer`, if any) on A if an earlier provision
attempt was interrupted.

## Source inventory scale and discovery

Each endpoint reads its own literal IPv4 `sources.txt`. Duplicate addresses
are deduplicated and the remaining unique addresses are **not capped**.
An inventory of 50,000 addresses has been parsed and a complete
50,000-candidate discovery traversal has been unit-tested without skipping
or repeating an address before the pass completes.

Every confirmed **(Source IPv4, outer profile)** combination is saved
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

Complete discovery is **Source × enabled outer profiles** rather than
just one randomly chosen profile per address. Its priority ordering
interleaves IPv4 /24 and /16 ranges to find varied candidates early,
but a failed sampled Source NEVER blocks the rest of its prefix,
another profile, or a future complete pass. No Source/provider country,
ASN, ownership, prefix or file-size policy is inferred.

Source lists are re-read after local edits and the ordered traversal
is rebuilt only when the inventory changes, not before each resend.
The helper schedules a bounded batch of up to 16 combinations per
roughly 700 ms tick per Link, with short packet spacing. A list
of 50,000 Sources with all eight formats means 400,000 different
combinations per complete pass. This can take hours when nothing
works and must not be misreported as an exhausted one-time failure:
the helper keeps cycling and can reconnect without a new Code.
An actual packet sent by the local kernel is **not** a success claim;
the peer must cryptographically confirm the received Source/profile.

`stl link spoof-status LINK_ID --json` distinguishes
`selected_source`, `selected_profile`, `recent_working_paths`,
`recovery_stage` (`RETRY_PREVIOUSLY_WORKING` or
`EXHAUSTIVE_SOURCE_PROFILE_SCAN`), available/failed local receiver
formats, inventory count, profile index, Source scan position and
completed full passes. These counters indicate scheduled attempts,
not proof that unselected paths were delivered.

For efficient, predictable operator updates, write a fresh inventory
into a protected temporary file and **atomically rename** it over
the old Source file. Interrupted in-place file edits may temporarily
show an empty/incomplete inventory; STL preserves the Link and retries.

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

**Not established by those tests:** a separate physical/VM kernel,
real WAN/provider filtering, public Internet source spoofing,
ordinary outer TCP establishment, all route/rp_filter/firewall combinations,
large-scale performance beyond tested netem transfers, or
review/merge/release. Container reboot is not a full independent
hardware/kernel reboot. These remain tracked in
[Issue #262](https://github.com/ach1992/simple-tun-link/issues/262).
