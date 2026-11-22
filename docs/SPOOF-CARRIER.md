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

Do not confuse:

| Layer | Tested transport | Meaning |
| --- | --- | --- |
| **Inside** the Link | ICMP / TCP / UDP | Ordinary private IPv4 application traffic carried encrypted by the same Link |
| **Outside**, profile `udp` | Raw IPv4 UDP | Authenticated frames to the *real peer* UDP receive port, with the selected Source IPv4 |
| **Outside**, profile `icmp` | Raw ICMPv4 unsolicited Echo Reply (no kernel reflexive reply to forged Source) | Authenticated frames to the *real peer* with the selected Source IPv4; per-Link ICMP receive identifier |
| **Outside**, TCP | **Not supported for this Spoof carrier** | TCP's three-way handshake ordinarily returns to the claimed source, not automatically to the actual sender. Emitting a forged SYN is not evidence of an established TCP data connection |

Both `udp` and `icmp` are **explicit, immutable per-Link profiles**.
There is no implicit cross-protocol carrier hopping or unproven fallback.
The creator selects a profile, the **single confidential offline Code**
pins it for the recipient, and both sides use that same profile.
Multiple independent Links with different profiles can coexist.
Protocol names do not imply traversal of arbitrary firewalls, NAT,
provider anti-spoofing, non-default routing or IPv4 restrictions.

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

For ICMP the numeric `PORT` in `--creator/--recipient` is a distinct
16-bit **ICMP Echo identifier**, not a UDP/TCP listener. Operators must
choose nonzero identifiers without colliding with other managed Spoof ICMP
Links. UDP uses ordinary UDP receive ports.

## Interactive workflow

In an interactive terminal, run `sudo stl menu`, then
**Create tunnel → 10. Spoof / Direct TUN** on A or
**Import Setup Link → 6. Spoof / Direct TUN** on B.
Create offers an exact Source file **Recheck**, a choice of UDP or ICMP,
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
  --outer udp \
  --sources /root/stl/spoof/sources.txt \
  --output /root/stl/spoof/setup.code --json
~~~

For an ICMP-only candidate, choose `--outer icmp`, a distinct Link
address pair and endpoint identifiers; keep the `--outer` choice
identical across the two peers via the Code.

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
on A if an earlier provision attempt was interrupted.

## Scope and validated evidence

In isolated Debian Incus system containers
`stl-spoof-262-a` / `stl-spoof-262-b` on a private no-NAT bridge
(no public forged packets), the current development branch has
**demonstrated on the earlier Echo Request ICMP candidate**, except
where noted. The release candidate now uses **unsolicited ICMP Echo Reply**
to prevent automatic kernel reflection toward the forged Source. Its
wire-format unit test passes but **this specific safer ICMP framing has
NOT yet been re-tested in the two containers**, because the final
isolated deployment was blocked by a tool execution control. No release
or full acceptance claim is made for the revised ICMP profile.

- UDP profile: one offline A-to-B handoff, A pending before B import,
  Noise authentication, bidirectional ICMP, SHA-256-verified TCP and
  payload-verified UDP; original Link recovered after source inventory
  rotation, peer service restart and both guest reboots
- Previous ICMP Echo **Request** profile: forged-source packet delivery
  in each direction, then full managed Noise/TUN `CONNECTED`, private
  bidirectional ICMP, at least 10 MiB digest-verified TCP and
  200 payload-verified UDP datagrams in **each direction**. **Do not attribute**
  this evidence to the new safer Echo Reply framing until re-tested.
- Both profiles automatically selected a new outgoing Source from
  the unchanged local file after B's lab network dropped the previous
  Source, and both reconnected after all outer UDP+ICMP paths were
  deliberately dropped then restored
- The profiles remained independent when only outer UDP or only outer
  ICMP was blocked; under per-guest network emulation (12 ms + jitter,
  1% loss, 4% reorder), TCP bytes were SHA256 verified over both
  encrypted Links despite actual kernel packet drops
- Two simultaneously active Links with distinct resources; removing
  one preserved the other; the retired ID was rejected on attempted
  re-import without redeploying the protected material
- Complete bilateral UDP+ICMP outage, clear symptoms, independent
  reauthentication/recovery of both without re-pair after netns firewall
  rules were removed; no test firewall tables remained
- Independent outer UDP vs outer ICMP path tests: dropping only the
  other profile did not interrupt the surviving encrypted Link
- A previously working Source remaining in both candidates, but
  failing at the peer: both Links rediscovered a different local Source
  without editing the file, regenerating identities or re-pairing
- SIGKILL original helper, systemd automatic restart and reconnection
  of the same Link (transient expected downtime)
- Test-only 12 ms mean plus jitter, 1% loss and 4% reordering on
  both container egress interfaces; 8 MiB SHA-256-verified private
  TCP transferred across UDP and ICMP, with observed link-layer drops
- DF IPv4 private ICMP packet sized 1228 bytes passed bidirectionally
  within configured 1280-byte TUN MTU

**Not established by those tests:** a separate physical/VM kernel,
real WAN/provider filtering, public Internet source spoofing, current
Echo Reply ICMP profile end-to-end acceptance, outer TCP establishment,
all route/rp_filter/firewall combinations,
large-scale performance beyond tested netem transfers, or
review/merge/release. Container reboot is not a full independent
hardware/kernel reboot. These remain tracked in
[Issue #262](https://github.com/ach1992/simple-tun-link/issues/262).
