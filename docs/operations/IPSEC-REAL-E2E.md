# Real isolated IKEv2/IPsec/XFRM two-peer acceptance fixture

Controlling work: Issue #7. The full release distribution, architecture and
reboot matrix remains assigned to Issue #12.

IMPORTANT: This is a **real protected-traffic integration fixture**, not a
production-enabled IPsec backend. The canonical Engine still does not register
an operational IPsec implementation. Successful isolated VICI calls are never
host-service admission or canonical Engine lifecycle evidence.

## Fixture boundaries

The caller launches a throwaway container disconnected from all networks
(Docker --network none), with specifically granted NET_ADMIN, NET_RAW and
SYS_ADMIN, without mounting host services, network namespaces, package files,
daemon configuration or writable host system paths. Inside this disposable
container only, two independent Linux network namespaces contain:

- One private veth underlay (192.0.2.1/30 and 192.0.2.2/30).
- Two independent native strongSwan charon-systemd daemon processes.
- Two distinct private Unix VICI endpoints and protected configuration files.
- One or two canonical STL-named connections, children, PSK identifiers
  and nonzero XFRM interface IDs derived from full 128-bit Link identities.
- Real /31 Link Addresses and 256-bit random protected test PSKs.

The Go helper constructs per-Link VICI requests using the repository's real
ipsec.Profile code and upstream govici framing. It cannot contact the host's
default VICI socket: it checks the disposable authorizations, Docker marker,
and exact fixture Unix socket location. load-conn and load-shared are strictly
per-Link; the helper checks vacancy and refuses an already present name.
The fixture has only two freshly created private daemon writers; this
private-writer fact is essential. A vacancy read against a shared daemon
does NOT prevent a foreign writer race and is never a production ownership
token.

Each fixture case performs an actual IKEv2 negotiation and bidirectional ping
(three ICMP packets each way) across the Link Addresses, inspects installed
kernel ESP SA identities and checks cleanup. A negative control checks that
the Link Addresses cannot communicate before any protected SA exists.
NAT-T acceptance requires actual kernel ESP-in-UDP encapsulation (ip xfrm
state encap espinudp), not merely a configuration flag.

- single: create, private-scoped VICI load, negotiate, protected traffic,
  read-only reapply check, terminate, unload and exact XFRM cleanup.
- multi: establish two simultaneous independent Links with the same underlay
  peers, remove one and prove the sibling still transfers packets.
- mismatch: use a different PSK on one peer for the second Link, require
  IKE negotiation failure, preserve an unrelated healthy sibling and clean
  the failed Link's test-owned objects.
- conflict: attempt a second VICI load for an already occupied same-name
  connection and shared PSK; reject replacement, retain existing traffic.
- restart: exploratory daemon restart and VICI reload from the same protected
  secret, NOT part of the verified evidence below.

The reapply check is intentionally **read-only** after first load. It does
not attest the actual PSK bytes already held by a daemon, durable ownership
or any production Engine transaction.

## Reproduce in an authorized disposable Docker environment

From the repository root, ensure Go, Docker and a recent Linux XFRM-enabled
kernel are available. Docker must be controlled by an explicitly authorized
operator. These steps build and execute containers; never run the test
script itself on the control-plane host.

    mkdir -p /tmp/stl-ipsec-e2e
    go build -o /tmp/stl-ipsec-e2e/stl-ipsec-probe ./scripts/e2e/ipsec-vici-probe

    docker build -f scripts/e2e/ipsec-lab-debian.Dockerfile -t stl-proof:debian .
    docker build -f scripts/e2e/ipsec-lab-ubuntu.Dockerfile -t stl-proof:ubuntu .

With one selected image (repeat for the other), run each combination.
The commands mount the read-only tool and fixture script only:

    IMAGE=stl-proof:debian
    for ENCAP in esp nat-t; do
      for CASE in single multi mismatch conflict; do
        docker run --rm --network none \
          --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
          --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
          -e STL_E2E_DISPOSABLE_HOST=approved \
          -e STL_IPSEC_ISOLATED=approved \
          -e STL_IPSEC_ENCAP="$ENCAP" -e STL_IPSEC_CASE="$CASE" \
          -v /tmp/stl-ipsec-e2e/stl-ipsec-probe:/usr/local/bin/stl-ipsec-probe:ro \
          -v "$PWD/scripts/e2e/ipsec-two-peer-netns.sh":/proof/run.sh:ro \
          "$IMAGE" bash /proof/run.sh
      done
    done

A passing test prints the REAL_IPSEC_E2E=PASS marker with exact case and
encapsulation, along with bidirectional ICMP statistics, and checks SA
and VICI object cleanup. Unexpected or ambiguous daemon responses fail
closed rather than becoming a success marker.

## Measured observations, 2026-10-12

AI Test Server, Ubuntu 6.8.0-31-generic host kernel (XFRM kernel behavior
shared with the isolated containers; host network configuration untouched):

- Debian 13 proof image ID:
  sha256:a0a66dbaa5c8aa2d7ffaf6eab085a670f9526fec2b7a6b1416bed50ece12edc2
  strongSwan 6.0.1 and iproute2 6.15.0.
- Ubuntu 24.04 proof image ID:
  sha256:3558e5e7de97f0a9e01d49a33bbb977c73b0cf0dce7ef458add8f0629b0c239a
  Ubuntu image package versions must be separately recorded at rerun.

On both distributions, single/ESP, single/NAT-T, multi/ESP and
mismatch/ESP passed in fresh disconnected disposable containers.
Debian also passed multi/NAT-T and conflict/ESP. The later Debian
multi/NAT-T run included both negative pre-IKE plaintext controls.

The recorded traffic was 3 of 3 ICMP packets received in BOTH directions.
The full NAT-T route had two ESP-in-UDP SAs per peer. Multi-Link removal
kept the surviving sibling passing bidirectional traffic; mismatch left
that sibling intact and produced no extra ESP SAs; scoped cleanup left
zero test Link SAs. A duplicate VICI load was rejected, demonstrating a
safety guard added after discovering the upstream replacement behavior.

## Open non-negotiable gates

This fixture alone does **not** prove native-exclusive systemd unit origin,
effective daemon process and secure CFG logging provenance, package script
or autostart side effects, lifetime-exclusive private VICI writers,
canonical Engine credential activation/commit, durable XFRM creation and
ifindex receipts, fail-safe interrupted transaction recovery, actual
production status/diagnostics, startup/reboot restore, NAT router traversal
or Issue #12's broader acceptance matrix.

The current fixture does not register an IPsec production backend; enabling
the existing read-only preparation code without these gates would risk
replacing foreign daemon objects and exposing secrets. Keep Issue #7 OPEN;
a final independent HIGH_ASSURANCE review and merge are appropriate only
after a complete operational Engine-integrated candidate, installed-service
admission and real isolated acceptance are all delivered and verified.

## Native-exclusive installation hazard observed in both distributions

A read-only examination of the installed Debian and Ubuntu package metadata
confirmed that charon-systemd packages ship a vendor-owned strongswan.service
unit and maintainer scripts. In BOTH tested package versions, the postinst
contains deb-systemd-helper enable, systemctl daemon-reload and
deb-systemd-invoke start/restart actions for that service. The exact observed
packages were Debian charon-systemd 6.0.1-6+deb13u7 and Ubuntu
charon-systemd 5.9.13-2ubuntu4.24.04.5.

Therefore, simply installing packages with apt on a real systemd host can
create/enable/start an **independent strongSwan service** and invalidate
native-exclusive ownership. A stopped service or an empty UDP socket list
does not resolve this durable autostart/upgrade risk. No foreign service,
package hook, global strongSwan configuration, or host firewall was modified
during these observations. The production implementation MUST explicitly
account for package-transaction side effects and future upgrades, not mask
or disable an unknown foreign unit as an undocumented workaround.

The latest supplementary isolated tests also passed multi/NAT-T and
mismatch/NAT-T on Ubuntu 24.04, mismatch/NAT-T on Debian 13, and the
conflict rejection scenario on Ubuntu. Production restart/restore remained
unverified because the privileged restart fixture invocation could not
be authorized through the test execution tool. This is an explicit gate,
not a successful restart observation.
