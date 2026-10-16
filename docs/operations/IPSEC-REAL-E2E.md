# Native IPsec / IKEv2 / XFRM E2E

This runbook exists for reproducible **real-kernel IPsec packet,
native-exclusive service and crash-reconciliation tests**.
Historical fixture acceptance and exact SHAs remain in
[Issue #7](https://github.com/ach1992/simple-tun-link/issues/7),
[Issue #12](https://github.com/ach1992/simple-tun-link/issues/12)
and [PR #81](https://github.com/ach1992/simple-tun-link/pull/81).
This is not a live development-status or release-approval log.

## Safety and prerequisites

**Never run these privileged Docker/network/systemd commands
on a production, shared, AI Server Agent or other control-plane
host.** They require separate operator approval for a disposable
Docker-capable VM. The marker
`STL_E2E_DISPOSABLE_HOST=approved` is a runner guard,
not authorization in itself.

The fixtures use disconnected containers, task-owned Linux
network namespaces, independent per-peer State/credential
roots and temporary strongSwan services. A positive private
VICI/service observation does not prove encrypted traffic:
verify actual IKE/CHILD SAs, bilateral Link Address packets,
kernel ESP or ESP-in-UDP state and scoped cleanup.

The production IPsec backend must admit **only** an exact
STL-origin native-exclusive strongSwan runtime. It may not
adopt/stop a foreign service, bulk unload credentials, delete
XFRM by name or rekey an uncertain Link. See
[IPsec ADR](../decisions/ADR-0005-scoped-vici-ipsec.md),
[security](../SECURITY.md) and
[installation](../INSTALL.md) for current consent/ownership rules.

## Disconnected two-peer namespace E2E

From a clean committed checkout **on the disposable VM**:

~~~bash
mkdir -p /tmp/stl-ipsec-e2e
go test -c -o /tmp/stl-ipsec-e2e/stl-ipsec-cli-test ./cmd/stl
go build -o /tmp/stl-ipsec-e2e/stl-ipsec-probe ./scripts/e2e/ipsec-vici-probe
docker build -f scripts/e2e/ipsec-lab-debian.Dockerfile -t stl-ipsec:debian .
docker build -f scripts/e2e/ipsec-lab-ubuntu.Dockerfile -t stl-ipsec:ubuntu .
for image in debian ubuntu; do
  for encap in esp nat-t; do
    for scenario in single multi mismatch foreign recover; do
      docker run --rm --network none \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
        -e STL_E2E_DISPOSABLE_HOST=approved -e STL_IPSEC_ISOLATED=approved \
        -e STL_IPSEC_CLI_FIXTURE=approved -e STL_IPSEC_DRIVER=cli \
        -e STL_IPSEC_CASE="$scenario" -e STL_IPSEC_ENCAP="$encap" \
        -v /tmp/stl-ipsec-e2e/stl-ipsec-cli-test:/usr/local/bin/stl-ipsec-cli-test:ro \
        -v /tmp/stl-ipsec-e2e/stl-ipsec-probe:/usr/local/bin/stl-ipsec-probe:ro \
        -v "$PWD/scripts/e2e/ipsec-two-peer-netns.sh":/proof/run.sh:ro \
        "stl-ipsec:$image" bash /proof/run.sh
    done
  done
done
~~~

The loop tests Debian/Ubuntu userspaces, ESP and NAT-T,
single/multi-sibling Link cases, deliberate PSK mismatch,
foreign-object rejection and recovery. Negative tests
intentionally fail a scoped operation before emitting an
overall successful rejection marker. A PASS requires
real two-way packets through the intended
Link Addresses after negotiation, no traffic before IKE,
correct `espinudp` for NAT-T, intact siblings and
exact-owned VICI/XFRM/credential removal.

No tests may silently skip an unavailable required native
capability or substitute mock/kernel-independent observations
for actual packet delivery. Do not copy PSKs or sensitive
Quick Links into CI/PR logs.

## Actual private systemd service E2E

The Dockerfile explicitly prevents its **own guest image**
from starting the vendor StrongSwan unit. This is **never**
permission to disable a unit on the Docker VM or a real
administrator's host. Use a **fresh** container and Link ID
for each `esp` and `nat-t` run (the example below uses
ESP; repeat explicitly with a new container for NAT-T).

First run the compile/image steps above; then:

~~~bash
docker build -f scripts/e2e/ipsec-lab-ubuntu-systemd.Dockerfile -t stl-ipsec:systemd .
# Create a new disposable container for each encap; this sample uses ESP.
cid=$(docker run --rm -d --network none --privileged --cgroupns private \
  --tmpfs /run --tmpfs /run/lock stl-ipsec:systemd)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || :' EXIT
go build -o /tmp/stl-ipsec-e2e/stl ./cmd/stl
go test -c -o /tmp/stl-ipsec-e2e/stl-ipsec-native-test ./internal/backend/ipsec
for binary in stl stl-ipsec-native-test stl-ipsec-cli-test stl-ipsec-probe; do
  docker cp "/tmp/stl-ipsec-e2e/$binary" "$cid:/usr/local/bin/$binary"
done
docker exec "$cid" sh -c 'chown root:root /usr/local/bin/stl /usr/local/bin/stl-ipsec-* && chmod 0755 /usr/local/bin/stl /usr/local/bin/stl-ipsec-*'
docker exec -e STL_E2E_DISPOSABLE_HOST=approved -e STL_IPSEC_ISOLATED=approved \
  -e STL_IPSEC_SYSTEMD_FIXTURE=approved "$cid" /usr/local/bin/stl-ipsec-native-test \
  -test.run '^TestIsolatedNativeExclusivePublication$' -test.v
docker exec "$cid" sh -c 'systemctl daemon-reload && systemctl start simple-tun-link-ipsec.service'
docker cp scripts/e2e/ipsec-installed-systemd.sh "$cid:/tmp/run-ipsec.sh"
docker exec -e STL_E2E_DISPOSABLE_HOST=approved -e STL_IPSEC_ISOLATED=approved \
  -e STL_IPSEC_SYSTEMD_FIXTURE=approved -e STL_IPSEC_ENCAP=esp "$cid" bash /tmp/run-ipsec.sh
~~~

Required fixture markers:

- `NATIVE_SYSTEMD_REAL_IPSEC_E2E=PASS encapsulation=esp`
  (or `nat-t`);
- `NATIVE_SYSTEMD_ACTUAL_UNIT_RESTART_RESTORE=PASS`;
- `NATIVE_SYSTEMD_PROTECTED_PSK_RETIREMENT=PASS`.

The test must attest private config/unit origin, effective
systemd service and root-owned executable, current VICI
peer/process/port identity and secret-safe logging **before**
loading a key. It must prove actual tunnel traffic after
a real restart of the **guest STL-only** service and
canonical `stl link restore --all`, then verify scoped
SA/VICI/XFRM and PSK retirement. A **container** service
restart is not a full Linux OS reboot.

## Fault and crash-recovery contract

The existing `scripts/e2e/ipsec-two-peer-netns.sh` fixture
also supports explicit `STL_IPSEC_CASE` fault scenarios
under the same root-owned disposable Docker isolation:

- `xfrm-index`: crash after XFRM creation, before original
  ifindex is durably recorded; refuse name-based adoption
  or automatic deletion even if a matching interface exists.
- `xfrm-alias` / `xfrm-address`: after the original
  ifindex is durably recorded but alias/address completion
  is incomplete; reconcile **only** the original owned
  inode/interface and recover original PSK/Link.
- `xfrm-foreign`: replace the known interface with a
  foreign same-name/`if_id` fixture; refuse deletion of
  the new identity.
- `remove-shared`, `remove-shared-absent`,
  `remove-device` and `remove-device-absent`:
  interruption during exact-owner VICI/SA/XFRM Remove;
  a fresh CLI process must reconcile the journal,
  preserve unrelated sibling packets and issue only the
  correct protected key-retirement receipt.

Pending or journal-bearing State is not authority to
repeat arbitrary effects or wipe credentials. **Current
private State schema v3** is separate from the public
CLI output schema v1; unknown journal fields and older
readers may have an upgrade-only compatibility boundary.
Follow [INSTALL.md](../INSTALL.md) rather than editing
State versions to force a downgrade.

## Acceptance boundaries

Source/fake-runner tests, kernel namespace packet traffic,
a real PID1-systemd container restart and an independently
**booted full guest** are different evidence classes.
Whole-guest IPsec ESP/NAT-T automatic restoration after
reboot and abrupt QEMU termination has distinct exact-SHA
evidence under [PR #81](https://github.com/ach1992/simple-tun-link/pull/81)
and [Issue #12](https://github.com/ach1992/simple-tun-link/issues/12).
QEMU process termination is **not** physical power-loss
testing; a guest's test-only NAT-T is **not** traversal of
a real provider/router.

Record exact executable/source SHA, distro/kernel/daemon,
test markers, both peer packet/SA observations, expected
failure classes and task-owned cleanup in the **controlling
CI/PR/Issue**. A published release, production installation
or physical host acceptance cannot be inferred from this
isolated test. Real two-server WAN/NAT/provider-firewall
checks remain the separate
[Owner field gate](https://github.com/ach1992/simple-tun-link/issues/93).
