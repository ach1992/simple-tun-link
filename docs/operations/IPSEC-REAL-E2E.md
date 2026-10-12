# Real native-exclusive IPsec/IKEv2/XFRM acceptance

Controlling engineering work: Issue #7. Issue #12 retains the broader
release/architecture/reboot/platform matrix. All evidence below is from
**isolated, deliberately authorized, disposable Linux Docker fixtures**, not
a production installation or a real NAT router. Do not run privileged tests
on a shared control-plane/production host without explicit authority.

## Functional vertical delivered for independent review

The normal `stl` CLI conditionally registers `ipsec.OperationalBackend`
**only** after an entire currently loaded native-exclusive service origin
admission succeeds. Otherwise IPsec is unavailable, while GRE/IPIP/WireGuard
remain independent. No default package install, strongSwan start/stop, vendor
service adoption, automatic rekey, wildcard VICI cleanup or host firewall
change occurs through runtime construction.

- `stl doctor ipsec --json`: read-only, current native service admission;
  success does not mean negotiated Link traffic.
- `stl link create-ipsec --stdin --output /root/<private-file> --json`:
  bounded versioned public JSON in stdin, protected 256-bit PSK generation,
  root-private **SENSITIVE** Quick Link handoff file, Engine stage/activate.
- `stl link preview --stdin --json`, then
  `stl link import --stdin --confirm <preview-token> --json` on the peer:
  no SENSITIVE URL/PSK in ordinary JSON, logs or errors.
- `stl link connect-ipsec <id> --confirm <id> --json`: explicitly initiate
  per-Link IKEv2. Command acceptance is **not** equivalent to encrypted traffic.
- `stl link ensure --stdin --json` and `stl link restore --all`:
  canonical Engine idempotence, protected PSK, durable activation/reapply
  journals; interrupt/unknown effect preserves reconciliation state and
  **must not** trigger blind replacement/retry.
- `stl link status <id> --json`, `stl link diagnose <id> --json`:
  exact admitted interface and private VICI/SA observations, real
  Link-Address quality/PMTU probes; no XFRM key or raw daemon output.
- `stl link remove <id> --confirm <id> --json`:
  exact committed-claim/ifindex/VICI removal, independent of whether the
  peer Underlay remains reachable; atomically records a protected-key
  retirement receipt, then retires **only the matching** credential.
  `stl link retire-ipsec <id> --confirm <id> --json` is an idempotent
  **post-Remove-only** retry; it refuses active/pending/unrecorded Links.

Dedicated non-loading test-only source publishers use receipt-bound,
no-replace `strongswan.conf` and `simple-tun-link-ipsec.service` files.
These publisher internals are deliberately **not exposed as a general host
installer**. Runtime admission attests actual loaded systemd unit properties,
vendor-service conflict policy, process executable/cgroup/netns/environment,
effective private VICI socket with SO_PEERCRED, and current UDP 500/4500
ownership, revalidating before operational effects. It rejects foreign
same-namespace strongSwan and preserves unrelated isolated namespaces.

## Real two-peer evidence (2026-10-12)

- Debian 13 amd64: strongSwan `6.0.1-6+deb13u7`, iproute2 `6.15.0-1`.
- Ubuntu 24.04 amd64: strongSwan `5.9.13-2ubuntu4.24.04.5`,
  iproute2 `6.1.0-1ubuntu6.4`. Native PID1-systemd fixture also used
  Ubuntu systemd `255.4-1ubuntu8.17`.
- Shared test-server Linux kernel: `6.8.0-31-generic`. Namespace
  isolation and real kernel XFRM/ESP state; neither host network routes nor
  its strongSwan/systemd services were changed.

**Canonical Engine and CLI**, in independent Debian/Ubuntu containers:
ESP and NAT-T; one or two simultaneous Links with identical underlay peers;
256-bit Quick Link sender/recipient import; three successful ICMP Link Address
packets in **both directions** after IKEv2; zero successful packets over the
same Link Addresses **before** negotiation; confirmed kernel `espinudp`
encapsulation for NAT-T; wrong-PSK rejection; rejection of preexisting
foreign VICI connection/credential; read-only `status` and `diagnose`;
idempotent `ensure`; loss/reload of owned VICI state via canonical
`RestoreAll`; isolated removal of one Link without sibling disruption;
complete XFRM, per-Link daemon and private-PSK cleanup, with durable
retirement receipt and idempotent post-Remove retry.

**Installed systemd + normal STL executable**, in an explicitly disposable
Ubuntu 24.04 PID1-systemd container with native STL config/unit published by
the reviewed no-replace fixture and vendor strongSwan unit disabled **only
inside that container**: `stl doctor ipsec` returned
`activation_allowed:true`; ordinary `stl create-ipsec` + peer import
established real ESP traffic; real `systemctl restart
simple-tun-link-ipsec.service` succeeded; `stl link restore --all`
reloaded the saved owned Link, then bilateral traffic resumed; per-Link Remove
cleaned owned XFRM/VICI/SA and the stored protected PSK. This full path
passed with **ESP and NAT-T** (including kernel ESP-in-UDP). The source
fixture did not call systemctl on the test-server host.

A missing/foreign service, unverified socket/ports/owner, stale kernel
resource or ambiguous transaction fails **IPsec-only closed**. A malformed
XFRM socket-bypass policy cannot masquerade as vacancy. A denied invalid
PSK digest, hardlink, symlink or unsafe key permissions cannot authorize
credential deletion.

## Reproduction: disconnected namespace E2E

From the repository root on an authorized disposable Docker-capable test
machine (privileged Docker itself is a consequential capability):

```bash
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
```

The `foreign` negative case intentionally expects one CLI operation to fail
before outputting an overall passing rejection marker. A mismatch case expects
authentication failure while a healthy sibling continues transferring data.

## Reproduction: real PID1-systemd native service E2E

A distinct image `scripts/e2e/ipsec-lab-ubuntu-systemd.Dockerfile`
explicitly disables the vendor unit **inside Docker image build**. Do not
disable/mask/stop a foreign service on a real host. Use a separate **fresh**
container for `esp` and `nat-t`, because the durable retired Link identity
must never be silently re-used for a second key. Build `stl`, the two
test binaries, and `ipsec-vici-probe` as above, then inside the disposable
container copy each executable as `/usr/local/bin/<name>`, **chown
root:root and chmod 0755** (production executable trust gate), run
`TestIsolatedNativeExclusivePublication`, and explicitly start the
STL-only unit within the container before running the fixture:

```bash
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
```

One complete run must end with
`NATIVE_SYSTEMD_REAL_IPSEC_E2E=PASS encapsulation=esp` or `nat-t`,
plus `NATIVE_SYSTEMD_ACTUAL_UNIT_RESTART_RESTORE=PASS` and
`NATIVE_SYSTEMD_PROTECTED_PSK_RETIREMENT=PASS`. The command applies
privileged network/systemd effects **only inside that disposable
network-disconnected container**; Docker itself runs with elevated rights,
so use only an explicitly authorized isolated test server.

## Non-negotiable limitations and deployment gates

1. The distro `charon-systemd` packages ship vendor `strongswan.service`
   units and post-install scripts that may **enable/start a foreign service**.
   This test image disables its own vendor unit on image build; the actual
   package-install/upgrade side effects on a preexisting production host
   must never be assumed safe. Production provisioning is **not performed**
   by this engineering PR; approved packaging/update operational guidance
   and a host-specific safety review are still required.
2. The positive native runtime check is an audited **time-local**
   provenance/permission snapshot, not a formal lifetime mutex against
   privileged foreign root administrators. The exact protected directory,
   loaded unit and private VICI boundary are assumed to remain
   administrator-controlled. Never share this private daemon with a foreign
   VICI writer or adopt same-name objects.
3. The actual public-NAT router traversal, reboot/power-loss durability,
   CI on arm64/other old kernel-distro floors, production installer/release
   and all combinations of the Issue #12 matrix remain **unverified**.
   The implemented restore test is a **real STL systemd service restart**,
   not a full OS reboot.
4. A crash during an indeterminate VICI write retains a durable public-only
   journal and stops automatic replay. It requires explicit, owner-verified
   reconciliation; never delete arbitrary observed state or auto-rekey.
5. Deployment, merge and public release still require the project's Owner
   gates and one independent, author-separated high-assurance review.

## Issue #7 high-assurance R1–R5 crash/reconciliation acceptance (2026-10-12)

The operational runtime now checks the native `/usr/sbin/charon-systemd`
executable is a root-owned regular inode with root-controlled, non-writable
ancestry before trusting its PID, systemd service and private VICI socket.
The isolated native systemd positive test verifies this admission on genuine
Ubuntu strongSwan; ordinary unprivileged tests reject a non-root-owned 0755
binary and a writable ancestor.

A durable per-Link `ipsec_xfrm_operations` record is written BEFORE the
kernel `ip link add`, then advances through `issuing-create`, `indexed`,
`aliased`, `configured`. The original kernel ifindex is fsynced
**before** the non-atomic alias operation. If the process crashes after the
kernel created a device but before the ifindex receipt was persisted, its
identity remains **unknown**; STL refuses automatic deletion/adoption by
name or `if_id`. `reconcile-xfrm-ipsec <link-id> --confirm <link-id>
[--json]` is explicit, exact-owner and allowed only before VICI effectful
issuance; it aborts only the original journal-bound kernel object or safely
clears an undeniably vacant pre-effect state. Never turn unknown identity
into a made-up ifindex.

A durable per-Link `ipsec_remove_operations` record precedes the first
SA/VICI/kernel Remove mutation and covers exact ordered phases: SA
termination, connection unload, credential unload, ifindex-pinned XFRM
deletion, canonical Link+journal commit and receipt-bound post-Remove PSK
retirement. Interrupted Remove blocks ordinary Ensure/Remove and must
be explicitly resumed by `reconcile-ipsec <link-id> --confirm <link-id>
[--json]` under the same Engine locks, exact committed resource identity
and fresh attested VICI/kernel readbacks. Unknown outcomes retain their
journal; no wildcard cleanup or automatic credential reload is authorized.
`retire-ipsec` operates from the protected post-Remove receipt even
when strongSwan is STOPPED or cannot pass runtime admission.

The current state file schema remains **v2** (ordinary CLI JSON remains
`schema_version:1`). Older v2 binaries that reject unknown lifecycle
members cannot read a journal-bearing new v2 state: **upgrade-only** during
an unresolved journal; downgrade/rewrite is not a recovery method. Schema
v1 files containing any lifecycle-only members, including
`ipsec_removal_receipts`, are rejected. Existing legitimate schema-v1
GRE/IPIP Link snapshots still migrate.

### Reproduce real isolated crash/fault matrix

From the same source checkout and approved disposable Docker test server,
compile and mount the two exact-source Go binaries as in the preceding
"Reproduction: disconnected namespace E2E" section. The same bounded
`scripts/e2e/ipsec-two-peer-netns.sh` supports additional
`STL_IPSEC_DRIVER=cli` scenarios, individually in **fresh**
`--rm --network none` Docker containers with the original read-only
`/proof/run.sh` and matching read-only test binaries:

- `STL_IPSEC_CASE=xfrm-index`: interruption after actual Linux XFRM
  create but before original ifindex publication; the resumed process
  rejects both automatic Ensure and unsafe name-based reconciliation;
  the ambiguous device remains untouched within the disposable fixture
- `STL_IPSEC_CASE=xfrm-alias`: after persisted original ifindex before
  alias; new process aborts only the journal-owned device, reactivates
  original protected PSK, proves fresh IKEv2/ESP traffic and scoped remove
- `STL_IPSEC_CASE=xfrm-address`: after alias before address/up; same
  exact-owner recovery and real bilateral traffic
- `STL_IPSEC_CASE=xfrm-foreign`: after original ifindex journaling,
  the test deliberately replaces the XFRM interface in its isolated
  namespace with a fresh foreign device of the SAME name and `if_id`.
  Reconciliation must refuse to delete/adopt it, and the test confirms
  the replacement remains intact before fixture-only cleanup
- `STL_IPSEC_CASE=remove-shared`: test-only simulated interruption with
  a genuine removed VICI connection but still-present shared PSK
- `STL_IPSEC_CASE=remove-shared-absent`: same indeterminate unload, while
  the secret was actually already unloaded
- `STL_IPSEC_CASE=remove-device`: daemon objects absent but original
  journal-bound XFRM device still present
- `STL_IPSEC_CASE=remove-device-absent`: kernel deleted the exact owned
  interface after its original ifindex was durably journaled, before
  the resumed Remove command

All four Remove cases resume with a **new CLI process**, prove that an
ordinary Ensure is blocked, finish exact scoped cleanup and protected PSK
retirement, and transfer packets over a simultaneously negotiated,
unaffected sibling Link. Fault injection and root/kernel writes occur
**only in explicitly disposable containers**. The script deliberately
does not pass when unauthorized privilege, Docker marker or network
isolation is missing.

Targeted state tests also recreate `FileStore` after each checkpoint,
verify persisted phases/ifindex and reject orphaned, duplicate or tampered
journals. The original native PID1-systemd ESP/NAT-T acceptance above
must still pass on the revised exact source tree. These simulated
interruption tests are bounded reproducible fault injections, **not**
proof of actual physical power loss, external NAT router traversal or
production package/upgrade safety; Issue #12 retains release-level gates.
