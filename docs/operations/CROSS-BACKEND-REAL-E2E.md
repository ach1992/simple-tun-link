# Cross-backend real-kernel E2E

This is the **reproduction and acceptance contract** for the
existing multi-backend Linux namespace fixture. Exact historical
successful or failed executions, SHAs, guest identities and
release decisions belong to the linked
[GitHub CI runs](https://github.com/ach1992/simple-tun-link/actions)
and [acceptance history](https://github.com/ach1992/simple-tun-link/issues/12),
not a changing status report in this file.

## Safety and setup

Run privileged tests **only on an explicitly approved disposable
Docker-capable VM**. Never use a production, shared, AI Server
Agent or test-control-plane host. Docker containers share the
VM's kernel; FOU/IPIP module autoload may affect that VM.
The `STL_E2E_DISPOSABLE_HOST=approved` environment flag is
a local safety check, **not** authorization by itself.

From an exact clean committed checkout on the dedicated guest,
review the Dockerfile and base image digests, then:

~~~sh
docker build -f scripts/e2e/cross-backend.Dockerfile \
  --build-arg BASE_IMAGE=ubuntu:24.04 -t stl-cross-backend:ubuntu24 .
docker build -f scripts/e2e/cross-backend.Dockerfile \
  --build-arg BASE_IMAGE=debian:13 -t stl-cross-backend:debian13 .
sudo env PATH="$PATH" STL_E2E_DISPOSABLE_HOST=approved \
  STL_E2E_IMAGE_UBUNTU=stl-cross-backend:ubuntu24 \
  STL_E2E_IMAGE_DEBIAN=stl-cross-backend:debian13 \
  bash scripts/e2e/cross-backend-docker.sh
~~~

The driver builds the **exact committed source** as one checksummed
native test executable and runs it in fresh isolated,
network-disconnected containers with task-owned veth/namespace
pairs and private State/credential roots. It does not mount
the Docker socket, host network, production systemd or live
VICI/strongSwan credentials into the guests.

## Required actual-packet checks

A successful run must demonstrate all of the following, not
merely compile or print a success-looking JSON response:

1. Three simultaneous same-peer GRE Native, keyed FOU and keyed
   GUE Links with unique IDs, link IPs, collision-safe UDP/firewall
   identity and **bidirectional inner traffic**.
2. A fourth configured WireGuard Link on the same peers, with
   matching public identities, authentic handshake, bilateral
   encrypted packets and independent resource/credential ownership.
3. Fifth IKEv2/XFRM ESP and sixth independently keyed NAT-T
   Link on those same peers, with kernel-installed SAs,
   actual `espinudp` state for NAT-T, blocked pre-negotiation
   plaintext and confirmed bilateral protected packets.
4. Accurate **six-ID inventory** in the same State roots,
   no false resource sharing, successful idempotent reapply,
   collision rejection of competing GRE/FOU port claims,
   refusal to adopt an intentionally created foreign interface,
   and scoped recovery of a task-owned missing interface.
5. Removing ESP must preserve NAT-T and GRE/WireGuard siblings;
   retiring NAT-T/PSK and WireGuard keys must not damage
   other Links. Confirm no stray SA, XFRM, firewall, FOU or
   credential resources remain after scoped cleanup.
6. With GRE still active, separately test IPIP Native,
   FOU and GUE sequentially; the same IPIP underlay
   pair must reject indistinguishable parallel modes,
   leaving GRE siblings unaffected.
7. Every expected cleanup marker and both image runs
   must pass. A required missing kernel/daemon capability,
   malformed output, skipped packet stage or incomplete
   cleanup is **not acceptance**.

The fixture emits packet/ownership markers including
`SIX_SAME_PEER_GRE_NATIVE_FOU_GUE_WG_ESP_NATT=PASS`,
`FOU_RECOVERY_PRESERVES_ESP_AND_NATT=PASS`,
`REMOVE_ESP_PRESERVES_NATT_AND_GRE_WG=PASS`
and `NATT_SCOPED_REMOVE_PRESERVES_GRE_WG_SIBLINGS=PASS`.
It also requires `GRE_E2E_CLEANUP_EXIT=0` for the
guest sessions and
`CROSS_BACKEND_DISPOSABLE_CLEANUP_EXIT=0` overall.
Failure/timeout/unsupported paths must not quietly print PASS.

## Exact-source CI and evidence

The opt-in
[`cross-backend-e2e.yml`](../../.github/workflows/cross-backend-e2e.yml)
workflow can run the privileged matrix on dedicated GitHub-hosted
native AMD64 and ARM64 VMs for eligible runtime/E2E PRs.
Each guest Ubuntu/Debian userspace shares its runner's
kernel; native execution is **not** independent boot
of those distribution kernels. Source-only Go tests,
script syntax, offline installer smoke or cross-compilation
cannot replace live packet evidence.

Record the source SHA, native executable hash,
runner/kernel/architecture, image digest and distro/tool
versions, required PASS markers, host capability failures,
and verified final cleanup with the *controlling PR/CI run*.
Do not copy raw sensitive Setup Links, PSKs/private keys
or unrelated host credentials into evidence. CI evidence
applies to its **exact** source, not future commits/tags.

A container/namespace run cannot prove whole-guest reboot,
power-loss behavior, published downloadable artifact
identity or physical two-server provider WAN/NAT/firewall
reachability. Those are independently evidenced by
[release acceptance](../RELEASE-ARTIFACTS.md),
[IPsec whole-guest evidence](IPSEC-REAL-E2E.md)
and, for real field conditions, the
[Owner acceptance gate](https://github.com/ach1992/simple-tun-link/issues/93).
No test or result here authorizes production deployment,
merging, release publication or host changes.
