# STL Spoof Diagnostics — standalone Go development candidate

This is a **partial, loopback-only Go diagnostic** independent of STL runtime and installation. Go supports `version`, `preflight`, `sources add`, `plan`, `report`, a basic `menu`, and actual authenticated two-agent **local** `lab` sessions with signed, portable receipts. It also supports a signed offline challenge/observation exchange when mTLS control is absent. **All Go networking remains restricted to 127.0.0.1; no raw forged IPv4 traffic or real-world field probes are implemented.** No usable private L3 Link has been built. The legacy Python experiment is distinct; its test results must not be substituted for exact Go acceptance.

`plan` validates **only explicit sources** in CSV/JSON. The file marks sender/receiver and A_TO_B vs B_TO_A; no IP block scanning is performed. `report` evaluates JSON declarations supplied by the operator; it does **NOT** cryptographically verify their observations. Accordingly results say `UNVERIFIED_INPUT_DECLARATION` and never claim private L3.


## Actual Go laboratory operation (no spoofing, 127.0.0.1 only)

The Go binary now has a genuine, separate sender and receiver using TLS 1.3 mutual authentication plus authenticated UDP over **loopback only**. A receiver signs the observations with its Ed25519 certificate. The sender verifies the signature, signer, run ID and sample identities. The standalone \`lab verify\` command can check a saved receipt against an independently recorded run ID. This proves **local authenticated transport and observation exchange** only: every claimed RFC1918 candidate remains metadata; the actual UDP source is \`127.0.0.1\`. Neither raw IPv4 fake-source egress, provider admission, sender return, nor private L3 has been demonstrated.

For disposable local development only, generate a new short-lived CA and separate A/B identities (the generated directory contains **both** nodes' private keys and the CA signing key; never copy the directory into a real server or package):

\`\`\`sh
stl-spoofdiag lab identity --dir /tmp/new-private-spoofdiag-lab-identity
\`\`\`

Use \`examples/sources-private.csv\` from this source tree or copy the shipped \`sources-private.csv\` from the verified offline package. In terminal B:

\`\`\`sh
stl-spoofdiag lab serve --file sources-private.csv \
  --cert /tmp/new-private-spoofdiag-lab-identity/B.crt \
  --key /tmp/new-private-spoofdiag-lab-identity/B.key \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt \
  --sender A --receiver B --control-port 24001 --data-port 24002
\`\`\`

In terminal A:

\`\`\`sh
stl-spoofdiag lab run --file sources-private.csv \
  --cert /tmp/new-private-spoofdiag-lab-identity/A.crt \
  --key /tmp/new-private-spoofdiag-lab-identity/A.key \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt \
  --sender A --receiver B --control-port 24001 \
  --packet-size 192 --out /tmp/new-peer-receipt.json
\`\`\`

The \`run_id\` printed by A must be retained **independently**. To verify the portable receipt without contacting B:

\`\`\`sh
stl-spoofdiag lab verify --file /tmp/new-peer-receipt.json \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt \
  --peer spoofdiag-b.local --run EXACT_RUN_ID_FROM_SENDER
\`\`\`

To test the opposite direction, swap sender/receiver roles, their A/B certificates, and the listener's role; candidates in the CSV remain **direction-specific**, not interchangeable.

### File-based signed challenge/receipt with no mTLS control channel

This separate, functional **local** flow is for demonstrating how authenticated measurements can be reunited when the normal control channel is unavailable. It does not discover a peer or test a WAN. All UDP sockets are bound to/send to \`127.0.0.1\` and the sender never claims \`PEER_OBSERVED\` solely because it sent a packet. The signed challenge carries no shared HMAC secret; each offline UDP packet is individually Ed25519-signed.

Terminal A creates a new expiring, signed challenge:

\`\`\`sh
stl-spoofdiag lab challenge --file sources-private.csv \
  --cert /tmp/new-private-spoofdiag-lab-identity/A.crt \
  --key /tmp/new-private-spoofdiag-lab-identity/A.key \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt \
  --sender A --receiver B --packet-size 192 \
  --out /tmp/new-challenge.json
\`\`\`

Transfer that signed JSON to B by an authorized out-of-band means. Terminal B validates the signature, exact allowlist and replay ledger before listening:

\`\`\`sh
stl-spoofdiag lab offline-listen --file sources-private.csv \
  --cert /tmp/new-private-spoofdiag-lab-identity/B.crt \
  --key /tmp/new-private-spoofdiag-lab-identity/B.key \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt \
  --sender A --receiver B --challenge /tmp/new-challenge.json \
  --state-dir /tmp/new-private-replay-ledger --window-seconds 10 \
  --data-port 24002 --out /tmp/new-offline-receipt.json
\`\`\`

While B listens, A invokes:

\`\`\`sh
stl-spoofdiag lab offline-send --challenge /tmp/new-challenge.json \
  --cert /tmp/new-private-spoofdiag-lab-identity/A.crt \
  --key /tmp/new-private-spoofdiag-lab-identity/A.key \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt \
  --sender A --receiver B --data-port 24002
\`\`\`

Finally, after transferring B's signed receipt back to the operator:

\`\`\`sh
stl-spoofdiag lab offline-verify --challenge /tmp/new-challenge.json \
  --receipt /tmp/new-offline-receipt.json \
  --ca /tmp/new-private-spoofdiag-lab-identity/ca.crt
\`\`\`

A valid signed receipt with **zero** packets is an \`INCONCLUSIVE\` delivery result, not proof of IP rejection. A partial receipt remains \`PARTIAL\`. The receiver's private \`--state-dir\` consumes run IDs durably and rejects reusing the same challenge; preserve it for the entire testing period. The challenge expires within 90 seconds; generate a fresh one for a new run. Signed records do not establish physical egress, admission of the claimed IP, sender-return routing, or an STL Link.

**Not yet delivered:** raw RFC1918 two/three-guest kernel packet admission from the exact Go binary, independent interface captures, field approval engine, practical production-grade node/key provisioning, broader interactive menu, cross-host/real-provider performance, offline lifecycle rollback/uninstall, published tool-specific Release, and online bootstrap. Keep \`LAB_VERIFIED\` and \`FIELD_READY\` unset until those independent gates pass.

## Use without internet, no packages or build tools on the destination

Once a snapshot/release directory is built using the Go builder, place its complete files under `/root/stl-spoofdiag/` on the authorized server. Source files and archives are **inbox material**, not the installation location. On the destination, from the **verified and extracted exact archive**:

```sh
cd /root/stl-spoofdiag/<verified-extracted-directory>
bash install-offline.sh --verify
sudo bash install-offline.sh --install
stl-spoofdiag version
stl-spoofdiag menu
stl-spoofdiag plan --file sources-private.csv
stl-spoofdiag report --file evidence-private.json
```

The operator must confirm `YES` on interactive installation; use `--install --accept` **only** for explicitly authorized noninteractive/test installation. No `apt`, `pip`, `curl`, `wget` or Go toolchain should run on the destination. The installer places the standalone binary but **does not automatically start an agent**, open firewall ports, create Link/network configurations or enable public-source spoofing. Local agents are started explicitly with `lab` commands; their sockets are loopback-only.

Sample source and evidence files contain private example addresses and illustrative **NOT_TESTED** records, not network measurements. The offline installer verifies archive-contained hashes and manifest; those hashes alone are not independent publisher authentication. Verify the full artifact against an independently trusted expected digest/signature before running it as root.

## Enter an explicit source IP manually (no network calls)

An operator can enter an owned **private laboratory** source and its direction without using an editor. The tool creates/updates an operator-owned JSON source list; repeated candidates, inconsistent source modes and direct symlink files are refused.

```sh
stl-spoofdiag sources add \
  --file /root/stl-spoofdiag/sources.json \
  --mode private_lab \
  --ip 10.90.3.100 --direction A_TO_B --sender A --receiver B

stl-spoofdiag sources add \
  --file /root/stl-spoofdiag/sources.json \
  --ip 10.90.3.101 --direction B_TO_A --sender B --receiver A

stl-spoofdiag plan --file /root/stl-spoofdiag/sources.json
```

To use an existing CSV or JSON file, use `plan --file` or menu option 3. Menu option 5 can add a single candidate to a JSON file. This **stores candidate identity only**; there is no packet transmission, IP scanning, or inference that the source is usable.

## Build and validate an offline archive (developer/CI machine only)

From a clean checked-out repository at the exact intended source commit:

```sh
cd research/spoof-diagnostics
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
bash scripts/package-offline.sh /tmp/spoofdiag-package-dir "$(git rev-parse HEAD)" dev-local amd64
cd /tmp/spoofdiag-package-dir
sha256sum -c spoofdiag-dev-local_linux_amd64.tar.gz.sha256
```

The output archive is `spoofdiag-dev-local_linux_amd64.tar.gz`. For ARM64 replace the last argument with `arm64`, build on a Go-capable development/CI host and install only on a matching Linux architecture. A `dev-local` archive is **NOT a published GitHub release**; it is a local snapshot. Copy the archive to `/root/stl-spoofdiag/` on a specifically authorized device. The external `.sha256` file does not establish publisher authenticity by itself: compare the digest against an independently trusted manifest/source identity.

## Local source and loopback acceptance

```sh
cd research/spoof-diagnostics
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0 go build ./cmd/stl-spoofdiag
```

CI/build machines (not hosts being diagnosed) require Go >= 1.23. The generator `scripts/build-offline.sh` builds an **unpublished snapshot directory**, not a GitHub Release or production package. The independent release lifecycle with tagged versions, installer validation for upgrades/removal/rollback and isolated two/three-guest kernel raw packet E2E remain outstanding.

For architectural truth see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/INSTALL-AND-RELEASE.md](docs/INSTALL-AND-RELEASE.md). No interaction with STL runtime or installed Links is allowed.
