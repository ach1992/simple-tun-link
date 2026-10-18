# STL Spoof Diagnostics — offline Go operator prototype

This is a **non-networking Go development slice**, not yet the complete two-node source-spoof probe. It is independent of the STL command and its installer/state. On current source, Go supports `version`, `preflight`, `sources add`, `plan`, `report`, and a basic offline `menu`. The future Go packet agent, per-host credential provisioning, authenticated offline evidence exchange, secure source-IP field test and encrypted bidirectional L3 are **NOT IMPLEMENTED**. The earlier Python two-agent prototype remains a separate, more complete lab study; its passing Python tests do not prove parity with this Go binary.

`plan` validates **only explicit sources** in CSV/JSON. The file marks sender/receiver and A_TO_B vs B_TO_A; no IP block scanning is performed. `report` evaluates JSON declarations supplied by the operator; it does **NOT** cryptographically verify their observations. Accordingly results say `UNVERIFIED_INPUT_DECLARATION` and never claim private L3.

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

The operator must confirm `YES` on interactive installation; use `--install --accept` **only** for explicitly authorized noninteractive/test installation. No `apt`, `pip`, `curl`, `wget` or Go toolchain should run on the destination. The installer is only for the Go offline console build **as it currently exists**; does not start agents, open ports, create Link/network configurations or enable public-source spoofing.

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

## Local source-only acceptance

```sh
cd research/spoof-diagnostics
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0 go build ./cmd/stl-spoofdiag
```

CI/build machines (not hosts being diagnosed) require Go >= 1.23. The generator `scripts/build-offline.sh` builds an **unpublished snapshot directory**, not a GitHub Release or production package. The independent release lifecycle with tagged versions, installer validation for upgrades/removal/rollback and isolated two/three-guest kernel raw packet E2E remain outstanding.

For architectural truth see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/INSTALL-AND-RELEASE.md](docs/INSTALL-AND-RELEASE.md). No interaction with STL runtime or installed Links is allowed.
