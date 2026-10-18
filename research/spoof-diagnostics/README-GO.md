# STL Spoof Diagnostics — offline Go operator prototype

This is a **non-networking Go development slice**, not yet the complete two-node source-spoof probe. It is independent of the STL command and its installer/state. On current source, Go supports `version`, `preflight`, `plan`, `report`, and a simple offline `menu`. The future Go packet agent, per-host credential provisioning, authenticated offline evidence exchange, secure source-IP field test and encrypted bidirectional L3 are **NOT IMPLEMENTED**. The earlier Python two-agent prototype remains a separate, more complete lab study; its passing Python tests do not prove parity with this Go binary.

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

## Local source-only acceptance

```sh
cd research/spoof-diagnostics
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0 go build ./cmd/stl-spoofdiag
```

CI/build machines (not hosts being diagnosed) require Go >= 1.23. The generator `scripts/build-offline.sh` builds an **unpublished snapshot directory**, not a GitHub Release or production package. The independent release lifecycle with tagged versions, installer validation for upgrades/removal/rollback and isolated two/three-guest kernel raw packet E2E remain outstanding.

For architectural truth see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/INSTALL-AND-RELEASE.md](docs/INSTALL-AND-RELEASE.md). No interaction with STL runtime or installed Links is allowed.
