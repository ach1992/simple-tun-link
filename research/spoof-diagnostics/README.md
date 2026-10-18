# STL Source-IP Admission Diagnostics — research-only prototype

> **Development tracks:** The initial two-agent Python implementation below remains a research prototype. A separate, newer **Go-only offline operator slice** has been added under `cmd/stl-spoofdiag/`, with dedicated [Go README](README-GO.md), [architecture](docs/ARCHITECTURE.md) and [offline installation/release contract](docs/INSTALL-AND-RELEASE.md). The Go binary validates direction-aware CSV/JSON candidates and includes real **loopback-only** mTLS/UDP A↔B agents, signed peer receipts and signed offline challenge/receipt exchange; a guarded **isolated RFC1918-only** raw IPv4 Go adapter was added, but true exact-binary private-kernel raw E2E remains **NOT_RUN** at this development checkpoint. These two implementations must not be conflated. The final independent Go release has **not** been published; no physical-host network test is authorized. Uploaded bundles belong under `/root/stl-spoofdiag/` as operator staging, never as STL's runtime state.

> **NOT an STL transport, installer, or production scanner.** This standalone
> Python 3.10+ diagnostic belongs to the research track of issue #125. It does
> not create an L3 Link, forward user traffic, modify routes or firewalls, or
> choose a transport for STL. No public spoofing trial was conducted.

## Why two agents?

A selected source IP **cannot be declared viable merely because a raw `sendto`
returns a byte count**. The tool requires a second, cooperating peer to report
which *authenticated probe datagrams* it actually received. The sender makes a
bounded attempt for each **explicitly approved source IP**, packet size and
repetition, and correlates observations using a fresh HMAC key/session ID.

* **Agent B: `serve`**. Listens on an exact, operator-owned IPv4 address for
  UDP probe packets and a TLS 1.3 **mutually authenticated** TCP control
  connection. Independently verifies the *actual UDP source IP* against the
  signed claimed IP, nonce/session, sample index, size and allowlist. Returns a
  TLS-protected observation summary. It sends **no UDP replies to the spoofed
  source**, so it cannot be misused as an open reflector.
* **Agent A: `probe`**. Creates the short-lived authenticated session, emits
  each candidate's probe to the **single fixed peer** and produces a JSON
  matrix. Only the explicitly opted-in `permitted_field` mode constructs raw
  IPv4/UDP packets; egress is bound to the exact configured interface.
* **`check`**. Validates a hypothetical field manifest and outputs a plan
  **without opening a socket or requiring permission**.

`peer_observed_sources` means every configured sample for that source and size
was **authenticated by Agent B** during that one session. It **does not** mean
(a) provider routing is permanently allowed, (b) a return path to the sender
exists, (c) the sender's NIC egress was independently captured, or (d) private
L3/VPN traffic works. Those fields are explicitly `NOT_TESTED`.

## Modes and executable authorization boundary

| Mode | What may run | Scope |
| --- | --- | --- |
| `local_loopback` | Real two-process TLS + UDP over `127.0.0.1`, no raw spoof | 127.0.0.1 / `lo` only |
| `permitted_field`, `check` | Static validation, **no traffic** | Explicit routable source list + fixed peer |
| `permitted_field`, `serve` / `probe` | **Not authorized or exercised in this research phase** | Requires a separately obtained, valid provider/source-prefix/peer approval, `--permit` metadata and `--enable-authorized-field` on **both** machines |

The last guard is an **operator attestation**, not independent verification of
legality or ISP permission. A made-up permit file does not authorize a real
field experiment. No source may be scanned without actual operator/provider
rights and applicable platform approval. Do not circumvent a rejected tool
operation. Tests must stay entirely local until the permission gate is
satisfied. Refusing public tests is **not** a transport failure.

Safety characteristics: one fixed destination (no destination discovery),
1–32 individually supplied source IPs, 1–2 payload sizes of 96–512 bytes,
1–2 repeats, at least 200ms inter-packet gap, at most 128 packets and 120s,
a fresh key/session, no amplification/reflection, no persistent service, and
no host-level firewall/sysctl/route/interface mutations. Only the exact
configured owned interface is used by the field sender (`SO_BINDTODEVICE`).
Field test needs Linux `CAP_NET_RAW` at Agent A. The peer may specify its own
owned local bind IPv4 using `--bind-ipv4`, for cloud 1:1 NAT setups.

## Local reproducible run (no forged packet)

From this directory, run:

```bash
python3 stl_spoof_diag.py check --config example-loopback.json
python3 -m unittest discover -s . -p 'test_*.py' -v
```

For a manual two-process local check, provision a **dedicated temporary CA,
peer server certificate with IP SAN `127.0.0.1`, and distinct client certificate**
with appropriate TLS EKUs (`serverAuth` and `clientAuth`). Do not commit the
private keys. Example, after generating `ca.crt`, `server.crt/server.key` and
`client.crt/client.key` into a private temporary directory:

```bash
# Terminal B (listener exits automatically after one bounded session):
python3 stl_spoof_diag.py serve --config example-loopback.json \
  --ca ./certs/ca.crt --cert ./certs/server.crt --key ./certs/server.key

# Terminal A:
python3 stl_spoof_diag.py probe --config example-loopback.json \
  --ca ./certs/ca.crt --cert ./certs/client.crt --key ./certs/client.key
```

The test suite independently generates short-lived certificates in a disposable
directory with OpenSSL; it runs a real loopback two-process authenticated UDP
exchange and a **zero-packet negative control**, plus a mocked raw
`SO_BINDTODEVICE` adapter and low-level auth/replay/field-gate tests.

## Future, authorization-dependent two-host procedure

1. **Before any real test**, the operator obtains explicit provider/network
   consent for the exact claimed source addresses/prefix, the assigned egress
   interface, the single receiving peer/ports and the approved observation
   mechanism; both server operators consent. Confirm platform permission.
2. Supply *only* specific authorized sources in the shared JSON manifest
   (`example-permitted-field.template.json` is intentionally not executable
   until replaced with genuine approved addresses). This tool screens that
   finite set; it does **not** discover all Internet addresses or generate
   candidate pools from arbitrary networks.
3. Create distinct TLS identities for both nodes under a private trusted CA.
   Copy the **same sanitized test manifest** to the two nodes; `egress_interface`
   refers to Agent A's interface. Keep certificates/keys and permit documents
   out of Git. On B use `--bind-ipv4` if the receiving public address is NATed.
4. Ensure a legitimate mTLS TCP control channel to Agent B is available and
   both test ports are explicitly permitted. When the control channel is
   unreachable, this version correctly fails closed even if raw UDP might
   have been admitted: **an independent/offline evidence rendezvous adapter
   is not yet implemented**. The tool does not silently declare an IP failed
   because its control channel could not connect.
5. When *all* permissions are actually verified, supply the separate
   `--permit` metadata and `--enable-authorized-field` to both roles. The tool
   performs a bounded one-shot admission measurement, then stops. Results
   describe admission to B only. Verify whether any separately authorized
   return path exists before considering L3; never reflect to an arbitrary
   claimed source to "test" it.

### Future-field JSON outcome vocabulary

```json
{
  "peer_observed_sources": ["<only authenticated, fully observed candidates>"],
  "sender_egress_capture": "NOT_TESTED",
  "return_path": "NOT_TESTED",
  "private_L3": "NOT_TESTED"
}
```

The example above is a **format illustration**, not a measured field result.

## What was validated, and what was not

The **exact Python program and tests in this folder** were exercised locally
in a container without `CAP_NET_RAW` or `CAP_NET_ADMIN`: manifest rejection,
authentication/replay, raw IPv4 header bytes, injected/mocked raw egress,
non-privileged two-process mTLS+loopback UDP end-to-end and empty-observation
fail-closed. Field raw packet emission, a public-Internet two-server run,
receiver source-admission through real providers and sender-return routing
are **NOT_RUN**. A *separate earlier* private kernel namespace experiment
reported in [issue #125](https://github.com/ach1992/simple-tun-link/issues/125)
established local RFC1918 raw peer admission in its own harness; it does not
validate this particular Python field raw socket byte-for-byte.

After any future permitted run, keep source/destination authorization evidence,
run ID, exact SHA and separate peer/sender observations, and describe the
provider/platform/return/L3 limits. Never publish secret keys or certificates.
