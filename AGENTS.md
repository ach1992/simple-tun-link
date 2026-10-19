# Agent Instructions

This repository is the authoritative implementation home for simple-tun-link.

Before coding:
1. Read docs/PROJECT-SPEC.md.
2. Read docs/ARCHITECTURE.md.
3. Read the relevant open GitHub Issue and ADRs.
4. Inspect current code/tests before changing behavior.

Hard boundaries:
- GRE Native is the v0.1 default.
- v0.1 backends are GRE, IPIP, WireGuard, and IPsec/XFRM.
- GRE/IPIP support Native/FOU/GUE.
- Go is the control plane; native backends keep packet data out of Go.
- For future Carriers, reuse the existing Engine and native L3 backends;
  no planned GOST or mandatory new userspace L3 engine. Prove framing,
  endpoint, security, MTU and resource-ownership compatibility before
  composing transports. See [Issue #142](https://github.com/ach1992/simple-tun-link/issues/142)
  for current Owner gates.
- No geography-specific data-model roles.
- No global host tuning merely for convenience.
- No firewall flush/default-route rewrite.
- No swallowed correctness errors or unconditional success messages.
- Operations must become idempotent and rollback owned partial state.
- Multi-Link is first-class: support 0..N Links per host, including multiple independent Links to the same peer pair when the backend/kernel can distinguish them.
- Do not invent product-imposed Link-count, bandwidth, transport, or external-consumer quotas; reject only real unsupported capability, conflicting resource identity, unsafe ownership, or unapproved host effects.
- Never assume one Link per host, peer, or backend; allocate collision-safe per-Link resources and keep create/update/repair/remove isolated from other Links.
- Interactive UI must not own engine logic. Follow
  `docs/CLI.md` interactive-operation contract and
  `docs/ARCHITECTURE.md` section 13 for semantic, width-aware screens;
  retain NO_COLOR/nonTTY and machine/JSON compatibility.
- Preparation should be a selected-backend, one-consent guided
  workflow using the existing canonical installer, kernel
  adapters and exclusive IPsec provisioner. Follow the exact service
  eligibility and separate STOP consent boundaries in
  `docs/SECURITY.md` and `docs/decisions/ADR-0005-scoped-vici-ipsec.md`.
  Do not duplicate service managers or substitute generic warnings
  for verified resource-ownership boundaries.
- Preserve standalone use plus generic reuse by arbitrary external software without designing STL around any specific future product.
- Never make interactive text an automation API; machine-readable outputs are versioned and secret-safe, and desired-state automation is idempotent.
- v0.1 secret-bearing pairing defaults to Quick Link: payloads are SENSITIVE, may carry receiver credentials, must never leak into ordinary logs/status/diagnostics, and must remain schema-extensible for a future secure/local-key exchange mode.

Validation economics:
- During implementation, use the narrowest high-signal test that can change the next decision; do not repeatedly run the full suite while the candidate is still changing.
- Do not add tests for trivial/compiler-guaranteed behavior or duplicate an already stronger behavioral proof.
- Race/fuzz/repeated stress/cross-compile/privileged E2E are risk-triggered, not default rituals.
- Once a Go candidate is stable, run the required acceptance gate once: `test -z "$(gofmt -l .)"`, `go vet ./...`, `go test ./...`, then exact-candidate CI. Re-run only evidence invalidated by later changes.

Privileged/network tests run only in disposable namespaces/environments and must preserve the AI Server Agent control plane.

Use Issues for unresolved work, ADRs for lasting decisions, and code/tests for implementation truth. Do not create chat-dependent handoff state.
