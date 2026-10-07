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
- No geography-specific data-model roles.
- No global host tuning merely for convenience.
- No firewall flush/default-route rewrite.
- No swallowed correctness errors or unconditional success messages.
- Operations must become idempotent and rollback owned partial state.
- Multi-Link is first-class: support 0..N Links per host, including multiple independent Links to the same peer pair when the backend/kernel can distinguish them.
- Never assume one Link per host, peer, or backend; allocate collision-safe per-Link resources and keep create/update/repair/remove isolated from other Links.
- Interactive UI must not own engine logic.
- Preserve standalone use plus generic reuse by arbitrary external software without designing STL around any specific future product.
- Never make interactive text an automation API; machine-readable outputs are versioned and secret-safe, and desired-state automation is idempotent.
- v0.1 secret-bearing pairing defaults to Quick Link: payloads are SENSITIVE, may carry receiver credentials, must never leak into ordinary logs/status/diagnostics, and must remain schema-extensible for a future secure/local-key exchange mode.

Validation for ordinary Go changes:

~~~bash
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
~~~

Privileged/network tests run only in disposable namespaces/environments and must preserve the AI Server Agent control plane.

Use Issues for unresolved work, ADRs for lasting decisions, and code/tests for implementation truth. Do not create chat-dependent handoff state.
