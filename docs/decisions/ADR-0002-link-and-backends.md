# ADR-0002: Stable Link abstraction with GRE default and multiple backends

- Status: Accepted
- Date: 2026-10-07

## Context

The product must create a private point-to-point IP that can be consumed by ordinary applications and future higher-level tunnels/backhauls. Provider/network behavior varies, so the underlay method cannot be hardcoded to one protocol.

## Decision

The primary object is a backend-neutral **Link** with stable local/peer Link Addresses.

Multi-Link operation is first-class in v0.1: a host can own 0..N independent Links, and the same two underlay endpoints may have multiple simultaneous Links using different backends or encapsulations. For example, A <-> B may concurrently run GRE Native, WireGuard, and GRE/FOU. No one-Link-per-host or one-Link-per-peer singleton is allowed in the domain model.

v0.1 backends:
- GRE — default;
- IPIP;
- WireGuard;
- IPsec/XFRM.

GRE and IPIP additionally support Native, FOU, and GUE encapsulations.

GRE Native is the default interactive selection.

IPsec uses strongSwan/IKEv2 with Linux XFRM interfaces as the primary model rather than carrying forward the older VTI-first workaround design.

VXLAN and Geneve are not v0.1 backends because the current problem is point-to-point L3 connectivity, not general L2/datacenter overlay networking.

Geographic labels are not part of the model. Use local/peer and, only where protocol behavior requires it, initiator/responder or listener/connector.

## Consequences

Higher-level consumers can keep using the same Link Address while backend selection changes.

Backend-specific state remains encapsulated behind a common lifecycle.

Each Link owns an independently identifiable resource set. Resource allocation and validation must prevent collisions, concurrent operations must not claim the same host resource, and deleting/repairing one Link must not disturb another. Backend-specific limitations may reject an ambiguous combination only when the underlying platform cannot safely distinguish it.

Adding methods increases test burden, so every new backend/encapsulation must prove a distinct operational use case rather than being added only because Linux supports it.
