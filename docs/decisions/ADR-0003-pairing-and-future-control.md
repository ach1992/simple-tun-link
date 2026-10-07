# ADR-0003: Versioned setup links, manual fallback, and future control-plane compatibility

- Status: Accepted
- Date: 2026-10-07

## Context

Manual copy blocks are understandable but become error-prone as paired settings grow. STL must also remain usable both as a standalone tool and as a reusable connectivity capability for arbitrary external software without introducing a second Link implementation.

## Decision

Provide:
- interactive/manual setup;
- a versioned stl:// setup-link format;
- a human-readable configuration block generated from the same internal pairing model;
- import preview and strict validation before apply;
- non-interactive CLI operations with versioned JSON output and deterministic exit semantics;
- an idempotent desired-state operation so external callers can ensure a Link without duplicating STL lifecycle logic.

A setup link is data, never executable content.

Secret-bearing setup payloads are explicitly sensitive. The exact default pairing mode is decided separately in ADR-0004; this ADR only requires the versioned format to carry the mode explicitly and remain extensible.

Do not build speculative integration infrastructure in v0.1. Preserve clean engine boundaries and stable Link identity so arbitrary external software can reuse STL through stable contracts while consumer-specific concepts remain outside STL.

## Consequences

Pairing reduces mismatched peer settings without making chat/manual memory authoritative.

External consumers can use one STL implementation rather than recreate Link/backend lifecycle logic.

Versioned formats require compatibility tests and explicit migration behavior.
