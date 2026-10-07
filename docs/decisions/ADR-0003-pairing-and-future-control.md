# ADR-0003: Versioned setup links, manual fallback, and future control-plane compatibility

- Status: Accepted
- Date: 2026-10-07

## Context

Manual copy blocks are understandable but become error-prone as paired settings grow. A future panel/agent should also configure the same link engine without introducing a second tunnel implementation.

## Decision

Provide:
- interactive/manual setup;
- a versioned stl:// setup-link format;
- a human-readable configuration block generated from the same internal pairing model;
- import preview and strict validation before apply;
- non-interactive CLI operations with JSON output.

A setup link is data, never executable content.

Secret-bearing backends must preserve local private-key ownership where practical. If a one-shot link contains a credential, the link is explicitly sensitive. Exact quick-vs-secure exchange UX remains implementation work, not permission to weaken secret handling silently.

Do not build a daemon or panel in v0.1. Preserve clean engine boundaries and stable Link identity so a future local agent/control plane can reuse them.

## Consequences

Pairing reduces mismatched peer settings without making chat/manual memory authoritative.

The future panel can consume one implementation rather than recreate backend logic.

Versioned formats require compatibility tests and explicit migration behavior.
