package app

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// SenderKeyStore contains exactly the protected own-key operations needed by
// the canonical sender transaction. The receiver secret remains ONLY in the
// caller's explicitly SENSITIVE handoff, never in durable sender state.
type SenderKeyStore interface {
	PutRecipient(domain.LinkID, []byte, string) error
	LocalPublicIdentity(domain.LinkID) (string, error)
}

func validSenderDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

// CreateWireGuardSender guarantees the order: canonical maintenance/Link lock
// -> no existing ID/pending -> durable own key -> durable public+digest pending
// -> SENSITIVE handoff publication -> backend Apply/Verify -> atomic commit of
// desired Link AND consumption of the pending transaction.
// No handoff callback can run before recoverable sender material is durable.
// A failure before handoff publication may leave a protected orphan key or
// public reservation for explicit operator reconciliation; such a state is
// NEVER advertised as recoverable unless the exact handoff is accessible.
func (e *Engine) CreateWireGuardSender(ctx context.Context, desired domain.Link, ownSecret []byte, digest string,
	keys SenderKeyStore, publish func() error) (Result, error) {
	if keys == nil || publish == nil || !validSenderDigest(digest) || desired.Validate() != nil ||
		desired.Backend != domain.BackendWireGuard || desired.Encapsulation != domain.EncapUDP ||
		desired.WireGuard.ListenPort == 0 || desired.WireGuard.PeerPort == 0 ||
		!desired.Underlay.Local.Is4() || !desired.Underlay.Peer.Is4() {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "create_wireguard", string(desired.ID), "", "invalid protected sender transaction")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "", "maintenance lock unavailable", err)
	}
	defer release()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(desired.ID)})
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "", "Link ownership lock unavailable", err)
	}
	defer linkRelease()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "", "cannot load saved Link identities", err)
	}
	if _, committed := snapshot.Find(desired.ID); committed {
		return Result{}, stlerr.New(stlerr.CodeConflict, "create_wireguard", string(desired.ID), "", "Link ID already committed; sender Create cannot replace its identity")
	}
	if _, pending := snapshot.FindPendingSender(desired.ID); pending {
		return Result{}, stlerr.New(stlerr.CodeConflict, "create_wireguard", string(desired.ID), "", "another sender transaction owns this Link ID; reconcile its pending handoff")
	}
	if _, ready := e.backends.Get(desired.Backend); !ready {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "create_wireguard", string(desired.ID), "", "WireGuard backend unavailable")
	}
	// Explicitly no-clobber. If a previous private key is an orphan, preserve
	// it and refuse publishing an unrelated second receiver offer for that ID.
	if err = keys.PutRecipient(desired.ID, ownSecret, desired.WireGuard.LocalPublicKey); err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "", "sender private key unavailable/conflicting; no handoff published", err)
	}
	// Durably publish public intent and the EXACT secret-bearing URL digest.
	// This is also the same-ID reservation for all concurrent STL operations.
	if err = e.store.Update(ctx, func(s *state.Snapshot) error {
		if _, exists := s.Find(desired.ID); exists {
			return fmt.Errorf("Link became committed during sender staging")
		}
		if _, exists := s.FindPendingSender(desired.ID); exists {
			return fmt.Errorf("sender staging already reserved this ID")
		}
		s.DeleteRemovalReceipt(desired.ID)
		s.PendingSenders = append(s.PendingSenders, state.PendingSender{Link: desired, HandoffSHA256: digest})
		return nil
	}); err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "",
			"sender pending intent not durably confirmed; no handoff publication attempted", err)
	}
	if err = ctx.Err(); err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "",
			"sender identity staged but interrupted before SENSITIVE handoff publication", err)
	}
	if err = publish(); err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "",
			"sender key and exact pending intent durable; handoff publication failed or uncertain; inspect destination before exact Resume", err)
	}
	if err = ctx.Err(); err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "create_wireguard", string(desired.ID), "",
			"handoff published with durable sender recovery, but activation interrupted", err)
	}
	// e.executeLocked is the common backend/ownership/rollback pipeline and
	// must run with the Link lock already held. Its successful state commit
	// consumes the EXACT pending intent in the same atomic state update.
	return e.executeLocked(ctx, backend.Request{Operation: backend.OperationEnsure, Link: desired}, state.LinkRecord{}, digest)
}

// ResumeWireGuardSender never creates or replaces sender private keys. A
// pre-commit retry MUST match the saved original URL digest and whole public
// desired Link. After commit has consumed pending, identical committed Link
// state authorizes idempotent verification/repair (never new uncommitted ID).
func (e *Engine) ResumeWireGuardSender(ctx context.Context, desired domain.Link, digest string, keys SenderKeyStore) (Result, error) {
	if keys == nil || !validSenderDigest(digest) || desired.Validate() != nil ||
		desired.Backend != domain.BackendWireGuard || desired.Encapsulation != domain.EncapUDP ||
		desired.WireGuard.ListenPort == 0 || desired.WireGuard.PeerPort == 0 {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "resume_wireguard", string(desired.ID), "", "invalid exact sender Resume")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "resume_wireguard", string(desired.ID), "", "maintenance lock unavailable", err)
	}
	defer release()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(desired.ID)})
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "resume_wireguard", string(desired.ID), "", "Link ownership lock unavailable", err)
	}
	defer linkRelease()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "resume_wireguard", string(desired.ID), "", "cannot load durable sender recovery state", err)
	}
	pending, hasPending := snapshot.FindPendingSender(desired.ID)
	committed, hasCommitted := snapshot.Find(desired.ID)
	if hasPending {
		if pending.Link != desired || pending.HandoffSHA256 != digest || hasCommitted {
			return Result{}, stlerr.New(stlerr.CodeConflict, "resume_wireguard", string(desired.ID), "", "handoff does not match the exact reserved sender intent")
		}
	} else if !hasCommitted || committed.Desired != desired {
		return Result{}, stlerr.New(stlerr.CodeConflict, "resume_wireguard", string(desired.ID), "", "no exact pending or committed sender Link to resume")
	}
	if _, removed := snapshot.FindRemovalReceipt(desired.ID); removed {
		return Result{}, stlerr.New(stlerr.CodeConflict, "resume_wireguard", string(desired.ID), "", "Link has been durably removed; Resume cannot resurrect it")
	}
	public, err := keys.LocalPublicIdentity(desired.ID)
	if err != nil || public != desired.WireGuard.LocalPublicKey {
		return Result{}, stlerr.New(stlerr.CodeConflict, "resume_wireguard", string(desired.ID), "", "protected sender key missing or not bound to staged public identity")
	}
	var prior *domain.Link
	if hasCommitted {
		previous := committed.Desired
		prior = &previous
	}
	return e.executeLocked(ctx, backend.Request{Operation: backend.OperationEnsure, Prior: prior, Link: desired}, committed, digest)
}
