package app

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// BindAuthenticatedSpoofPeer is the canonical Engine-owned first-enrollment
// transaction, called only after the managed helper completes Noise XKpsk0
// using the original protected Link material. An already pinned public key
// can be confirmed idempotently but NEVER silently replaced.
func (e *Engine) BindAuthenticatedSpoofPeer(ctx context.Context, authenticated *spoof.Session) (bool, error) {
	id, localIdentity, identity, ok := authenticated.VerifiedPeerIdentity()
	if !ok {
		return false, errors.New("Spoof peer binding requires a completed authenticated Noise session")
	}
	linkID := domain.LinkID(id)
	releaseMaintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return false, fmt.Errorf("Spoof enrollment maintenance lock: %w", err)
	}
	defer releaseMaintenance()
	releaseLink, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(linkID)})
	if err != nil {
		return false, fmt.Errorf("Spoof enrollment Link lock: %w", err)
	}
	defer releaseLink()
	public := base64.RawURLEncoding.EncodeToString(identity[:])
	changed := false
	err = e.store.Update(ctx, func(snapshot *state.Snapshot) error {
		record, exists := snapshot.Find(linkID)
		if !exists || record.Desired.Backend != domain.BackendSpoof ||
			record.Desired.Spoof.Role != string(spoof.RoleCreator) {
			return errors.New("Spoof creator Link must be committed before peer enrollment")
		}
		local, err := base64.RawURLEncoding.Strict().DecodeString(record.Desired.Spoof.LocalPublicKey)
		if err != nil || subtle.ConstantTimeCompare(local, localIdentity[:]) != 1 {
			return errors.New("Spoof Noise session does not belong to this Link's original local private identity")
		}
		bound := record.Desired.Spoof.PeerPublicKey
		if bound != "" {
			previous, err := base64.RawURLEncoding.Strict().DecodeString(bound)
			if err != nil || subtle.ConstantTimeCompare(previous, identity[:]) != 1 {
				return errors.New("Spoof peer is already bound to a different identity; explicit revoke/new setup required")
			}
			return nil
		}
		record.Desired.Spoof.PeerPublicKey = public
		snapshot.Upsert(record)
		changed = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("Spoof authenticated peer enrollment: %w", err)
	}
	return changed, nil
}
