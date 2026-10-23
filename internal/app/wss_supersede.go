package app

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// SupersedeWSSOriginal is a durable, owner-confirmed LOGICAL transition.
// The caller must independently verify its new peer before invoking it.
// It deliberately does not inspect, stop, delete, retire, or adopt the old
// kernel WG/helper/guard or credentials, nor switch external application routes.
// The old original remains committed and its resource reservations persist.
func (e *Engine) SupersedeWSSOriginal(ctx context.Context, oldID, replacementID domain.LinkID) (bool, error) {
	if oldID.Validate() != nil || replacementID.Validate() != nil || oldID == replacementID {
		return false, stlerr.New(stlerr.CodeInvalid, "wss_supersede", string(oldID),
			"wireguard-wss", "original and replacement must be distinct valid Link IDs")
	}
	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "wss_supersede", string(oldID),
			"wireguard-wss", "maintenance gate unavailable; no State update attempted", err)
	}
	defer maintenanceRelease()
	// Serialize against original Ensure/Remove/Restore and new Link
	// provisioning/replacement. The file-store's atomic lock is an
	// additional authoritative serialization boundary.
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(oldID), linkLock(replacementID)})
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "wss_supersede", string(oldID),
			"wireguard-wss", "cannot lock exact original and replacement IDs", err)
	}
	defer release()

	before, err := e.store.Load(ctx)
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "wss_supersede", string(oldID),
			"wireguard-wss", "cannot read protected WSS owner State", err)
	}
	old, found := before.Find(oldID)
	if !found || old.Desired.Backend != domain.BackendWireGuardWSS {
		return false, stlerr.New(stlerr.CodeConflict, "wss_supersede", string(oldID),
			"wireguard-wss", "original is not a committed WSS Link")
	}
	if old.WSSSupersededBy != "" {
		if old.WSSSupersededBy != replacementID {
			return false, stlerr.New(stlerr.CodeConflict, "wss_supersede", string(oldID),
				"wireguard-wss", "original is already superseded; changing its successor is forbidden")
		}
		// A visible marker is not evidence of a durable one: a prior
		// rename can succeed while the subsequent directory fsync fails.
		// Re-publish the unchanged, freshly checked snapshot under the
		// canonical Store lock before confirming an idempotent retry.
		if err := e.store.Update(ctx, func(s *state.Snapshot) error {
			current, exists := s.Find(oldID)
			if !exists || !reflect.DeepEqual(current, old) {
				return fmt.Errorf("superseded original State changed before durability confirmation")
			}
			return nil
		}); err != nil {
			return false, stlerr.Wrap(stlerr.CodeState, "wss_supersede", string(oldID),
				"wireguard-wss", "existing supersession marker durability unconfirmed; retry without changing old resources", err)
		}
		return false, nil // idempotent, now durably confirmed; no host effects
	}
	next, found := before.Find(replacementID)
	if !found || next.Desired.Backend != domain.BackendWireGuardWSS ||
		next.WSSSupersededBy != "" {
		return false, stlerr.New(stlerr.CodeConflict, "wss_supersede", string(replacementID),
			"wireguard-wss", "independent replacement is not a normal committed WSS Link")
	}
	if _, pending := before.FindWSSCrashOperation(replacementID); pending {
		return false, stlerr.New(stlerr.CodeConflict, "wss_supersede", string(replacementID),
			"wireguard-wss", "replacement has an unresolved crash journal, not a proven committed outcome")
	}
	if !independentWSSReplacement(old, next) {
		return false, stlerr.New(stlerr.CodeConflict, "wss_supersede", string(replacementID),
			"wireguard-wss", "replacement is not independent of original WSS identity or resource claims")
	}
	err = e.store.Update(ctx, func(s *state.Snapshot) error {
		current, exists := s.Find(oldID)
		successor, nextExists := s.Find(replacementID)
		if !exists || !nextExists || !reflect.DeepEqual(current, old) ||
			!reflect.DeepEqual(successor, next) {
			return fmt.Errorf("original/replacement owner State changed before durable supersession")
		}
		if _, pending := s.FindWSSCrashOperation(replacementID); pending {
			return fmt.Errorf("replacement acquired an unresolved WSS journal before supersession")
		}
		current.WSSSupersededBy = replacementID
		s.Upsert(current)
		return nil
	})
	if err != nil {
		// A post-rename durability failure can leave the marker visible but
		// unconfirmed. Never claim a completed outcome on write error.
		return false, stlerr.Wrap(stlerr.CodeState, "wss_supersede", string(oldID),
			"wireguard-wss", "logical supersession State publication not durably confirmed; reload protected State", err)
	}
	return true, nil
}

// Checks only persisted, freshly serialized claims/issuance. This is not
// peer reachability, historical kernel extinction or credential retirement.
// An absent resource reservation is NOT evidence that the host is vacant.
func independentWSSReplacement(old, next state.LinkRecord) bool {
	a, b := old.Desired, next.Desired
	if a.Backend != domain.BackendWireGuardWSS || b.Backend != domain.BackendWireGuardWSS ||
		a.ID == b.ID || a.WSS.Role != b.WSS.Role ||
		a.WireGuard.LocalPublicKey == b.WireGuard.LocalPublicKey ||
		a.WireGuard.LocalPublicKey == b.WireGuard.PeerPublicKey ||
		a.WireGuard.PeerPublicKey == b.WireGuard.LocalPublicKey ||
		a.WireGuard.PeerPublicKey == b.WireGuard.PeerPublicKey ||
		a.WireGuard.ListenPort == b.WireGuard.ListenPort ||
		a.WireGuard.PeerPort == b.WireGuard.PeerPort ||
		old.WSSOrigin == next.WSSOrigin ||
		a.WSS.TCPPort == b.WSS.TCPPort ||
		a.Addresses.Local.Masked().Contains(b.Addresses.Local.Addr()) ||
		b.Addresses.Local.Masked().Contains(a.Addresses.Local.Addr()) ||
		old.WSSFiles == next.WSSFiles ||
		old.WSSFiles.Certificate == next.WSSFiles.Certificate ||
		old.WSSFiles.TLSKey == next.WSSFiles.TLSKey ||
		old.WSSFiles.TrustCA == next.WSSFiles.TrustCA ||
		old.WSSFiles.Authorization == next.WSSFiles.Authorization ||
		len(old.OwnedResources) == 0 || len(next.OwnedResources) == 0 {
		return false
	}
	// Use the same semantic exclusion rule as Engine provisioning: CIDR
	// reservations can overlap even if their canonical strings differ.
	for _, original := range old.OwnedResources {
		for _, candidate := range next.OwnedResources {
			conflict, err := domain.ResourceClaimsConflict(original, candidate)
			if err != nil || conflict {
				return false
			}
		}
	}
	return true
}
