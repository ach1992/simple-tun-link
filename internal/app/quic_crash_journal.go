package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// PrepareQUICCrash is a SOURCE-ONLY, non-runnable first journal publication
// for a NEW proposed QUIC/WG Link. The supplied complete public binding must
// come from a previously validated quic.Plan.HostPlan and anticipated
// credential/config/executable fingerprints. This function generates the
// transaction nonce and exact native+carrier claims, rechecks the fresh host
// and State under maintenance -> Link -> resource locks, then acquires the
// shared restore-persistence lock to publish the durable pre-effect intent
// BEFORE any future writer may stage files or mutate Linux resources.
//
// No protected file is written, service installed, helper spawned, firewall
// configured, WG interface created, actual binary inspected, or credential
// attested here. This journal is quarantine, NOT proof of effect ownership.
// It is intentionally not consumed/cleared until a later separately reviewed
// exact-owned recovery and complete runtime transaction exists.
func (e *Engine) PrepareQUICCrash(ctx context.Context, intent state.QUICCrashOperation,
	host QUICHostCollisionInspector) (state.QUICCrashOperation, error) {
	const operation = "quic_prepare_crash"
	id := intent.Plan.Local.LinkID
	if intent.Nonce != "" || len(intent.Resources) != 0 {
		return state.QUICCrashOperation{}, stlerr.New(stlerr.CodeInvalid, operation, string(id), "quic",
			"QUIC pre-effect nonce and canonical resource claims are Engine-owned")
	}
	if err := intent.Plan.Validate(); err != nil {
		return state.QUICCrashOperation{}, stlerr.New(stlerr.CodeInvalid, operation, string(id), "quic",
			"incomplete physical/role/TLS QUIC pre-effect Plan")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return state.QUICCrashOperation{}, stlerr.New(stlerr.CodeState, operation, string(id), "quic",
			"cannot allocate protected QUIC transaction nonce")
	}
	intent.Nonce = hex.EncodeToString(nonce[:])
	provider := QUICWireGuardProvider{Addresses: intent.Addresses, WireGuard: intent.WireGuard}
	_, err := e.checkQUICPreparation(ctx, intent.Plan.Local, provider, host,
		func(claims []domain.ResourceClaim) error {
			intent.Resources = append([]domain.ResourceClaim(nil), claims...)
			if err := intent.Validate(); err != nil {
				return stlerr.New(stlerr.CodeInvalid, operation, string(id), "quic",
					"incomplete canonical QUIC pre-effect identity or fingerprint binding")
			}
			// The shared restore unit must not be retired between the final
			// State check and this journal publication. Take its existing lock
			// AFTER Link/resource locks, matching ordinary Remove and RestoreAll.
			releaseRestore, lockErr := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
			if lockErr != nil {
				return stlerr.New(stlerr.CodeState, operation, string(id), "quic",
					"cannot serialize QUIC journal with restore persistence")
			}
			defer releaseRestore()
			// FileStore.Update is a serialized durable state publication; a
			// concurrent state writer outside the initial snapshot still cannot
			// bypass the exact post-lock recheck before the journal is appended.
			err := e.store.Update(ctx, func(s *state.Snapshot) error {
				if quicLinkIdentityReserved(*s, id) {
					return fmt.Errorf("QUIC Link identity reserved before journal publication")
				}
				if err := rejectResourceConflicts(*s, id, claims); err != nil {
					return err
				}
				if quicConflictsWithSharedIPsecPorts(*s, claims) {
					return fmt.Errorf("shared IPsec daemon UDP identity reserved")
				}
				s.QUICCrashOperations = append(s.QUICCrashOperations, intent)
				return nil
			})
			if err != nil {
				// Even a post-rename fsync failure may have published State.
				// Never roll back, delete or claim the journal absent.
				return stlerr.New(stlerr.CodeState, operation, string(id), "quic",
					"QUIC pre-effect journal durability is uncertain; no host effects attempted")
			}
			return nil
		})
	if err != nil {
		return state.QUICCrashOperation{}, err
	}
	return intent, nil
}
