// Package quicwgkey stages the first protected native WG credential for the
// source-only QUIC journal. It shares the existing native WireGuard KeyStore
// rather than introducing a second secret store or Link owner.
package quicwgkey

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/app"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// StageInitial publishes only the first private WG key for an unresolved
// Engine-owned QUIC journal. The original journal public identity is checked
// before any write. Existing matching keys are NOT adopted or overwritten.
// The caller must zeroize its own in-memory key after use.
//
// Staging creates no host/network effect. Any failed or uncertain file
// publication leaves the journal and possible protected key quarantined;
// the returned result never authorizes automatic cleanup, replay or recovery.
func StageInitial(ctx context.Context, engine *app.Engine,
	id domain.LinkID, key wgbackend.PrivateKey) error {
	if engine == nil {
		return fmt.Errorf("canonical QUIC Engine required for private key staging")
	}
	public, err := key.PublicKey()
	if err != nil {
		return fmt.Errorf("invalid private WireGuard credential")
	}
	return engine.WithQUICCrashWireGuardKeyAdmission(ctx, id, public, func(root, expectedPublic string) error {
		store, err := wgbackend.NewKeyStore(root)
		if err != nil {
			return err
		}
		if err := store.PutNew(id, key); err != nil {
			return err // Engine redacts filesystem/credential error details
		}
		file, err := store.OpenForWireGuard(id, expectedPublic)
		if err != nil {
			return err
		}
		return file.Close()
	})
}

// InspectJournalKey is read-only: it verifies current private file mode,
// ownership, canonical descriptor and derived public key against the immutable
// QUIC journal. It is not a first-creation receipt or kernel ownership proof.
func InspectJournalKey(ctx context.Context, engine *app.Engine, id domain.LinkID) error {
	if engine == nil {
		return fmt.Errorf("canonical QUIC Engine required for private key inspection")
	}
	return engine.WithQUICCrashWireGuardKeyObservation(ctx, id, func(root, expectedPublic string) error {
		store, err := wgbackend.NewKeyStore(root)
		if err != nil {
			return err
		}
		file, err := store.OpenForWireGuard(id, expectedPublic)
		if err != nil {
			return err
		}
		return file.Close()
	})
}
