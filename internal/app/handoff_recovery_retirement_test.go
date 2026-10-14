package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// This test store deliberately returns a legacy persisted state that predates
// the cross-backend validation fix. Production FileStore now rejects it on
// Load, but the Engine must also refuse the conflicting tombstone itself.
type legacyRetiredSenderStore struct {
	snapshot state.Snapshot
}

func (s *legacyRetiredSenderStore) Load(context.Context) (state.Snapshot, error) {
	return s.snapshot, nil
}

func (*legacyRetiredSenderStore) Update(context.Context, func(*state.Snapshot) error) error {
	return errors.New("unexpected write during recovery")
}

type recoveryPublicKeyOnly struct {
	key     string
	checked bool
}

func (*recoveryPublicKeyOnly) PutRecipient(domain.LinkID, []byte, string) error {
	return errors.New("unexpected new private key")
}

func (k *recoveryPublicKeyOnly) LocalPublicIdentity(domain.LinkID) (string, error) {
	k.checked = true
	return k.key, nil
}

func TestRecoverPendingSenderRejectsIPsecRemovalReceiptBeforePublishing(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "unretired"
		if retired {
			name = "retired"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			registry, err := backend.NewRegistry()
			if err != nil {
				t.Fatal(err)
			}
			link := wireGuardReviewLink(t, "legacy-overlap", "10.98.1.0/31", "10.98.1.1/31")
			digest := strings.Repeat("a", 64)
			snapshot := state.EmptySnapshot()
			snapshot.PendingSenders = []state.PendingSender{{Link: link, HandoffSHA256: digest}}
			snapshot.IPsecRemovalReceipts = []state.IPsecRemovalReceipt{{
				LinkID: link.ID, PSKSHA256: strings.Repeat("b", 64), Retired: retired,
			}}
			store := &legacyRetiredSenderStore{snapshot: snapshot}
			e, err := New(registry, store, state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			keys := &recoveryPublicKeyOnly{key: link.WireGuard.LocalPublicKey}
			published := false
			err = e.RecoverWireGuardSenderHandoff(context.Background(), link, digest, keys, func() error {
				published = true
				return nil
			})
			if stlerr.CodeOf(err) != stlerr.CodeConflict || published || keys.checked {
				t.Fatalf("cross-backend retired Link ID allowed SENSITIVE recovery: %v published=%v inspected-key=%v",
					err, published, keys.checked)
			}
			if _, err = e.ResumeWireGuardSender(context.Background(), link, digest, keys); stlerr.CodeOf(err) != stlerr.CodeConflict {
				t.Fatalf("IPsec retirement did not block exact WireGuard Resume: %v", err)
			}
			if keys.checked {
				t.Fatal("retired identity reached protected credential inspection")
			}
			if store.snapshot.PendingSenders[0].Link != link ||
				store.snapshot.IPsecRemovalReceipts[0].Retired != retired {
				t.Fatal("legacy conflicting snapshot was modified by rejected recovery")
			}
		})
	}
}
