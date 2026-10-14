package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Delegates to the real protected PSK store, while proving that an invalid
// retired identity never reaches *either* credential API, even for replay.
type ipsecStageCredentialCalls struct {
	keys         *ipsec.PSKStore
	putCalls     int
	requireCalls int
}

func (s *ipsecStageCredentialCalls) PutNew(id domain.LinkID, raw []byte) error {
	s.putCalls++
	return s.keys.PutNew(id, raw)
}

func (s *ipsecStageCredentialCalls) RequireExistingExact(id domain.LinkID, raw []byte) error {
	s.requireCalls++
	return s.keys.RequireExistingExact(id, raw)
}

func TestIPsecStageSenderAndRecipientRefuseSameIDRetirementBeforeAnyPSK(t *testing.T) {
	for _, origin := range []string{"sender", "recipient"} {
		for _, retired := range []bool{false, true} {
			name := origin + "_not_retired"
			if retired {
				name = origin + "_retired"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				root := filepath.Join(t.TempDir(), "protected-root")
				engine, store, realKeys := stageEngineAtRoot(t, root)
				keys := &ipsecStageCredentialCalls{keys: realKeys}
				link := stagedIPsecLink("lnk_99999999999999999999999999999999", "10.84.42.0/31")
				secret := bytes.Repeat([]byte{0x7b}, 32)
				receiptDigest := sha256.Sum256([]byte("independent-test-PSK-retirement"))
				receipt := state.IPsecRemovalReceipt{
					LinkID: link.ID, PSKSHA256: hex.EncodeToString(receiptDigest[:]), Retired: retired,
				}
				if err := store.Update(ctx, func(snapshot *state.Snapshot) error {
					snapshot.IPsecRemovalReceipts = append(snapshot.IPsecRemovalReceipts, receipt)
					return nil
				}); err != nil {
					t.Fatal("could not establish valid durable retirement receipt:", err)
				}
				before := mustState(t, store)
				offer := offerForStage(t, link, secret)
				defer offer.ClearRecipientCredential()
				encoded, err := offer.EncodeSetupLink()
				if err != nil {
					t.Fatal(err)
				}
				published := 0
				if origin == "sender" {
					err = engine.StageIPsecSender(ctx, offer, keys, func(url string) error {
						published++
						return errors.New("SENSITIVE source must not reach publisher: " + url)
					})
				} else {
					err = engine.StageIPsecRecipient(ctx, encoded, confirmIPsecURL(encoded), keys)
				}
				if stlerr.CodeOf(err) != stlerr.CodeConflict {
					t.Fatalf("retired IPsec sender/recipient was not rejected as an identity conflict: %v", err)
				}
				if err == nil || strings.Contains(err.Error(), encoded) ||
					strings.Contains(err.Error(), "SENSITIVE source") ||
					strings.Contains(err.Error(), hex.EncodeToString(secret)) {
					t.Fatalf("conflict error disclosed original Quick Link or PSK")
				}
				if published != 0 || keys.putCalls != 0 || keys.requireCalls != 0 {
					t.Fatalf("retired identity reached SENSITIVE publication/credential API: published=%d put=%d require=%d",
						published, keys.putCalls, keys.requireCalls)
				}
				privateKey := filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")
				if _, err := os.Lstat(privateKey); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("retired identity generated an orphan PSK: %v", err)
				}
				if _, err := realKeys.Load(link.ID); err == nil {
					t.Fatal("retired identity persisted protected PSK material")
				}
				after := mustState(t, store)
				if !reflect.DeepEqual(after, before) || len(after.Links) != 0 ||
					len(after.PendingIPsec) != 0 || len(after.PendingSenders) != 0 ||
					len(after.IPsecRemovalReceipts) != 1 ||
					after.IPsecRemovalReceipts[0] != receipt {
					t.Fatalf("retired identity changed canonical state or retirement receipt: %+v", after)
				}
				// No backend is registered in stageEngineAtRoot. Even in
				// valid staging, the Engine may not apply VICI/XFRM/host
				// resources; a rejected stage has no state or key effects.
			})
		}
	}
}

// The first snapshot is valid when a stage begins. An injected intervening
// persisted retirement claim tests the *second* check inside Update:
// it must refuse appending IPsec pending intent rather than relying on the
// Store's final validator to catch the conflicting state too late.
type ipsecStageLateReceiptStore struct {
	state.Store
	receipt         state.IPsecRemovalReceipt
	checked         bool
	mutatorRejected bool
	unsafeAppended  bool
}

func (s *ipsecStageLateReceiptStore) Update(ctx context.Context, mutate func(*state.Snapshot) error) error {
	snapshot, err := s.Store.Load(ctx)
	if err != nil {
		return err
	}
	snapshot.IPsecRemovalReceipts = append(snapshot.IPsecRemovalReceipts, s.receipt)
	before := len(snapshot.PendingIPsec)
	err = mutate(&snapshot)
	s.checked = true
	s.mutatorRejected = err != nil
	s.unsafeAppended = len(snapshot.PendingIPsec) != before
	if s.unsafeAppended {
		return errors.New("unsafe pending IPsec appended over an intervening retirement")
	}
	return err
}

func TestIPsecStageRechecksRetirementInsideAtomicStateMutation(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "protected-root")
	engine, store, realKeys := stageEngineAtRoot(t, root)
	link := stagedIPsecLink("lnk_88888888888888888888888888888888", "10.84.44.0/31")
	digest := sha256.Sum256([]byte("late-cross-backend-retirement"))
	lateStore := &ipsecStageLateReceiptStore{Store: store, receipt: state.IPsecRemovalReceipt{
		LinkID: link.ID, PSKSHA256: hex.EncodeToString(digest[:]), Retired: true,
	}}
	engine.store = lateStore
	offer := offerForStage(t, link, bytes.Repeat([]byte{0x59}, 32))
	defer offer.ClearRecipientCredential()
	published := false
	err := engine.StageIPsecSender(ctx, offer, realKeys, func(string) error {
		published = true
		return nil
	})
	if stlerr.CodeOf(err) != stlerr.CodeState || !lateStore.checked ||
		!lateStore.mutatorRejected || lateStore.unsafeAppended || published {
		t.Fatalf("state mutation didn't reject newly observed retirement before handoff: %v checked=%v published=%v",
			err, lateStore.checked, published)
	}
	if len(mustState(t, store).PendingIPsec) != 0 {
		t.Fatal("injected late receipt allowed durable IPsec pending state")
	}
	// In an impossible-to-coordinate external state race the protected key
	// may already be staged; consistent with existing protocol it is retained
	// for explicit reconciliation, never automatically deleted or disclosed.
}
