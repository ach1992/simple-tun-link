package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// A digest is intentionally impossible in this path: only exact
// descriptor-proven absence and durable non-secret receipt state count.
func TestRetireIPsecAlreadyAbsentPSKUsesNoFabricatedDigest(t *testing.T) {
	for _, stage := range []string{"clean-absent", "symlink-reappears", "untrusted-file-reappears", "incomplete-retirement"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			root := filepath.Join(t.TempDir(), "owner")
			e, st, keys := stageEngineAtRoot(t, root)
			e.SetIPsecRetirementStore(keys)
			link := stagedIPsecLink("lnk_56565656565656565656565656565656", "10.84.50.0/31")
			if err := keys.PutNew(link.ID, []byte("0123456789abcdef0123456789abcdef")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := st.Update(ctx, func(s *state.Snapshot) error {
				s.IPsecRemovalReceipts = append(s.IPsecRemovalReceipts, state.IPsecRemovalReceipt{LinkID: link.ID, VerifiedAbsent: true})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if stage == "symlink-reappears" {
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "untrusted-file-reappears" {
				if err := os.WriteFile(path, []byte("FOREIGN-PRIVATE-MATERIAL"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "incomplete-retirement" {
				if err := os.Chmod(filepath.Join(root, "credentials"), 0o777); err != nil {
					t.Fatal(err)
				}
			}
			err := e.RetireIPsecCredential(ctx, link.ID)
			shouldSucceed := stage == "clean-absent"
			if (err == nil) != shouldSucceed {
				t.Fatalf("absent receipt improperly finalized or rejected: %v", err)
			}
			after, err := st.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			receipt, ok := after.FindIPsecRemovalReceipt(link.ID)
			if !ok || receipt.PSKSHA256 != "" || !receipt.VerifiedAbsent || receipt.Retired != shouldSucceed {
				t.Fatalf("receipt mutated or invented digest: %+v", receipt)
			}
			if shouldSucceed {
				if err = e.RetireIPsecCredential(ctx, link.ID); err != nil {
					t.Fatal("idempotent receipt retry", err)
				}
				if err = keys.VerifyAbsent(link.ID); err != nil {
					t.Fatal("successful retirement created PSK", err)
				}
			} else if stage == "symlink-reappears" || stage == "untrusted-file-reappears" {
				if _, err = os.Lstat(path); err != nil {
					t.Fatal("retirement deleted foreign credential", err)
				}
			}
		})
	}
}

type deferredIPsecAbsentReceiptStore struct {
	state.Store
	failMarkerOnce bool
}

func (s *deferredIPsecAbsentReceiptStore) Update(ctx context.Context, modify func(*state.Snapshot) error) error {
	if s.failMarkerOnce {
		current, err := s.Store.Load(ctx)
		if err != nil {
			return err
		}
		if err := modify(&current); err != nil {
			return err
		}
		if len(current.IPsecRemovalReceipts) == 1 && current.IPsecRemovalReceipts[0].Retired {
			s.failMarkerOnce = false
			return errors.New("test-only interrupted retirement marker persistence")
		}
	}
	return s.Store.Update(ctx, modify)
}
func TestIPsecAbsentReceiptInterruptedRetirementMarkerIsRetryable(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "owner")
	e, st, keys := stageEngineAtRoot(t, root)
	e.SetIPsecRetirementStore(keys)
	link := stagedIPsecLink("lnk_57575757575757575757575757575757", "10.84.52.0/31")
	if err := keys.PutNew(link.ID, []byte(strings.Repeat("B", 32))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(ctx, func(s *state.Snapshot) error {
		s.IPsecRemovalReceipts = append(s.IPsecRemovalReceipts, state.IPsecRemovalReceipt{LinkID: link.ID, VerifiedAbsent: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.store = &deferredIPsecAbsentReceiptStore{Store: st, failMarkerOnce: true}
	if err := e.RetireIPsecCredential(ctx, link.ID); err == nil {
		t.Fatal("interrupted state marker accepted")
	}
	snap, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := snap.FindIPsecRemovalReceipt(link.ID)
	if proof.Retired || !proof.VerifiedAbsent {
		t.Fatal("failed marker wrote false durable success")
	}
	if err := e.RetireIPsecCredential(ctx, link.ID); err != nil {
		t.Fatal("no-effect retirement retry failed", err)
	}
	snap, err = st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ = snap.FindIPsecRemovalReceipt(link.ID)
	if !proof.Retired || proof.PSKSHA256 != "" {
		t.Fatal("retry lost exact absence proof")
	}
}

func TestIPsecAbsentReceiptCannotOverlapCommittedOrPending(t *testing.T) {
	root := filepath.Join(t.TempDir(), "owner")
	_, st, _ := stageEngineAtRoot(t, root)
	link := stagedIPsecLink("lnk_58585858585858585858585858585858", "10.84.54.0/31")
	if err := st.Update(context.Background(), func(s *state.Snapshot) error {
		s.IPsecRemovalReceipts = append(s.IPsecRemovalReceipts, state.IPsecRemovalReceipt{LinkID: link.ID, VerifiedAbsent: true})
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err == nil {
		t.Fatal("absent retirement accepted while Link committed")
	}
}

// Keep this import to assert the protected PSK API contract remains the
// same for all other users of the store, not a synthetic Digest sentinel.
var _ interface{ VerifyAbsent(domain.LinkID) error } = (*ipsec.PSKStore)(nil)
