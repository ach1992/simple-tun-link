package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type receiptSpoofRetirer struct {
	store state.Store
	calls int
	fail  bool
}

func (r *receiptSpoofRetirer) RetireAfterRemove(ctx context.Context, link domain.Link) error {
	r.calls++
	s, err := r.store.Load(ctx)
	if err != nil {
		return err
	}
	v, ok := s.FindSpoofRemovalReceipt(link.ID)
	if !ok || v.Link != link {
		return errors.New("refuse foreign or inexact original")
	}
	if r.fail {
		return errors.New("injected interrupted quarantine")
	}
	return r.store.Update(ctx, func(current *state.Snapshot) error {
		for i := range current.SpoofRemovalReceipts {
			if current.SpoofRemovalReceipts[i].Link == link {
				current.SpoofRemovalReceipts[i].Retired = true
				return nil
			}
		}
		return errors.New("receipt disappeared")
	})
}

func TestSpoofCommittedRemovalReceiptRetryAndIdempotence(t *testing.T) {
	engine, store := newEngine(t, newFakeBackend())
	ctx := context.Background()
	link := provisioningSpoofLink(t, "original", "10.57.1.1/32", "10.57.1.2/32")
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.SpoofRemovalReceipts = append(s.SpoofRemovalReceipts, state.SpoofRemovalReceipt{Link: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	retirer := &receiptSpoofRetirer{store: store, fail: true}
	engine.SetSpoofRetirementStore(retirer)
	if err := engine.RetireSpoofCredential(ctx, link.ID); err == nil || !strings.Contains(err.Error(), "injected interrupted") {
		t.Fatalf("expected original in-progress error: %v", err)
	}
	snapshot, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, ok := snapshot.FindSpoofRemovalReceipt(link.ID); !ok || receipt.Retired {
		t.Fatal("incomplete cleanup falsely marked Retired")
	}
	retirer.fail = false
	if err := engine.RetireSpoofCredential(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	if err := engine.RetireSpoofCredential(ctx, link.ID); err != nil || retirer.calls != 2 {
		t.Fatalf("repeat retire should be a no-op after durable proof; calls=%d err=%v", retirer.calls, err)
	}
	snapshot, _ = store.Load(ctx)
	receipt, _ := snapshot.FindSpoofRemovalReceipt(link.ID)
	if !receipt.Retired {
		t.Fatal("successful retirement receipt not persisted")
	}
}

func TestSpoofRetirementRejectsAbsentActiveAndInexactReceipt(t *testing.T) {
	engine, store := newEngine(t, newFakeBackend())
	ctx := context.Background()
	link := provisioningSpoofLink(t, "owned", "10.57.1.1/32", "10.57.1.2/32")
	retirer := &receiptSpoofRetirer{store: store}
	engine.SetSpoofRetirementStore(retirer)
	if err := engine.RetireSpoofCredential(ctx, link.ID); err == nil {
		t.Fatal("unreceipted retirement accepted")
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.SpoofRemovalReceipts = append(s.SpoofRemovalReceipts, state.SpoofRemovalReceipt{Link: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := engine.RetireSpoofCredential(ctx, "lnk_1234567890abcdef1234567890abcdef"); err == nil {
		t.Fatal("foreign ID must not select an unrelated receipt")
	}
	if retirer.calls != 0 {
		t.Fatal("unproven original was ever sent to material store")
	}
}
