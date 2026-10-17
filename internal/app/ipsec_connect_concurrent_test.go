package app

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type lockedConcurrentIPsecConnectFake struct {
	*fakeBackend
	active        atomic.Int32
	initiated     atomic.Int32
	saEstablished atomic.Bool
}

func (*lockedConcurrentIPsecConnectFake) Kind() domain.Backend { return domain.BackendIPsec }

func (f *lockedConcurrentIPsecConnectFake) Connect(ctx context.Context, link domain.Link, claims []domain.ResourceClaim) error {
	if link.Backend != domain.BackendIPsec || len(claims) != 1 || claims[0].Key != link.DisplayName {
		return errors.New("invalid scoped committed Connect")
	}
	if f.active.Add(1) != 1 {
		f.active.Add(-1)
		return errors.New("Engine admitted simultaneous Connect under same Link/resource locks")
	}
	defer f.active.Add(-1)
	// A peer or first caller may install the matching SA while other
	// operators are still waiting for canonical Engine locks.
	time.Sleep(18 * time.Millisecond)
	if f.saEstablished.CompareAndSwap(false, true) {
		f.initiated.Add(1)
	}
	return nil
}

func TestConcurrentCanonicalEngineConnectOnlyInitiatesOnce(t *testing.T) {
	for _, initialSA := range []bool{false, true} {
		tag := "initial SA missing"
		if initialSA {
			tag = "peer SA appeared before locked Connect"
		}
		t.Run(tag, func(t *testing.T) {
			b := &lockedConcurrentIPsecConnectFake{fakeBackend: newFakeBackend()}
			b.saEstablished.Store(initialSA)
			registry, err := backend.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			store := state.NewFileStore(root)
			e, err := New(registry, store, state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			link := linkFor(t, "one-specific-IPsec-peer", "10.200.10.0/31", "10.200.10.1/31")
			link.Backend, link.Encapsulation = domain.BackendIPsec, domain.EncapESP
			link.Underlay.Local = netip.MustParseAddr("192.0.2.10")
			link.Underlay.Peer = netip.MustParseAddr("192.0.2.20")
			claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: link.DisplayName}
			if err := store.Update(context.Background(), func(s *state.Snapshot) error {
				s.Upsert(state.LinkRecord{Desired: link, OwnedResources: []domain.ResourceClaim{claim}})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			errs := make(chan error, 12)
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					errs <- e.ConnectIPsec(context.Background(), link.ID)
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("concurrent canonical Connect rejected or overlapped: %v", err)
				}
			}
			want := int32(1)
			if initialSA {
				want = 0
			}
			if b.initiated.Load() != want || b.active.Load() != 0 {
				t.Fatalf("multiple IKE initiations despite verified SA: started=%d", b.initiated.Load())
			}
			after, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			row, exists := after.Find(link.ID)
			if !exists || row.Desired != link || len(row.OwnedResources) != 1 || row.OwnedResources[0] != claim {
				t.Fatal("concurrent Connect mutated committed Link or ownership")
			}
		})
	}
}
