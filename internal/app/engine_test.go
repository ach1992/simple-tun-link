package app

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type fakeObservation struct {
	present   bool
	resources []domain.ResourceClaim
}

func (o fakeObservation) ObservedResources() []domain.ResourceClaim { return o.resources }

type fakePlan struct {
	empty     bool
	resources []domain.ResourceClaim
}

func (p fakePlan) Empty() bool                       { return p.empty }
func (p fakePlan) Resources() []domain.ResourceClaim { return p.resources }

type fakeBackend struct {
	mu             sync.Mutex
	present        map[domain.LinkID][]domain.ResourceClaim
	applyCount     int
	rollbackCount  int
	failVerifyOnce bool
	applyDelay     time.Duration
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{present: make(map[domain.LinkID][]domain.ResourceClaim)}
}

func (b *fakeBackend) Kind() domain.Backend { return domain.BackendGRE }

func (b *fakeBackend) Inspect(_ context.Context, link domain.Link) (backend.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	resources, ok := b.present[link.ID]
	return fakeObservation{present: ok, resources: append([]domain.ResourceClaim(nil), resources...)}, nil
}

func (b *fakeBackend) Plan(_ context.Context, req backend.Request, observed backend.Observation) (backend.Plan, error) {
	obs := observed.(fakeObservation)
	claim := domain.ResourceClaim{Kind: "interface", Key: req.Link.DisplayName}
	if req.Operation == backend.OperationRemove {
		return fakePlan{empty: !obs.present}, nil
	}
	resources := []domain.ResourceClaim{claim}
	return fakePlan{empty: obs.present && sameClaims(obs.resources, resources), resources: resources}, nil
}

func (b *fakeBackend) Validate(context.Context, backend.Request, backend.Observation, backend.Plan) error {
	return nil
}

func (b *fakeBackend) Apply(_ context.Context, req backend.Request, _ backend.Observation, plan backend.Plan) (backend.Rollback, error) {
	if b.applyDelay > 0 {
		time.Sleep(b.applyDelay)
	}
	b.mu.Lock()
	before, existed := b.present[req.Link.ID]
	beforeCopy := append([]domain.ResourceClaim(nil), before...)
	if req.Operation == backend.OperationRemove {
		delete(b.present, req.Link.ID)
	} else {
		b.present[req.Link.ID] = append([]domain.ResourceClaim(nil), plan.Resources()...)
	}
	b.applyCount++
	b.mu.Unlock()

	return func(context.Context) error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if existed {
			b.present[req.Link.ID] = beforeCopy
		} else {
			delete(b.present, req.Link.ID)
		}
		b.rollbackCount++
		return nil
	}, nil
}

func (b *fakeBackend) Verify(_ context.Context, req backend.Request) (backend.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failVerifyOnce {
		b.failVerifyOnce = false
		return nil, errors.New("private_key=DO-NOT-LEAK")
	}
	resources, exists := b.present[req.Link.ID]
	if req.Operation == backend.OperationRemove && exists {
		return nil, errors.New("still present")
	}
	if req.Operation == backend.OperationEnsure && !exists {
		return nil, errors.New("not present")
	}
	return fakeObservation{present: exists, resources: append([]domain.ResourceClaim(nil), resources...)}, nil
}

func newEngine(t *testing.T, b *fakeBackend) (*Engine, *state.FileStore) {
	t.Helper()
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	return engine, store
}

func linkFor(t *testing.T, name, local, peer string) domain.Link {
	t.Helper()
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	return domain.Link{
		ID:          id,
		DisplayName: name,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix(local),
			Peer:  netip.MustParsePrefix(peer),
		},
		Backend:       domain.BackendGRE,
		Encapsulation: domain.EncapNative,
	}
}

func TestEnsureIsIdempotentAndPersistsDesiredSeparatelyFromObserved(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	link := linkFor(t, "stl0", "10.80.20.0/31", "10.80.20.1/31")

	first, err := engine.Ensure(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed {
		t.Fatal("first Ensure should change observed state")
	}
	second, err := engine.Ensure(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Fatal("second Ensure should be idempotent")
	}
	if b.applyCount != 1 {
		t.Fatalf("applyCount = %d, want 1", b.applyCount)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, ok := snapshot.Find(link.ID)
	if !ok || record.Desired.ID != link.ID {
		t.Fatal("desired Link was not committed")
	}
}

func TestEnsureRollbackOnVerifyFailureAndErrorIsSecretSafe(t *testing.T) {
	b := newFakeBackend()
	b.failVerifyOnce = true
	engine, store := newEngine(t, b)
	link := linkFor(t, "stl1", "10.80.21.0/31", "10.80.21.1/31")

	_, err := engine.Ensure(context.Background(), link)
	if err == nil {
		t.Fatal("expected verify failure")
	}
	if stlerr.CodeOf(err) != stlerr.CodeVerify {
		t.Fatalf("code = %q, want %q", stlerr.CodeOf(err), stlerr.CodeVerify)
	}
	if got := err.Error(); contains(got, "DO-NOT-LEAK") {
		t.Fatalf("public error leaked backend cause: %q", got)
	}
	if b.rollbackCount != 1 {
		t.Fatalf("rollbackCount = %d, want 1", b.rollbackCount)
	}
	b.mu.Lock()
	_, present := b.present[link.ID]
	b.mu.Unlock()
	if present {
		t.Fatal("backend state remained after rollback")
	}
	snapshot, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, ok := snapshot.Find(link.ID); ok {
		t.Fatal("failed Ensure was committed to state")
	}
}

func TestMultipleSamePeerLinksRemainIndependent(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	first := linkFor(t, "stl-a", "10.80.30.0/31", "10.80.30.1/31")
	second := linkFor(t, "stl-b", "10.80.31.0/31", "10.80.31.1/31")

	if _, err := engine.Ensure(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ensure(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Links) != 2 {
		t.Fatalf("len(Links) = %d, want 2", len(snapshot.Links))
	}
	if _, err := engine.Remove(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Links) != 1 || snapshot.Links[0].Desired.ID != second.ID {
		t.Fatalf("removing one Link disturbed sibling state: %#v", snapshot.Links)
	}
}

func TestConcurrentLinksCannotClaimSameResource(t *testing.T) {
	b := newFakeBackend()
	b.applyDelay = 75 * time.Millisecond
	engine, _ := newEngine(t, b)
	first := linkFor(t, "shared-if", "10.80.40.0/31", "10.80.40.1/31")
	second := linkFor(t, "shared-if", "10.80.41.0/31", "10.80.41.1/31")

	start := make(chan struct{})
	errCh := make(chan error, 2)
	for _, link := range []domain.Link{first, second} {
		link := link
		go func() {
			<-start
			_, err := engine.Ensure(context.Background(), link)
			errCh <- err
		}()
	}
	close(start)

	var successes, conflicts int
	for i := 0; i < 2; i++ {
		err := <-errCh
		if err == nil {
			successes++
			continue
		}
		if stlerr.CodeOf(err) == stlerr.CodeConflict {
			conflicts++
			continue
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
}

func sameClaims(a, b []domain.ResourceClaim) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
