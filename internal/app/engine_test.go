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
	lastOwned      []domain.ResourceClaim
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
	b.mu.Lock()
	b.lastOwned = append([]domain.ResourceClaim(nil), req.OwnedResources...)
	b.mu.Unlock()
	obs := observed.(fakeObservation)
	claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: req.Link.DisplayName}
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

func TestEnsureUpdateCarriesPriorOwnershipAndKeepsStableID(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	link := linkFor(t, "stl-old", "10.80.22.0/31", "10.80.22.1/31")

	if _, err := engine.Ensure(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	updated := link
	updated.DisplayName = "stl-new"
	result, err := engine.Ensure(context.Background(), updated)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.LinkID != link.ID {
		t.Fatalf("update result = %#v, want changed with stable ID %s", result, link.ID)
	}

	b.mu.Lock()
	lastOwned := append([]domain.ResourceClaim(nil), b.lastOwned...)
	b.mu.Unlock()
	if len(lastOwned) != 1 || lastOwned[0].Kind != domain.ResourceInterface || lastOwned[0].Key != "stl-old" {
		t.Fatalf("backend prior ownership = %#v, want prior interface stl-old", lastOwned)
	}

	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, ok := snapshot.Find(link.ID)
	if !ok || record.Desired.DisplayName != "stl-new" {
		t.Fatalf("updated desired state not committed: %#v", record)
	}
	if len(record.OwnedResources) != 1 || record.OwnedResources[0].Key != "stl-new" {
		t.Fatalf("updated ownership not committed: %#v", record.OwnedResources)
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

func TestRejectResourceConflictsDetectsOverlappingLinkNetworks(t *testing.T) {
	first := linkFor(t, "stl-net-a", "10.80.50.0/31", "10.80.50.1/31")
	second := linkFor(t, "stl-net-b", "10.80.51.0/31", "10.80.51.1/31")
	snapshot := state.EmptySnapshot()
	snapshot.Upsert(state.LinkRecord{
		Desired: first,
		OwnedResources: []domain.ResourceClaim{{
			Kind: domain.ResourceLinkSubnet,
			Key:  "10.80.50.0/30",
		}},
	})

	err := rejectResourceConflicts(snapshot, second.ID, []domain.ResourceClaim{{
		Kind: domain.ResourceLinkAddress,
		Key:  "10.80.50.2",
	}})
	if stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("err = %v, code = %q, want conflict", err, stlerr.CodeOf(err))
	}
}

func TestResourceLockClaimsCoordinateOverlappingAddressSpace(t *testing.T) {
	subnetLocks, err := resourceLockClaims([]domain.ResourceClaim{{
		Kind: domain.ResourceLinkSubnet,
		Key:  "10.80.60.0/30",
	}})
	if err != nil {
		t.Fatal(err)
	}
	addressLocks, err := resourceLockClaims([]domain.ResourceClaim{{
		Kind: domain.ResourceLinkAddress,
		Key:  "10.80.60.2",
	}})
	if err != nil {
		t.Fatal(err)
	}

	want := domain.ResourceClaim{Kind: "stl-address-space", Key: "ipv4"}.Canonical()
	if !hasCanonicalClaim(subnetLocks, want) || !hasCanonicalClaim(addressLocks, want) {
		t.Fatalf("overlapping address resources do not share the core allocation lock: subnet=%#v address=%#v", subnetLocks, addressLocks)
	}
}

func TestValidatedClaimsRejectsCoreReservedKinds(t *testing.T) {
	_, err := validatedClaims([]domain.ResourceClaim{{Kind: "stl-address-space", Key: "ipv4"}})
	if err == nil {
		t.Fatal("expected core-reserved resource kind to be rejected")
	}
}

func hasCanonicalClaim(claims []domain.ResourceClaim, canonical string) bool {
	for _, claim := range claims {
		if claim.Canonical() == canonical {
			return true
		}
	}
	return false
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

type gateBeforeLinkLock struct {
	delegate Locker
	linkID   domain.LinkID
	entered  chan struct{}
	proceed  chan struct{}
}

func (g *gateBeforeLinkLock) Acquire(ctx context.Context, claims []domain.ResourceClaim) (func() error, error) {
	if len(claims) == 1 && claims[0] == linkLock(g.linkID) {
		close(g.entered)
		select {
		case <-g.proceed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g.delegate.Acquire(ctx, claims)
}

// The reviewer-identified race happens after the operator has confirmed A
// but before Remove acquires the Link lock. Force Ensure(B) to win that
// interleaving deterministically; the conditional Remove must fail before
// invoking the backend, without affecting another same-peer Link.
func TestRemoveIfUnchangedRejectsConcurrentReconfigurationAfterConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	root := t.TempDir()
	b := newFakeBackend()
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	normal, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	first := linkFor(t, "preview-old", "10.80.30.0/31", "10.80.30.1/31")
	sibling := linkFor(t, "sibling-stays", "10.80.31.0/31", "10.80.31.1/31")
	for _, link := range []domain.Link{first, sibling} {
		if _, err := normal.Ensure(ctx, link); err != nil {
			t.Fatal(err)
		}
	}
	gate := &gateBeforeLinkLock{
		delegate: state.NewLockManager(root), linkID: first.ID,
		entered: make(chan struct{}), proceed: make(chan struct{}),
	}
	conditional, err := New(registry, store, gate)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := conditional.RemoveIfUnchanged(ctx, first)
		done <- outcome{result, err}
	}()
	select {
	case <-gate.entered:
		// The removal is confirmed/submitted but not allowed to lock.
	case <-ctx.Done():
		t.Fatal("conditional removal never reached the Link-lock boundary")
	}

	updated := first
	updated.DisplayName = "preview-changed"
	if result, err := normal.Ensure(ctx, updated); err != nil || !result.Changed {
		t.Fatalf("competing same-ID Ensure did not win before removal: %+v %v", result, err)
	}
	close(gate.proceed)
	select {
	case got := <-done:
		if stlerr.CodeOf(got.err) != stlerr.CodeConflict || got.result != (Result{}) {
			t.Fatalf("stale confirmed Remove must reject before backend work: %+v %v", got.result, got.err)
		}
	case <-ctx.Done():
		t.Fatal("conditional Remove deadlocked on the same-Link lock")
	}
	visible, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := visible.Find(first.ID)
	other, okSibling := visible.Find(sibling.ID)
	if !ok || !okSibling || record.Desired != updated || other.Desired != sibling {
		t.Fatal("stale removal lost reconfigured or unrelated desired Link")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.applyCount != 3 || len(b.present) != 2 {
		t.Fatalf("conditional removal touched backend state: applyCount=%d present=%d", b.applyCount, len(b.present))
	}
}
