package app

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// The guard must execute after acquisition of the SAME Link lock used by
// Ensure/Remove. A CLI-side preflight would leave a stale-check window.
type importLockSignal struct {
	underlying Locker
	target     domain.ResourceClaim
	entered    chan struct{}
}

func (l *importLockSignal) Acquire(ctx context.Context, claims []domain.ResourceClaim) (func() error, error) {
	if len(claims) == 1 && claims[0] == l.target {
		select {
		case l.entered <- struct{}{}:
		default:
		}
	}
	return l.underlying.Acquire(ctx, claims)
}

func TestEnsureImportedGuardsNewSameAndDifferentDesiredState(t *testing.T) {
	ctx := context.Background()
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	incoming := linkFor(t, "receiver-a", "10.81.20.0/31", "10.81.20.1/31")
	sibling := linkFor(t, "receiver-b", "10.81.22.0/31", "10.81.22.1/31")

	first, err := engine.EnsureImported(ctx, incoming)
	if err != nil || !first.Changed {
		t.Fatalf("new Link import must use Engine: %+v %v", first, err)
	}
	second, err := engine.EnsureImported(ctx, incoming)
	if err != nil || second.Changed {
		t.Fatalf("identical repeat import must be idempotent: %+v %v", second, err)
	}
	if _, err := engine.EnsureImported(ctx, sibling); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	priorApplies := b.applyCount
	b.mu.Unlock()

	changed := incoming
	changed.DisplayName = "untrusted-preview-name-do-not-echo"
	changed.Underlay.Peer = sibling.Underlay.Peer.Next()
	_, err = engine.EnsureImported(ctx, changed)
	if stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("changed existing Link ID must conflict before backend action: %v", err)
	}
	if err == nil || contains(err.Error(), changed.DisplayName) {
		t.Fatal("conflict must not include untrusted display text")
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("conflicting import altered any saved Link or claims: %+v %v", after, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.applyCount != priorApplies || len(b.present) != 2 {
		t.Fatalf("conflicting import touched backend or sibling: applies=%d present=%+v", b.applyCount, b.present)
	}
}

func TestEnsureImportedChecksConflictAfterLinkLockNotBefore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	incoming := linkFor(t, "incoming", "10.81.24.0/31", "10.81.24.1/31")
	existing := incoming
	existing.DisplayName = "already-committed"

	underlying := engine.locks
	release, err := underlying.Acquire(ctx, []domain.ResourceClaim{linkLock(incoming.ID)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if release != nil {
			_ = release()
		}
	}()
	engine.locks = &importLockSignal{
		underlying: underlying,
		target:     linkLock(incoming.ID),
		entered:    make(chan struct{}, 1),
	}
	done := make(chan error, 1)
	go func() {
		_, importErr := engine.EnsureImported(ctx, incoming)
		done <- importErr
	}()

	// Deterministic scheduling point: importer reached the shared Link lock,
	// but cannot inspect committed state while our test holds that lock.
	select {
	case <-engine.locks.(*importLockSignal).entered:
	case <-ctx.Done():
		t.Fatal("import never reached Link lock")
	}
	if err := store.Update(ctx, func(snapshot *state.Snapshot) error {
		snapshot.Upsert(state.LinkRecord{Desired: existing})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release = nil
	select {
	case err := <-done:
		if stlerr.CodeOf(err) != stlerr.CodeConflict {
			t.Fatalf("import lost interleaved new desired state: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("import remained blocked after releasing Link lock")
	}
	actual, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := actual.Find(incoming.ID)
	if !ok || record.Desired != existing || b.applyCount != 0 {
		t.Fatalf("import bypassed committed-state guard: record=%+v applied=%d", record, b.applyCount)
	}
}
