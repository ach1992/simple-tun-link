package app

import (
	"context"
	"errors"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type engineMTUStub struct {
	current, calls, undos int
}

func (m *engineMTUStub) Apply(_ context.Context, req backend.Request, _ bool, _ []domain.ResourceClaim) (backend.Rollback, bool, error) {
	if req.Link.MTU.Mode == domain.MTUUnmanaged {
		return nil, false, errors.New("unmanaged MTU incorrectly passed to writer")
	}
	next := req.Link.MTU.Bytes
	if req.Link.MTU.Mode == domain.MTUAuto {
		next = 1280
	}
	m.calls++
	if m.current == next {
		return nil, false, nil
	}
	previous := m.current
	m.current = next
	return func(context.Context) error { m.undos++; m.current = previous; return nil }, true, nil
}

func TestManagedMTUUpdateAndRestoreUseTheSameEngine(t *testing.T) {
	ctx := context.Background()
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	mtu := &engineMTUStub{current: 1500}
	engine.SetMTUManager(mtu)
	link := linkFor(t, "mtu0", "10.90.70.0/31", "10.90.70.1/31")
	// Old/legacy policy remains unmanaged even when a manager is registered.
	if _, err := engine.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	if mtu.calls != 0 || mtu.current != 1500 {
		t.Fatal("legacy Link MTU modified")
	}

	updated := link
	updated.MTU = domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1380}
	result, err := engine.Ensure(ctx, updated)
	if err != nil || !result.Changed || mtu.current != 1380 || b.applyCount != 1 {
		t.Fatalf("managed-only change should not recreate tunnel: %+v %v mtu=%d backendCalls=%d", result, err, mtu.current, b.applyCount)
	}
	repeat, err := engine.Ensure(ctx, updated)
	if err != nil || repeat.Changed || mtu.current != 1380 {
		t.Fatalf("idempotent MTU reapply: %+v %v", repeat, err)
	}
	// A legacy v1 automation payload with the MTU field absent must not
	// silently drop a previously committed managed policy.
	legacy := updated
	legacy.MTU = domain.MTUPolicy{}
	legacyResult, err := engine.Ensure(ctx, legacy)
	if err != nil || legacyResult.Changed || mtu.current != 1380 {
		t.Fatalf("legacy ensure unexpectedly changed managed Link: %+v %v", legacyResult, err)
	}
	preserved, err := store.Load(ctx)
	previous, exists := preserved.Find(link.ID)
	if err != nil || !exists || previous.Desired.MTU != updated.MTU {
		t.Fatalf("legacy desired input wiped persistent local MTU: %+v %v", previous, err)
	}
	// A late backend Verify failure must revert only the managed MTU delta,
	// and retain the last committed desired policy.
	b.failVerifyOnce = true
	newPolicy := updated
	newPolicy.MTU.Bytes = 1320
	if _, err := engine.Ensure(ctx, newPolicy); err == nil {
		t.Fatal("expected failure")
	}
	if mtu.current != 1380 || mtu.undos != 1 {
		t.Fatalf("managed MTU rollback lost prior state: current=%d undos=%d", mtu.current, mtu.undos)
	}
	saved, err := store.Load(ctx)
	record, _ := saved.Find(link.ID)
	if err != nil || record.Desired != updated {
		t.Fatalf("failed MTU update committed state: %+v %v", record, err)
	}
	// Simulate reboot: kernel Link and MTU disappear but persisted committed
	// desired Link remains. Restore must recreate the Link and reapply MTU.
	delete(b.present, link.ID)
	mtu.current = 1500
	if _, err := engine.RestoreAll(ctx); err != nil || mtu.current != 1380 || b.applyCount != 2 {
		t.Fatalf("managed MTU did not restore committed Link: err=%v mtu=%d backendCalls=%d", err, mtu.current, b.applyCount)
	}
}

func TestManagedMTUFailsClosedWithoutWriterAndRollsBackNewBackend(t *testing.T) {
	ctx := context.Background()
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	link := linkFor(t, "no_mtu_writer", "10.90.80.0/31", "10.90.80.1/31")
	link.MTU = domain.MTUPolicy{Mode: domain.MTUAuto}
	if _, err := engine.Ensure(ctx, link); err == nil {
		t.Fatal("managed Link committed without any Engine MTU implementation")
	}
	if b.rollbackCount != 1 {
		t.Fatalf("failed managed Link did not roll back backend: %d", b.rollbackCount)
	}
	saved, err := store.Load(ctx)
	if err != nil || len(saved.Links) != 0 {
		t.Fatalf("managed Link persisted without MTU: %v %+v", err, saved.Links)
	}
}

// Versioned v2 can explicitly opt out of MTU management. Unlike a missing
// legacy field, it is a durable policy transition, not a host-device write.
func TestManagedMTUExplicitUnmanagedIsDurableWithoutHostMutation(t *testing.T) {
	ctx := context.Background()
	b := newFakeBackend()
	e, store := newEngine(t, b)
	m := &engineMTUStub{current: 1500}
	e.SetMTUManager(m)
	link := linkFor(t, "mtu_optout", "10.90.90.0/31", "10.90.90.1/31")
	link.MTU = domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1340}
	if _, err := e.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	request := link
	request.MTU = domain.MTUPolicy{Mode: domain.MTUUnmanagedExplicit}
	result, err := e.Ensure(ctx, request)
	if err != nil || result.Changed || m.current != 1340 {
		t.Fatalf("unmanaged opt-out changed host: %+v %v", result, err)
	}
	after, err := store.Load(ctx)
	rec, _ := after.Find(link.ID)
	if err != nil || rec.Desired.MTU != request.MTU {
		t.Fatalf("unmanaged not durable: %+v %v", rec, err)
	}
}
