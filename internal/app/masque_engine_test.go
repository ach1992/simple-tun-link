package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	masqueb "github.com/ach1992/simple-tun-link/internal/backend/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type managedMASQUEFakeHost struct {
	value     masqueb.HostObservation
	starts    int
	stops     int
	failStart bool
	failStop  bool
}

func (h *managedMASQUEFakeHost) Inspect(context.Context, domain.Link) (masqueb.HostObservation, error) {
	return h.value, nil
}
func (h *managedMASQUEFakeHost) Preflight(context.Context, domain.Link, bool) error { return nil }
func (h *managedMASQUEFakeHost) Start(_ context.Context, link domain.Link) (core.Rollback, error) {
	h.starts++
	before := h.value
	h.value = masqueb.HostObservation{
		UnitExists: true, UnitOwned: true, UnitActive: true,
		InterfaceExists: true, InterfaceOwned: true, InterfaceIndex: 11,
		LocalAddress: link.Addresses.Local, PeerRoute: true, RuntimeReady: true,
	}
	undo := func(context.Context) error { h.value = before; return nil }
	if h.failStart {
		return undo, errors.New("simulated failure after exact unit was started")
	}
	return undo, nil
}
func (h *managedMASQUEFakeHost) Stop(context.Context, domain.Link) (core.Rollback, error) {
	h.stops++
	before := h.value
	h.value = masqueb.HostObservation{}
	undo := func(context.Context) error { h.value = before; return nil }
	if h.failStop {
		return nil, core.ErrIndeterminateHostEffect
	}
	return undo, nil
}

type managedMASQUERetirer struct{ calls int }

func (r *managedMASQUERetirer) RetireMatching(context.Context, domain.Link) error {
	r.calls++
	return nil
}

func testMASQUEDesired() domain.Link {
	return domain.Link{
		ID:      "lnk_f0123456789abcde01f0123456789abc",
		Backend: domain.BackendMASQUE, Encapsulation: domain.EncapTLS,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("2a10:ed40::1"), Peer: netip.MustParseAddr("2a01:4f8::2"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.252.97.2/32"),
			Peer:  netip.MustParsePrefix("10.252.97.1/32"),
		},
		MASQUE: domain.MASQUEOptions{
			Role: "dial", TCPPort: 38443, TLSServerName: "masque.test",
			MaterialSHA256: strings.Repeat("d", 64),
		},
	}
}

func testMASQUEEngine(t *testing.T, root string, h *managedMASQUEFakeHost, r *managedMASQUERetirer) (*Engine, *state.FileStore) {
	t.Helper()
	b, err := masqueb.New(h)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := core.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	engine, err := New(reg, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMASQUERetirementStore(r)
	return engine, store
}

func TestMASQUEEngineEndToEndStateAndExactRetirement(t *testing.T) {
	ctx := context.Background()
	host := &managedMASQUEFakeHost{}
	retirer := &managedMASQUERetirer{}
	engine, store := testMASQUEEngine(t, t.TempDir(), host, retirer)
	link := testMASQUEDesired()
	if link.Validate() != nil {
		t.Fatal("invalid test Link")
	}
	count := 0
	res, err := engine.EnsureWithMASQUEProvision(ctx, link, func() error { count++; return nil }, nil)
	if err != nil || !res.Changed || host.starts != 1 || count != 1 {
		t.Fatalf("MASQUE original Ensure failed: %v %+v", err, res)
	}
	doc, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	saved, exists := doc.Find(link.ID)
	if !exists || len(doc.MASQUEOperations) != 0 || len(saved.MASQUELastEffectNonce) != 64 {
		t.Fatalf("MASQUE journal did not commit atomically: %+v", doc)
	}
	// Repeated Ensure must not spawn another service or advance the original
	// generation. It must not re-issue credentials.
	res, err = engine.Ensure(ctx, link)
	if err != nil || res.Changed || host.starts != 1 {
		t.Fatalf("MASQUE duplicate Ensure not idempotent: %v %+v", err, res)
	}
	if _, err = engine.Remove(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	doc, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, exists := doc.FindMASQUERemovalReceipt(link.ID)
	if !exists || !receipt.Retired || receipt.Purpose != "removed" || len(doc.Links) != 0 || len(doc.MASQUEOperations) != 0 ||
		host.stops != 1 || retirer.calls != 1 {
		t.Fatalf("MASQUE committed Remove/retirement not atomic: %+v %+v", doc, host)
	}
	if _, err := engine.Ensure(ctx, link); err == nil {
		t.Fatal("reused an already-retired MASQUE original identity")
	}
}

func TestMASQUEEngineCrashJournalRecoveryNeverAdoptsHost(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &managedMASQUEFakeHost{failStart: true}
	retirer := &managedMASQUERetirer{}
	engine, store := testMASQUEEngine(t, root, host, retirer)
	link := testMASQUEDesired()
	_, err := engine.EnsureWithMASQUEProvision(ctx, link, func() error { return nil }, nil)
	if err == nil {
		t.Fatal("simulated host creation failure reported success")
	}
	snap, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, pending := snap.FindMASQUEOperation(link.ID); !pending || len(snap.Links) != 0 {
		t.Fatalf("pre-effect journal missing after failed mutation: %+v", snap)
	}
	restarted, _ := testMASQUEEngine(t, root, host, retirer)
	host.value = masqueb.HostObservation{UnitExists: true, UnitOwned: false}
	if _, err := restarted.ReconcileMASQUE(ctx, link.ID); err == nil {
		t.Fatal("reconciliation adopted a foreign service")
	}
	host.value = masqueb.HostObservation{}
	rec, err := restarted.ReconcileMASQUE(ctx, link.ID)
	if err != nil || rec.Recovery != "abandoned_uncommitted" || !rec.OriginalRetired {
		t.Fatalf("MASQUE absent original reconcile failed: %v %+v", err, rec)
	}
	doc, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, exists := doc.FindMASQUERemovalReceipt(link.ID)
	if !exists || !receipt.Retired || receipt.Purpose != "abandoned" || len(doc.MASQUEOperations) != 0 {
		t.Fatalf("MASQUE failed original not durably tombstoned: %+v", doc)
	}
	if _, err := restarted.Ensure(ctx, link); err == nil {
		t.Fatal("reused abandoned original identity")
	}
}

func TestMASQUEEngineRecoveryOfInterruptedRemove(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &managedMASQUEFakeHost{}
	retirer := &managedMASQUERetirer{}
	engine, store := testMASQUEEngine(t, root, host, retirer)
	link := testMASQUEDesired()
	if _, err := engine.EnsureWithMASQUEProvision(ctx, link, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	host.failStop = true
	if _, err := engine.Remove(ctx, link.ID); err == nil {
		t.Fatal("uncertain stop was reported successful")
	}
	doc, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.MASQUEOperations) != 1 || len(doc.Links) != 1 {
		t.Fatal("interrupted Remove lost committed Link or pre-effect journal")
	}
	restarted, _ := testMASQUEEngine(t, root, host, retirer)
	recovered, err := restarted.ReconcileMASQUE(ctx, link.ID)
	if err != nil || !recovered.CommittedRemoved || !recovered.OriginalRetired {
		t.Fatalf("interrupted Remove exact recovery failed: %+v %v", recovered, err)
	}
	doc, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Links) != 0 || len(doc.MASQUEOperations) != 0 {
		t.Fatal("failed durable MASQUE Remove recovery")
	}
}
