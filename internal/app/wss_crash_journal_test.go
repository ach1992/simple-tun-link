package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type crashWSSBackend struct {
	*fakeBackend
	crashAfterHost         bool
	store                  *state.FileStore
	journalObservedAtApply bool
}

func (b *crashWSSBackend) Kind() domain.Backend { return domain.BackendWireGuardWSS }
func (b *crashWSSBackend) Plan(_ context.Context, req backend.Request, observed backend.Observation) (backend.Plan, error) {
	path, err := composition.Build(req.Link, composition.CarrierForLink(req.Link))
	if err != nil {
		return nil, err
	}
	link := req.Link
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.WireGuard.ListenPort))},
		{Kind: domain.ResourceFirewall, Key: "wss/nft/" + string(link.ID)},
	}
	claims = append(claims, path.CarrierClaims()...)
	if req.Operation == backend.OperationRemove {
		return fakePlan{empty: !observed.(fakeObservation).present, resources: claims}, nil
	}
	claims = append(claims,
		domain.ResourceClaim{Kind: domain.ResourceInterface, Key: "stlwg" + string(link.ID)[4:14]},
		domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
		domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + link.WireGuard.LocalPublicKey},
	)
	// Fake state observations preserve a deterministic resource order so
	// an idempotent committed Ensure does not generate a new journal.
	prior := observed.(fakeObservation)
	return fakePlan{empty: prior.present && sameClaims(prior.resources, claims), resources: claims}, nil
}
func (b *crashWSSBackend) Apply(ctx context.Context, req backend.Request, obs backend.Observation,
	p backend.Plan) (backend.Rollback, error) {
	if b.store != nil {
		snapshot, err := b.store.Load(ctx)
		if err != nil {
			return nil, err
		}
		op, ok := snapshot.FindWSSCrashOperation(req.Link.ID)
		if !ok || op.Operation != string(req.Operation) || len(op.Nonce) != 32 {
			return nil, errors.New("host Apply invoked without durable pre-effect WSS journal")
		}
		b.journalObservedAtApply = true
	}
	undo, err := b.fakeBackend.Apply(ctx, req, obs, p)
	if b.crashAfterHost {
		b.crashAfterHost = false
		panic("INJECTED_HARD_PROCESS_DEATH_AFTER_HOST_EFFECT")
	}
	return undo, err
}
func (b *crashWSSBackend) CrashHostVacant(_ context.Context, obs backend.Observation) (bool, error) {
	current := obs.(fakeObservation)
	return !current.present, nil
}
func journalTestLink(t *testing.T) domain.Link {
	t.Helper()
	local, peer := make([]byte, 32), make([]byte, 32)
	for i := 0; i < 32; i++ {
		local[i] = 1
		peer[i] = 2
	}
	return domain.Link{
		ID:          "lnk_0123456789abcdef0123456789abcdef",
		DisplayName: "wss-crash-resource",
		Backend:     domain.BackendWireGuardWSS, Encapsulation: domain.EncapUDP,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("198.51.100.21"),
			Peer:  netip.MustParseAddr("203.0.113.34")},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.93.0.1/30"),
			Peer:  netip.MustParsePrefix("10.93.0.2/30")},
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: base64.StdEncoding.EncodeToString(local),
			PeerPublicKey:  base64.StdEncoding.EncodeToString(peer),
			ListenPort:     51820, PeerPort: 51821},
		WSS: domain.WSSOptions{Role: "listen", TCPPort: 59443},
	}
}
func crashWSSEngine(t *testing.T, b *crashWSSBackend) (*Engine, *state.FileStore) {
	t.Helper()
	reg, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := New(reg, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	return engine, store
}
func causeCrash(t *testing.T, fn func()) {
	t.Helper()
	crashed := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				crashed = true
				if recovered != "INJECTED_HARD_PROCESS_DEATH_AFTER_HOST_EFFECT" {
					t.Fatalf("unexpected panic: %v", recovered)
				}
			}
		}()
		fn()
	}()
	if !crashed {
		t.Fatal("simulated host mutation crash did not occur")
	}
}
func TestWSSCrashJournalPersistedBeforeMutationAndFailClosed(t *testing.T) {
	ctx := context.Background()
	host := &crashWSSBackend{fakeBackend: newFakeBackend(), crashAfterHost: true}
	engine, store := crashWSSEngine(t, host)
	host.store = store
	link := journalTestLink(t)
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	causeCrash(t, func() { _, _ = engine.Ensure(ctx, link) })
	if !host.journalObservedAtApply {
		t.Fatal("backend Apply started without committed WSS journal")
	}
	saved, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	op, ok := saved.FindWSSCrashOperation(link.ID)
	if !ok || op.Intent != link || op.Operation != "ensure" || op.HadCommittedLink ||
		len(op.Resources) < 7 || len(op.Nonce) != 32 {
		t.Fatalf("missing durable, secret-free pre-effect WSS journal: %+v", op)
	}
	// Durable State is credential-free and fsynced to state.json before
	// the simulated hard crash; no private authentication material may leak.
	serialized, encodeErr := json.Marshal(saved)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if bytes.Contains(serialized, []byte("private_key")) || bytes.Contains(serialized, []byte("authorization-token")) {
		t.Fatal("crash State exposed secret material")
	}
	if _, ok := saved.Find(link.ID); ok {
		t.Fatal("interrupted WSS Ensure falsely committed Link")
	}
	_, err = engine.Ensure(ctx, link)
	if err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("replayed unresolved WSS host effects: %v", err)
	}
	if host.applyCount != 1 {
		t.Fatal("interrupted WSS operation was replayed")
	}
	if _, err := engine.RestoreAll(ctx); err == nil {
		t.Fatal("RestoreAll silently ignored unresolved crash journal")
	}
	if err := engine.ReconcileWSSCrashVacant(ctx, link.ID); err == nil {
		t.Fatal("journal cleared even though host resources remained")
	}
	if _, ok := (mustLoadCrashSnapshot(t, store)).FindWSSCrashOperation(link.ID); !ok {
		t.Fatal("journal removed while host mutation remained")
	}
	// Same resource identity is reserved for all other Links.
	sibling := link
	sibling.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sibling.Addresses.Local = netip.MustParsePrefix("10.94.0.1/30")
	sibling.Addresses.Peer = netip.MustParsePrefix("10.94.0.2/30")
	if _, err := engine.Ensure(ctx, sibling); err == nil {
		t.Fatal("different Link reused an unresolved WSS interface reservation")
	}
	// Model external *read-only corroborated* absence after a separately
	// authorized cleanup; Reconcile itself never calls backend Apply.
	delete(host.present, link.ID)
	if err := engine.ReconcileWSSCrashVacant(ctx, link.ID); err != nil {
		t.Fatalf("vacancy reconciliation: %v", err)
	}
	if _, ok := (mustLoadCrashSnapshot(t, store)).FindWSSCrashOperation(link.ID); ok {
		t.Fatal("verified vacant pre-effect WSS journal was not cleared")
	}
	if host.applyCount != 1 {
		t.Fatal("reconcile changed host resources")
	}
	if _, err := engine.Ensure(ctx, link); err != nil {
		t.Fatalf("exact retry after verified vacancy: %v", err)
	}
	final := mustLoadCrashSnapshot(t, store)
	if _, ok := final.FindWSSCrashOperation(link.ID); ok {
		t.Fatal("successful WSS State commit retained crash journal")
	}
	if _, ok := final.Find(link.ID); !ok {
		t.Fatal("successful WSS Link not committed")
	}
}
func mustLoadCrashSnapshot(t *testing.T, store *state.FileStore) state.Snapshot {
	t.Helper()
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWSSCommittedRemoveCrashRemainsQuarantined(t *testing.T) {
	ctx := context.Background()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	engine, store := crashWSSEngine(t, host)
	host.store = store
	link := journalTestLink(t)
	if _, err := engine.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	host.crashAfterHost = true
	causeCrash(t, func() { _, _ = engine.Remove(ctx, link.ID) })
	after := mustLoadCrashSnapshot(t, store)
	pending, exists := after.FindWSSCrashOperation(link.ID)
	if !exists || pending.Operation != "remove" || !pending.HadCommittedLink {
		t.Fatalf("committed WSS Remove lost recovery quarantine: %+v", pending)
	}
	if _, stillCommitted := after.Find(link.ID); !stillCommitted {
		t.Fatal("interrupted WSS Remove unexpectedly lost committed ownership")
	}
	if err := engine.ReconcileWSSCrashVacant(ctx, link.ID); err == nil {
		t.Fatal("vacancy-only reconciliation adopted committed Remove")
	}
	if _, err := engine.Remove(ctx, link.ID); err == nil {
		t.Fatal("interrupted Remove was automatically replayed")
	}
	if _, err := engine.Ensure(ctx, link); err == nil {
		t.Fatal("interrupted WSS Remove was silently reversed")
	}
	if host.applyCount != 2 {
		t.Fatal("WSS crash journal failed to prevent another host mutation")
	}
}

func TestWSSCleanSuccessfulEnsureConsumesJournalAtomically(t *testing.T) {
	ctx := context.Background()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	engine, store := crashWSSEngine(t, host)
	host.store = store
	link := journalTestLink(t)
	result, err := engine.Ensure(ctx, link)
	if err != nil || !result.Changed {
		t.Fatalf("initial WSS Ensure: %+v, %v", result, err)
	}
	snapshot := mustLoadCrashSnapshot(t, store)
	if len(snapshot.WSSCrashOperations) != 0 {
		t.Fatal("completed WSS committed Link retained preparation journal")
	}
	if _, committed := snapshot.Find(link.ID); !committed {
		t.Fatal("WSS Link was not committed")
	}
	result, err = engine.Ensure(ctx, link)
	if err != nil || result.Changed {
		t.Fatalf("idempotent committed WSS Ensure: %+v, %v", result, err)
	}
	if len(mustLoadCrashSnapshot(t, store).WSSCrashOperations) != 0 {
		t.Fatal("no-op Ensure created an unnecessary crash journal")
	}
}

func TestWSSInterruptedRemoveDoesNotBlockIndependentGREBootRestore(t *testing.T) {
	ctx := context.Background()
	wss := &crashWSSBackend{fakeBackend: newFakeBackend()}
	gre := newFakeBackend()
	registry, err := backend.NewRegistry(wss, gre)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	locks := state.NewLockManager(root)
	engine, err := New(registry, store, locks)
	if err != nil {
		t.Fatal(err)
	}
	wss.store = store
	wssLink := journalTestLink(t)
	greLink := linkFor(t, "gre-independent", "10.80.30.0/31", "10.80.30.1/31")
	if _, err := engine.Ensure(ctx, wssLink); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ensure(ctx, greLink); err != nil {
		t.Fatal(err)
	}
	wss.crashAfterHost = true
	causeCrash(t, func() { _, _ = engine.Remove(ctx, wssLink.ID) })
	// A subsequent boot loses volatile backend inventory for the unrelated
	// GRE, but must never replay the interrupted WSS transaction.
	gre.present = make(map[domain.LinkID][]domain.ResourceClaim)
	beforeWSSApply := wss.applyCount
	results, restoreErr := engine.RestoreAll(ctx)
	if restoreErr == nil {
		t.Fatal("boot restore silently reported success with interrupted WSS")
	}
	if len(results) != 1 || results[0].LinkID != greLink.ID {
		t.Fatalf("unrelated GRE was not restored alongside quarantined WSS: %+v %v", results, restoreErr)
	}
	if wss.applyCount != beforeWSSApply {
		t.Fatal("interrupted WSS was replayed during restore")
	}
	if _, present := gre.present[greLink.ID]; !present {
		t.Fatal("independent GRE host resources not restored")
	}
	if _, exists := mustLoadCrashSnapshot(t, store).FindWSSCrashOperation(wssLink.ID); !exists {
		t.Fatal("boot restore erased unfinished WSS journal")
	}
}
