package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func quicCrashIntentFixture() state.QUICCrashOperation {
	local, provider := quicReadinessFixture()
	return state.QUICCrashOperation{
		Plan: composition.QUICHostPlan{
			Local: local, Physical: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60",
		},
		Addresses: provider.Addresses, WireGuard: provider.WireGuard,
		CertificateSHA256: strings.Repeat("a", 64), TrustCASHA256: strings.Repeat("b", 64),
		AuthorizationSHA256: strings.Repeat("c", 64), HelperConfigSHA256: strings.Repeat("d", 64),
		ExecutablePath: "/usr/local/libexec/stl/hysteria", ExecutableSHA256: strings.Repeat("e", 64),
		ExecutableDevice: 1, ExecutableInode: 2,
	}
}

func TestPrepareQUICCrashWritesExactCanonicalJournalAndQuarantinesOrdinaryActions(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	e, store := newEngine(t, backend)
	prepared := quicCrashIntentFixture()
	probe := &quicVacancyProbe{}
	got, err := e.PrepareQUICCrash(ctx, prepared, probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nonce) != 32 || len(got.Resources) == 0 || probe.calls != 1 ||
		len(backend.present) != 0 || backend.applyCount != 0 {
		t.Fatalf("journal admission executed host effect or omitted nonce/claims: %+v probe=%d", got, probe.calls)
	}
	localWG := quicClaim(domain.ResourceUDPListenPort, "51821")
	helpUDP := quicClaim(domain.ResourceUDPListenPort, "52211")
	remoteWG := quicClaim(domain.ResourceUDPListenPort, "51820")
	if !slices.Contains(got.Resources, localWG) || !slices.Contains(got.Resources, helpUDP) || slices.Contains(got.Resources, remoteWG) {
		t.Fatalf("journal reserved incorrect local vs remote UDP ports: %+v", got.Resources)
	}
	reloaded, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fromDisk, found := reloaded.FindQUICCrashOperation(prepared.Plan.Local.LinkID)
	if !found || !reflect.DeepEqual(got, fromDisk) || len(reloaded.Links) != 0 {
		t.Fatalf("uncommitted QUIC intent was not durably quarantined: %+v", reloaded)
	}
	if _, err := e.CheckQUICPreparation(ctx, prepared.Plan.Local,
		QUICWireGuardProvider{Addresses: prepared.Addresses, WireGuard: prepared.WireGuard}, probe); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("read-only preview adopted unresolved journal: %v", err)
	}
	if _, err := e.PrepareQUICCrash(ctx, prepared, probe); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("replayed same Link over unresolved journal: %v", err)
	}
	if probe.calls != 1 {
		t.Fatalf("duplicate Link performed new live probe: %d", probe.calls)
	}
	link := linkFor(t, "same-ID-cannot-adopt", "10.80.23.0/31", "10.80.23.1/31")
	link.ID = prepared.Plan.Local.LinkID
	if _, err := e.Ensure(ctx, link); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("normal native Ensure could reuse quarantined ID: %v", err)
	}
	if _, err := e.Remove(ctx, link.ID); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("normal Remove could clear quarantined ID: %v", err)
	}
	if _, err := e.RestoreAll(ctx); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("journal-only State was mistaken for empty healthy state: %v", err)
	}
	if len(backend.present) != 0 || backend.applyCount != 0 {
		t.Fatal("QUIC journal caused an unexpected normal native backend mutation")
	}
	end, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(reloaded, end) {
		t.Fatalf("replay/restore altered quarantined State: %v", err)
	}
}

func TestPrepareQUICCrashChecksBothStateAndIndependentLinkReservations(t *testing.T) {
	ctx := context.Background()
	e, store := newEngine(t, newFakeBackend())
	first := quicCrashIntentFixture()
	if _, err := e.PrepareQUICCrash(ctx, first, &quicVacancyProbe{}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Plan.Local.LinkID = domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	second.Plan.Local.LocalWGUDPPort = 51822
	second.Plan.Local.LocalHelperUDPPort = 52212
	second.Addresses.Local = netip.MustParsePrefix("10.96.21.0/31")
	second.Addresses.Peer = netip.MustParsePrefix("10.96.21.1/31")
	second.WireGuard.ListenPort, second.WireGuard.PeerPort = 51822, 52212
	second.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	if _, err := e.PrepareQUICCrash(ctx, second, &quicVacancyProbe{}); err != nil {
		t.Fatalf("different local resources toward same peer were prohibited: %v", err)
	}
	third := second
	third.Plan.Local.LinkID = domain.LinkID("lnk_cccccccccccccccccccccccccccccccc")
	if _, err := e.PrepareQUICCrash(ctx, third, &quicVacancyProbe{}); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("independent QUIC journal did not reserve local ports: %v", err)
	}
	loaded, err := store.Load(ctx)
	if err != nil || len(loaded.QUICCrashOperations) != 2 || len(loaded.Links) != 0 {
		t.Fatalf("independent intents were not protected: %+v %v", loaded, err)
	}
	// A committed/native Link cannot claim a reserved QUIC local socket,
	// even when a fake host inspector reports all resources vacant.
	if err := rejectResourceConflicts(loaded, domain.LinkID("lnk_dddddddddddddddddddddddddddddddd"),
		[]domain.ResourceClaim{quicClaim(domain.ResourceUDPListenPort, "52211")}); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("normal Engine conflict path ignored QUIC journal: %v", err)
	}
	if err := rejectResourceConflicts(loaded, domain.LinkID("lnk_dddddddddddddddddddddddddddddddd"),
		[]domain.ResourceClaim{quicClaim(domain.ResourceLinkSubnet, "10.96.20.0/31")}); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("normal Engine conflict path ignored QUIC private route: %v", err)
	}
}

func TestPrepareQUICCrashRejectsUnsafeOrUnverifiedPreflightWithoutMutation(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		modify func(*state.QUICCrashOperation)
		probe  *quicVacancyProbe
		want   stlerr.Code
	}{
		{"expected-digest-missing", func(op *state.QUICCrashOperation) { op.CertificateSHA256 = "" }, &quicVacancyProbe{}, stlerr.CodeInvalid},
		{"plan-route-captures-physical", func(op *state.QUICCrashOperation) {
			op.Plan.Physical = netip.MustParseAddrPort("10.96.20.1:443")
			op.Plan.TLSName = "10.96.20.1"
		}, &quicVacancyProbe{}, stlerr.CodeInvalid},
		{"caller-invents-nonce", func(op *state.QUICCrashOperation) { op.Nonce = strings.Repeat("a", 32) }, &quicVacancyProbe{}, stlerr.CodeInvalid},
		{"caller-invents-claim", func(op *state.QUICCrashOperation) {
			op.Resources = []domain.ResourceClaim{{Kind: domain.ResourceUDPListenPort, Key: "52211"}}
		}, &quicVacancyProbe{}, stlerr.CodeInvalid},
		{"occupied-socket", func(*state.QUICCrashOperation) {}, &quicVacancyProbe{occupied: true}, stlerr.CodeConflict},
		{"ambiguous-socket", func(*state.QUICCrashOperation) {}, &quicVacancyProbe{err: errors.New("bearer=very-secret")}, stlerr.CodeState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, store := newEngine(t, newFakeBackend())
			in := quicCrashIntentFixture()
			tc.modify(&in)
			_, err := e.PrepareQUICCrash(ctx, in, tc.probe)
			if stlerr.CodeOf(err) != tc.want || (err != nil && strings.Contains(err.Error(), "very-secret")) {
				t.Fatalf("unsafe journal preflight had wrong result: %v", err)
			}
			got, err := store.Load(ctx)
			if err != nil || len(got.QUICCrashOperations) != 0 {
				t.Fatalf("failed admission nevertheless published State: %+v %v", got, err)
			}
		})
	}
}

type quicUncertainPublishStore struct{ state.Store }

func (u quicUncertainPublishStore) Update(ctx context.Context, update func(*state.Snapshot) error) error {
	if err := u.Store.Update(ctx, update); err != nil {
		return err
	}
	return &state.PublicationError{Cause: errors.New("private potentially sensitive fsync diagnostic")}
}

func TestPrepareQUICCrashPublicationUncertainKeepsJournalAndNoHostEffects(t *testing.T) {
	e, durable := newEngine(t, newFakeBackend())
	e.store = quicUncertainPublishStore{Store: durable}
	probe := &quicVacancyProbe{}
	in := quicCrashIntentFixture()
	_, err := e.PrepareQUICCrash(context.Background(), in, probe)
	if stlerr.CodeOf(err) != stlerr.CodeState || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("indeterminate publication was reported as successful or leaked: %v", err)
	}
	stored, err := durable.Load(context.Background())
	if err != nil || len(stored.QUICCrashOperations) != 1 {
		t.Fatalf("possible post-publication journal was incorrectly cleared: %+v %v", stored, err)
	}
	if _, err := e.PrepareQUICCrash(context.Background(), in, &quicVacancyProbe{}); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("indeterminate journal allowed second attempt: %v", err)
	}
}

func TestRestoreAllPreservesOnlyQUICCrashJournalAndExistingRestoreUnit(t *testing.T) {
	persistence := &fakeRestorePersistence{active: true}
	e, _ := persistentTestEngine(t, newFakeBackend(), persistence)
	if _, err := e.PrepareQUICCrash(context.Background(), quicCrashIntentFixture(), &quicVacancyProbe{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RestoreAll(context.Background()); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("empty-Link QUIC journal incorrectly cleaned restore service: %v", err)
	}
	if persistence.removes != 0 || !persistence.active {
		t.Fatalf("pending intent destroyed original restore unit: %+v", persistence)
	}
}

func TestPrepareQUICCrashConcurrentSameLinkOnlyOneDurableWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, store := newEngine(t, newFakeBackend())
	candidate := quicCrashIntentFixture()
	start := make(chan struct{})
	result := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := e.PrepareQUICCrash(ctx, candidate, &quicVacancyProbe{})
			result <- err
		}()
	}
	close(start)
	first, second := <-result, <-result
	countSuccess, countConflict := 0, 0
	for _, err := range []error{first, second} {
		if err == nil {
			countSuccess++
		} else if stlerr.CodeOf(err) == stlerr.CodeConflict {
			countConflict++
		} else {
			t.Fatalf("invalid concurrent outcome: %v", err)
		}
	}

	if countSuccess != 1 || countConflict != 1 {
		t.Fatalf("concurrent same-Link prepares = %d success / %d collision", countSuccess, countConflict)
	}
	fresh, err := store.Load(ctx)
	if err != nil || len(fresh.QUICCrashOperations) != 1 {
		t.Fatalf("concurrent publication duplicated journal: %+v %v", fresh, err)
	}
}

// A test-only observer proves that QUIC publication participates in the
// same restore-persistence lock as ordinary Remove and empty-State RestoreAll.
// The underlying real file LockManager still enforces cross-Engine exclusion.
type quicRestoreLockObserver struct {
	Locker
	attempted chan struct{}
	held      atomic.Bool
}

func (o *quicRestoreLockObserver) Acquire(ctx context.Context, claims []domain.ResourceClaim) (func() error, error) {
	if len(claims) != 1 || claims[0] != restoreLockClaim() {
		return o.Locker.Acquire(ctx, claims)
	}
	if o.attempted != nil {
		select {
		case o.attempted <- struct{}{}:
		default:
		}
	}
	release, err := o.Locker.Acquire(ctx, claims)
	if err != nil {
		return nil, err
	}
	o.held.Store(true)
	return func() error {
		err := release()
		o.held.Store(false)
		return err
	}, nil
}

type quicPublicationGateStore struct {
	state.Store
	lock    *quicRestoreLockObserver
	entered chan struct{}
	proceed <-chan struct{}
}

func (g *quicPublicationGateStore) Update(ctx context.Context, mutate func(*state.Snapshot) error) error {
	close(g.entered)
	if !g.lock.held.Load() {
		return errors.New("QUIC publication attempted outside shared restore lock")
	}
	select {
	case <-g.proceed:
	case <-ctx.Done():
		return ctx.Err()
	}
	return g.Store.Update(ctx, mutate)
}

// The gate pauses QUIC exactly at State publication while it owns the
// restore lock. A concurrent last-Link Remove reaches the same lock before
// QUIC is unblocked; it must then see the pending journal in committed State,
// remove only the unrelated Link and KEEP the original host restore unit.
func TestLastLinkRemoveCannotRetireRestoreWhenQUICJournalPublishesFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	p := &fakeRestorePersistence{}
	e, store := persistentTestEngine(t, newFakeBackend(), p)
	link := linkFor(t, "remove-with-quic-intent", "10.80.192.0/31", "10.80.192.1/31")
	if _, err := e.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}

	publisher := *e
	publisherLock := &quicRestoreLockObserver{Locker: e.locks}
	publisher.locks = publisherLock
	proceed := make(chan struct{})
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	entered := make(chan struct{})
	publisher.store = &quicPublicationGateStore{Store: store, lock: publisherLock, entered: entered, proceed: proceed}
	published := make(chan error, 1)
	go func() {
		_, err := publisher.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
		published <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("QUIC publication did not reach controlled gate")
	}
	if !publisherLock.held.Load() {
		t.Fatal("publisher did not hold shared restore lock before State publication")
	}

	remover := *e
	removeAttempt := make(chan struct{}, 1)
	remover.locks = &quicRestoreLockObserver{Locker: e.locks, attempted: removeAttempt}
	removed := make(chan error, 1)
	go func() {
		_, err := remover.Remove(ctx, link.ID)
		removed <- err
	}()
	select {
	case <-removeAttempt:
	case <-ctx.Done():
		t.Fatal("last-Link Remove did not reach shared restore lock")
	}
	close(proceed)
	if err := <-published; err != nil {
		t.Fatalf("QUIC journal publication failed: %v", err)
	}
	if err := <-removed; err != nil {
		t.Fatalf("independent ordinary Link removal failed: %v", err)
	}
	fresh, err := store.Load(ctx)
	if err != nil || len(fresh.Links) != 0 || len(fresh.QUICCrashOperations) != 1 {
		t.Fatalf("last-Link removal lost pending QUIC State: %+v %v", fresh, err)
	}
	p.mu.Lock()
	active, removes := p.active, p.removes
	p.mu.Unlock()
	if !active || removes != 0 {
		t.Fatalf("Remove retired shared restore unit despite QUIC journal: active=%t removes=%d", active, removes)
	}
}

// RestoreAll first sees an empty snapshot, but the QUIC publisher commits
// before its restore-persistence lock is available. Its under-lock recheck
// must refuse cleanup rather than deleting the still-needed existing unit.
func TestRestoreAllEmptyStateCleanupCannotRaceQUICPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	p := &fakeRestorePersistence{active: true}
	e, store := persistentTestEngine(t, newFakeBackend(), p)
	if err := store.Update(ctx, func(*state.Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	publisher := *e
	publisherLock := &quicRestoreLockObserver{Locker: e.locks}
	publisher.locks = publisherLock
	proceed := make(chan struct{})
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	entered := make(chan struct{})
	publisher.store = &quicPublicationGateStore{Store: store, lock: publisherLock, entered: entered, proceed: proceed}
	published := make(chan error, 1)
	go func() {
		_, err := publisher.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
		published <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("QUIC publication did not reach controlled gate")
	}
	if !publisherLock.held.Load() {
		t.Fatal("publisher did not protect journal publication with restore lock")
	}
	restorer := *e
	cleanupAttempt := make(chan struct{}, 1)
	restorer.locks = &quicRestoreLockObserver{Locker: e.locks, attempted: cleanupAttempt}
	restored := make(chan error, 1)
	go func() {
		_, err := restorer.RestoreAll(ctx)
		restored <- err
	}()
	select {
	case <-cleanupAttempt:
	case <-ctx.Done():
		t.Fatal("empty-State RestoreAll did not reach restore lock")
	}
	close(proceed)
	if err := <-published; err != nil {
		t.Fatalf("QUIC publication failed: %v", err)
	}
	if err := <-restored; stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("RestoreAll did not reject concurrently published intent: %v", err)
	}
	fresh, err := store.Load(ctx)
	if err != nil || len(fresh.Links) != 0 || len(fresh.QUICCrashOperations) != 1 {
		t.Fatalf("RestoreAll damaged QUIC journal: %+v %v", fresh, err)
	}
	p.mu.Lock()
	active, removes := p.active, p.removes
	p.mu.Unlock()
	if !active || removes != 0 {
		t.Fatalf("RestoreAll deleted original unit despite journal: active=%t removes=%d", active, removes)
	}
}

// Removing the last ordinary Link is allowed with a non-conflicting QUIC
// journal. Unlike an entirely empty State, it must leave persistence active.
func TestLastOrdinaryLinkRemoveKeepsPendingQUICAndOwnedRestoreUnit(t *testing.T) {
	ctx := context.Background()
	p := &fakeRestorePersistence{}
	e, store := persistentTestEngine(t, newFakeBackend(), p)
	link := linkFor(t, "last-with-quic-intent", "10.80.194.0/31", "10.80.194.1/31")
	if _, err := e.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	journal, err := e.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := e.Remove(ctx, link.ID)
	if err != nil || !removed.Removed {
		t.Fatalf("unrelated Link removal must succeed: %+v %v", removed, err)
	}
	fresh, err := store.Load(ctx)
	if err != nil || len(fresh.Links) != 0 || len(fresh.QUICCrashOperations) != 1 ||
		!reflect.DeepEqual(fresh.QUICCrashOperations[0], journal) {
		t.Fatalf("Remove altered durable QUIC intent: %+v %v", fresh, err)
	}
	p.mu.Lock()
	active, removes := p.active, p.removes
	p.mu.Unlock()
	if !active || removes != 0 {
		t.Fatalf("last ordinary Link removed shared restore unit: active=%t removes=%d", active, removes)
	}
}
