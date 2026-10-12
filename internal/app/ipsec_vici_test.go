package app

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// ipsecVICITestWriter is a TEST-ONLY injected fake for the original
// prepare/phase-journal safety contract. The production scoped govici writer
// now operates only behind native-exclusive service and Engine ownership.
type ipsecVICITestWriter interface {
	LoadShared(context.Context, ipsec.Profile, *ipsec.PSK) error
	LoadConnection(context.Context, ipsec.Profile) error
}

// simulatePreparedIPsecVICI exists only in _test.go and injects fake effects.
// It tests the original journal's fail-closed transitions; unlike the live
// operational backend it neither contacts the daemon nor establishes ownership.
func (e *Engine) simulatePreparedIPsecVICI(ctx context.Context, id domain.LinkID, keys IPsecProtectedKeyReader, reader IPsecVICIInventory, xfrm IPsecXFRMVacancy, writer ipsecVICITestWriter) error {
	const op = "ipsec_vici_apply"
	if writer == nil {
		return stlerr.New(stlerr.CodeInvalid, op, string(id), "ipsec", "test-only VICI simulation fixture is required")
	}
	return e.withIPsecActivationVacancy(ctx, id, keys, reader, xfrm, func(p ipsec.Profile, key *ipsec.PSK) error {
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICIPrepared, state.IPsecVICIIssuingShared); err != nil {
			return stlerr.New(stlerr.CodeConflict, op, string(id), "ipsec", "durable prepared IPsec transaction is required; no VICI call made")
		}
		if err := writer.LoadShared(ctx, p, key); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "scoped shared-key call uncertain; retain transaction journal for manual reconciliation")
		}
		view, err := reader.Inspect(ctx, p)
		if err != nil || !view.SecretNamePresent || view.ConnectionNamePresent {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "strongSwan shared-key result unverified; retain transaction journal")
		}
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICIIssuingShared, state.IPsecVICISharedObserved); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "shared-key observation not durable; no connection call made")
		}
		// Repeat immediately before connection load: an outside writer may
		// have introduced a colliding connection during the shared-key step.
		view, err = reader.Inspect(ctx, p)
		if err != nil || !view.SecretNamePresent || view.ConnectionNamePresent {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "strongSwan connection namespace changed; do not overwrite")
		}
		if err := xfrm.RequireVacant(ctx, p); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "XFRM namespace changed; do not load connection")
		}
		if err := ctx.Err(); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "IPsec VICI transaction interrupted before connection call")
		}
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICISharedObserved, state.IPsecVICIIssuingConnection); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "connection issue journal not proven durable; no connection call made")
		}
		if err := writer.LoadConnection(ctx, p); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "scoped connection call uncertain; retain transaction journal")
		}
		view, err = reader.Inspect(ctx, p)
		if err != nil || !view.ConnectionNamePresent || !view.SecretNamePresent {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "strongSwan connection result unverified; retain transaction journal")
		}
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICIIssuingConnection, state.IPsecVICIConnectionSeen); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "connection observation not durable; retain transaction journal")
		}
		// Presence is not ownership proof. XFRM, IKE negotiation, scoped
		// cleanup/reapply and canonical Link commit are separate gated work.
		return nil
	})
}

type ipsecVICIWriterFixture struct {
	store       *state.FileStore
	t           *testing.T
	daemon      *ipsecInventoryFixture
	calls       []string
	failOn      string
	interruptOn string
}

func (w *ipsecVICIWriterFixture) verifyPhase(p ipsec.Profile, phase string) {
	w.t.Helper()
	s, err := w.store.Load(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	got, exists := s.FindIPsecVICIOperation(p.Link.ID)
	if !exists || got.Phase != phase || len(s.Links) != 0 || len(s.PendingIPsec) != 1 {
		w.t.Fatalf("VICI invoked without durable pre-effect journal phase %s: %+v", phase, got)
	}
}

func (w *ipsecVICIWriterFixture) LoadShared(_ context.Context, p ipsec.Profile, k *ipsec.PSK) error {
	w.verifyPhase(p, state.IPsecVICIIssuingShared)
	material := k.SecretBytes()
	defer clear(material)
	if !bytes.Equal(material, bytes.Repeat([]byte{0x73}, 32)) {
		w.t.Fatal("protected IPsec credential lost or substituted")
	}
	w.calls = append(w.calls, "load-shared")
	if w.failOn == "shared" {
		return errors.New("SENSITIVE PSK and daemon text must never be disclosed")
	}
	w.daemon.observed.SecretNamePresent = true
	return nil
}
func (w *ipsecVICIWriterFixture) LoadConnection(_ context.Context, p ipsec.Profile) error {
	w.verifyPhase(p, state.IPsecVICIIssuingConnection)
	w.calls = append(w.calls, "load-conn")
	if w.failOn == "connection" {
		return errors.New("SENSITIVE daemon connection error")
	}
	w.daemon.observed.ConnectionNamePresent = true
	return nil
}

func stagedPreparedVICI(t *testing.T) (*Engine, *state.FileStore, *ipsec.PSKStore, domain.Link, *ipsecInventoryFixture, *ipsecXFRMFixture) {
	t.Helper()
	e, st, keys := stageEngine(t)
	link := stagedIPsecLink("lnk_35353535353535353535353535353535", "10.84.60.0/31")
	if err := e.StageIPsecSender(context.Background(), offerForStage(t, link, bytes.Repeat([]byte{0x73}, 32)), keys, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	daemon := &ipsecInventoryFixture{}
	xfrm := &ipsecXFRMFixture{}
	if err := e.PrepareIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm); err != nil {
		t.Fatal(err)
	}
	return e, st, keys, link, daemon, xfrm
}

func TestIPsecVICIPrepareIsDurableIdempotentAndNeverMutatesDaemon(t *testing.T) {
	e, st, keys, link, daemon, xfrm := stagedPreparedVICI(t)
	got, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	original, exists := got.FindIPsecVICIOperation(link.ID)
	if !exists || original.Phase != state.IPsecVICIPrepared || original.Nonce == "" {
		t.Fatal("prepared journal not durable")
	}
	if err := e.PrepareIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm); err != nil {
		t.Fatal("idempotent prepared replay rejected", err)
	}
	again, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	replayed, exists := again.FindIPsecVICIOperation(link.ID)
	if !exists || replayed != original || len(again.PendingIPsec) != 1 || len(again.Links) != 0 {
		t.Fatal("prepared replay changed public authority or Link state")
	}
	if daemon.calls != 2 || xfrm.calls != 2 {
		t.Fatal("replay skipped fresh read-only collision checks")
	}
}

func TestIPsecVICISimulatedPhasesStopAtUncommittedConfiguration(t *testing.T) {
	e, st, keys, link, daemon, xfrm := stagedPreparedVICI(t)
	writer := &ipsecVICIWriterFixture{store: st, t: t, daemon: daemon}
	if err := e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(writer.calls, []string{"load-shared", "load-conn"}) {
		t.Fatalf("unbounded or out-of-order VICI effects: %v", writer.calls)
	}
	s, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	marker, ok := s.FindIPsecVICIOperation(link.ID)
	if !ok || marker.Phase != state.IPsecVICIConnectionSeen || len(s.PendingIPsec) != 1 || len(s.Links) != 0 {
		t.Fatal("name presence was incorrectly promoted into full Link ownership")
	}
	if xfrm.calls != 3 || daemon.calls != 5 {
		t.Fatalf("VICI and XFRM were not re-inspected after first effect: daemon=%d kernel=%d", daemon.calls, xfrm.calls)
	}
	// A success receipt from VICI is NOT authority to repeat load or unload.
	if err := e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer); err == nil {
		t.Fatal("loaded daemon objects were implicitly adopted on retry")
	}
	if len(writer.calls) != 2 {
		t.Fatal("already attempted VICI effects repeated")
	}
}

func TestIPsecVICISimulatedFailureRetainsUncertainPhaseAndNeverRetriesOrLeaks(t *testing.T) {
	for _, tc := range []struct{ name, failOn, wantPhase string }{
		{"shared reply uncertain", "shared", state.IPsecVICIIssuingShared},
		{"connection reply uncertain", "connection", state.IPsecVICIIssuingConnection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, st, keys, link, daemon, xfrm := stagedPreparedVICI(t)
			writer := &ipsecVICIWriterFixture{store: st, t: t, daemon: daemon, failOn: tc.failOn}
			err := e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer)
			if err == nil || strings.Contains(err.Error(), "SENSITIVE") {
				t.Fatalf("uncertain writer error leaked or reported success: %v", err)
			}
			s, _ := st.Load(context.Background())
			op, ok := s.FindIPsecVICIOperation(link.ID)
			if !ok || op.Phase != tc.wantPhase {
				t.Fatalf("unsafe phase after partial write: %+v", op)
			}
			count := len(writer.calls)
			if err = e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer); err == nil {
				t.Fatal("uncertain daemon effect retried")
			}
			if len(writer.calls) != count {
				t.Fatal("mutating command retried despite uncertain durable journal")
			}
			if len(s.PendingIPsec) != 1 || len(s.Links) != 0 {
				t.Fatal("partial VICI effect silently committed or discarded public intent")
			}
		})
	}
}

func TestIPsecVICISimulationRejectsObservedCollisions(t *testing.T) {
	e, st, keys, link, daemon, xfrm := stagedPreparedVICI(t)
	daemon.observed.ConnectionNamePresent = true
	if err := e.PrepareIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm); err == nil {
		t.Fatal("foreign daemon conflict accepted")
	}
	daemon.observed.ConnectionNamePresent = false
	xfrm.err = errors.New("SENSITIVE uncertain kernel inventory")
	writer := &ipsecVICIWriterFixture{store: st, t: t, daemon: daemon}
	if err := e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer); err == nil || len(writer.calls) != 0 {
		t.Fatal("XFRM collision bypassed")
	}
	s, _ := st.Load(context.Background())
	op, _ := s.FindIPsecVICIOperation(link.ID)
	if op.Phase != state.IPsecVICIPrepared {
		t.Fatal("failed read-only preflight advanced durable writer phase")
	}
}

// The state store may publish a journal rename and then fail metadata fsync.
// In either case (known absence or uncertain publication), NO effect can be
// sent until the pre-effect phase is durably acknowledged by Store.Update.
type ipsecVICIUpdateFault struct {
	state.Store
	failOnPhase string
	published   bool
}

func (f *ipsecVICIUpdateFault) Update(ctx context.Context, mutate func(*state.Snapshot) error) error {
	failure := errors.New("SENSITIVE state publish/metadata error")
	err := f.Store.Update(ctx, func(s *state.Snapshot) error {
		if err := mutate(s); err != nil {
			return err
		}
		for _, operation := range s.IPsecVICIOperations {
			if operation.Phase == f.failOnPhase && !f.published {
				return failure
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if f.published {
		s, loadErr := f.Store.Load(ctx)
		if loadErr != nil {
			return loadErr
		}
		for _, operation := range s.IPsecVICIOperations {
			if operation.Phase == f.failOnPhase {
				return &state.PublicationError{Cause: failure}
			}
		}
	}
	return nil
}
func TestIPsecVICISimulationRequiresDurablePhaseBeforeFakeEffect(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-rename", true: "after-rename"}[published], func(t *testing.T) {
			e, st, keys, link, daemon, xfrm := stagedPreparedVICI(t)
			e.store = &ipsecVICIUpdateFault{Store: st, failOnPhase: state.IPsecVICIIssuingShared, published: published}
			writer := &ipsecVICIWriterFixture{store: st, t: t, daemon: daemon}
			err := e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer)
			if err == nil || strings.Contains(err.Error(), "SENSITIVE") || len(writer.calls) != 0 {
				t.Fatalf("effect sent without durable journal proof: %v", err)
			}
			s, err := st.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			op, ok := s.FindIPsecVICIOperation(link.ID)
			if !ok {
				t.Fatal("missing journal after failed transition")
			}
			expected := state.IPsecVICIPrepared
			if published {
				expected = state.IPsecVICIIssuingShared
			}
			if op.Phase != expected {
				t.Fatalf("unverified phase=%q expected=%q", op.Phase, expected)
			}
			if len(s.PendingIPsec) != 1 || len(s.Links) != 0 {
				t.Fatal("uncertain result promoted into operational Link")
			}
		})
	}
}

type ipsecXFRMFailAt struct{ calls, failAt int }

func (f *ipsecXFRMFailAt) RequireVacant(_ context.Context, _ ipsec.Profile) error {
	f.calls++
	if f.calls == f.failAt {
		return errors.New("SENSITIVE untrusted XFRM inventory")
	}
	return nil
}
func TestIPsecVICISimulationStopsBeforeConnectionOnHostDrift(t *testing.T) {
	e, st, keys, link, daemon, _ := stagedPreparedVICI(t)
	xfrm := &ipsecXFRMFailAt{failAt: 2} // after initial VICI vacancy check, before connection
	writer := &ipsecVICIWriterFixture{store: st, t: t, daemon: daemon}
	err := e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer)
	if err == nil || strings.Contains(err.Error(), "SENSITIVE") || !reflect.DeepEqual(writer.calls, []string{"load-shared"}) {
		t.Fatalf("foreign kernel drift failed to block VICI connection: %v %v", err, writer.calls)
	}
	s, _ := st.Load(context.Background())
	op, _ := s.FindIPsecVICIOperation(link.ID)
	if op.Phase != state.IPsecVICISharedObserved {
		t.Fatalf("shared key phase lost after host drift: %s", op.Phase)
	}
}

// Two callers cannot both consume the same prepared journal or replace a
// same-name daemon connection: the canonical Link lock serializes them,
// and the second invocation must treat the first write as an occupied name.
func TestIPsecVICIConcurrentSimulationCannotDuplicateFakeEffects(t *testing.T) {
	e, st, keys, link, daemon, xfrm := stagedPreparedVICI(t)
	writer := &ipsecVICIWriterFixture{store: st, t: t, daemon: daemon}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var errs [2]error
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			errs[index] = e.simulatePreparedIPsecVICI(context.Background(), link.ID, keys, daemon, xfrm, writer)
		}(i)
	}
	close(start)
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("exactly one transaction must succeed: %v / %v", errs[0], errs[1])
	}
	if !reflect.DeepEqual(writer.calls, []string{"load-shared", "load-conn"}) {
		t.Fatalf("concurrent operation duplicated daemon effects: %v", writer.calls)
	}
	s, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	op, ok := s.FindIPsecVICIOperation(link.ID)
	if !ok || op.Phase != state.IPsecVICIConnectionSeen || len(s.Links) != 0 {
		t.Fatal("concurrent VICI phase lost safety or claimed an operational Link")
	}
}

// The source-only journal transition helper must never infer success by
// skipping observations or moving backward, even in fake-only simulation.
func TestIPsecVICIRejectsNonAdjacentJournalPhaseTransitions(t *testing.T) {
	e, st, _, link, _, _ := stagedPreparedVICI(t)
	profile, err := ipsec.NewProfile(link)
	if err != nil {
		t.Fatal(err)
	}
	invalid := [][2]string{
		{state.IPsecVICIPrepared, state.IPsecVICIConnectionSeen},
		{state.IPsecVICIPrepared, state.IPsecVICISharedObserved},
		{state.IPsecVICIPrepared, state.IPsecVICIPrepared},
		{state.IPsecVICIConnectionSeen, state.IPsecVICIPrepared},
		{state.IPsecVICIIssuingShared, state.IPsecVICISharedObserved},
	}
	before, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, edges := range invalid {
		if err := e.advanceIPsecVICIPhase(context.Background(), profile, edges[0], edges[1]); err == nil {
			t.Fatalf("journal permitted invalid or unproven transition %s -> %s", edges[0], edges[1])
		}
		after, err := st.Load(context.Background())
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("failed journal transition changed durable state: %v", err)
		}
	}
}
