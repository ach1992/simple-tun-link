package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	core "github.com/ach1992/simple-tun-link/internal/backend"
	masquebackend "github.com/ach1992/simple-tun-link/internal/backend/masque"
	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/masquehost"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestPublicMASQUECLICannotClaimMenuHandoffNamespace(t *testing.T) {
	opts, _, _, _ := guidedSavedWireGuardFixture(t)
	id := domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	target, err := prepareProtectedMenuHandoff(opts, id)
	if err != nil {
		t.Fatal(err)
	}
	request := masqueInputTestRequest()
	request.LinkID = id
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := linkMASQUECommand([]string{"create-masque", "--stdin", "--output", target, "--json"},
		bytes.NewReader(raw), &out, &errOut, opts)
	if code == 0 || !strings.Contains(out.String(), "reserved for guided Create") {
		t.Fatalf("public Create entered menu-owned private namespace: code=%d", code)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("denied public Create published private material")
	}
	if _, err := os.Lstat(filepath.Join(opts.stateRoot, "masque")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("denied public Create staged local MASQUE keys")
	}
	privateDirectory := filepath.Join(filepath.Dir(target), "nested")
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkCreatorHandoffDestination(opts, id, filepath.Join(privateDirectory, "offer.stl")); err == nil {
		t.Fatal("CLI was admitted inside a nested reserved menu directory")
	}
	normalOutput := filepath.Join(opts.stateRoot, "operator-selected.stl")
	if err := checkCreatorHandoffDestination(opts, id, normalOutput); err != nil {
		t.Fatalf("ordinary owner-private CLI destination was unnecessarily banned: %v", err)
	}
	scoped := menuHandoffCreationOptions(opts, id)
	if err := checkCreatorHandoffDestination(scoped, id, target); err != nil {
		t.Fatalf("guided menu cannot create its own exact original offer: %v", err)
	}
	if err := checkCreatorHandoffDestination(scoped, domain.LinkID("lnk_cccccccccccccccccccccccccccccccc"), target); err == nil {
		t.Fatal("a different Link ID inherited another menu offer authorization")
	}
}

func TestUnmarkedLegacyReservedCLIOriginalIsNotAutoDeleted(t *testing.T) {
	opts, link, path, _ := guidedSavedWireGuardFixture(t)
	origin, err := menuHandoffOriginPath(opts, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a valid old-CLI --output written to the reserved pathname.
	// It has correct sender credentials, but cannot prove menu authorship.
	if err := os.Remove(origin); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := executeLinkMutation("link_remove", domain.Link{}, link.ID, true, &out, &errOut, opts)
	if code == 0 {
		t.Fatal("unknown original provenance was silently accepted for automatic deletion")
	}
	var failure lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &failure); err != nil ||
		failure.Outcome != "removed_cleanup_incomplete" ||
		failure.PartialResult == nil || !failure.PartialResult.Removed {
		t.Fatalf("removed Link status was not truthful for historical CLI output: %+v %v", failure, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("unmarked historical CLI output was deleted", err)
	}
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 0 {
		t.Fatal("provenance uncertainty blocked committed Engine removal", err)
	}
}

func TestExplicitReceiverDeleteAlsoRetiresItsMenuOriginReceipt(t *testing.T) {
	opts, link, path, _ := guidedSavedWireGuardFixture(t)
	origin, err := menuHandoffOriginPath(opts, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(origin); err != nil {
		t.Fatal("guided Create never recorded menu-owned origin", err)
	}
	if err := secureDeleteProtectedMenuHandoff(opts, link); err != nil {
		t.Fatalf("fresh, explicit DELETE failed: %v", err)
	}
	for _, file := range []string{path, origin} {
		if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("explicit DELETE retained protected artifact %s: %v", file, err)
		}
	}
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 {
		t.Fatal("deleting only the saved offer altered the active Link", err)
	}
}

func TestAutoRetireRejectsIdenticalContentOnReplacedInode(t *testing.T) {
	opts, link, path, secret := guidedSavedWireGuardFixture(t)
	prepared, err := prepareProtectedHandoffRemoval(opts, link.ID)
	if err != nil || prepared == nil {
		t.Fatalf("original preparation unavailable: %v", err)
	}
	originalBackup := path + ".original"
	if err := os.Rename(path, originalBackup); err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(path, []byte(secret+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := state.NewFileStore(opts.stateRoot).Update(context.Background(), func(s *state.Snapshot) error {
		if !s.Delete(link.ID) {
			return errors.New("original Link is missing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := prepared.retireAfterRemove(opts); err == nil {
		t.Fatal("identical content on a different inode was mistaken for the original file")
	}
	if actual, err := readPrivateHandoffFile(path); err != nil || actual != secret {
		t.Fatal("post-removal cleanup destroyed substituted byte-identical file", err)
	}
	if actual, err := readPrivateHandoffFile(originalBackup); err != nil || actual != secret {
		t.Fatal("original inode was lost", err)
	}
}

func TestAutoRetireHoldsCanonicalLinkLockAcrossStateAndUnlink(t *testing.T) {
	opts, link, path, _ := guidedSavedWireGuardFixture(t)
	prepared, err := prepareProtectedHandoffRemoval(opts, link.ID)
	if err != nil || prepared == nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(opts.stateRoot)
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, found := snapshot.Find(link.ID)
	if !found {
		t.Fatal("original committed sender missing")
	}
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Delete(link.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release, err := state.NewLockManager(opts.stateRoot).Acquire(context.Background(),
		[]domain.ResourceClaim{app.LinkLockClaim(link.ID)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- prepared.retireAfterRemove(opts) }()
	select {
	case result := <-done:
		_ = release()
		t.Fatalf("cleanup ignored a concurrently held canonical Link lock: %v", result)
	case <-time.After(45 * time.Millisecond):
	}
	// A concurrent writer changes State before post-commit cleanup obtains
	// the Link lock. Cleanup must recheck and retain the original file.
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(record)
		return nil
	}); err != nil {
		_ = release()
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cleanup removed an offer for a now-committed Link")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("post-commit cleanup never released the Link lock")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("concurrent committed sender lost its private original", err)
	}
}

type interruptedMenuMASQUEHost struct {
	observed masquebackend.HostObservation
}

func (h *interruptedMenuMASQUEHost) Inspect(context.Context, domain.Link) (masquebackend.HostObservation, error) {
	return h.observed, nil
}
func (*interruptedMenuMASQUEHost) Preflight(context.Context, domain.Link, bool) error { return nil }
func (h *interruptedMenuMASQUEHost) Start(_ context.Context, link domain.Link) (core.Rollback, error) {
	before := h.observed
	h.observed = masquebackend.HostObservation{UnitExists: true, UnitOwned: true,
		UnitActive: true, InterfaceExists: true, InterfaceOwned: true, InterfaceIndex: 29,
		LocalAddress: link.Addresses.Local, PeerRoute: true, RuntimeReady: true}
	return func(context.Context) error { h.observed = before; return nil }, nil
}
func (h *interruptedMenuMASQUEHost) Stop(context.Context, domain.Link) (core.Rollback, error) {
	// The service/TUN disappeared, but the initiating Engine received an
	// indeterminate result after host effects: only explicit Reconcile can commit.
	h.observed = masquebackend.HostObservation{}
	return nil, core.ErrIndeterminateHostEffect
}

type menuMASQUERetirement struct {
	fail  error
	calls int
}

func (r *menuMASQUERetirement) RetireMatching(context.Context, domain.Link) error {
	r.calls++
	return r.fail
}

type interruptedMenuMASQUEFixture struct {
	options       *runtimeOptions
	host          *interruptedMenuMASQUEHost
	store         *state.FileStore
	id            domain.LinkID
	offerPath     string
	cliOutput     string
	unrelatedID   domain.LinkID
	unrelatedPath string
	retirement    *menuMASQUERetirement
}

func newInterruptedMenuMASQUEFixture(t *testing.T) interruptedMenuMASQUEFixture {
	t.Helper()
	req := masqueInputTestRequest()
	sender, receiver, err := req.makePair(req.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := masque.GeneratePair(sender.ID, sender.MASQUE.TLSServerName, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	root := filepath.Join(t.TempDir(), "state")
	sender, own, err := masquehost.BuildMaterial(root, sender, pair)
	if err != nil {
		t.Fatal(err)
	}
	defer masquehost.ClearFiles(own)
	receiver, files, err := masquehost.BuildMaterial(root, receiver, pair)
	if err != nil {
		t.Fatal(err)
	}
	offer := masqueOfferV1{SchemaVersion: 1, Sender: sender, Receiver: receiver, ReceiverMaterial: files}
	defer offer.Clear()
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	host := &interruptedMenuMASQUEHost{}
	backend, err := masquebackend.New(host)
	if err != nil {
		t.Fatal(err)
	}
	retirer := &menuMASQUERetirement{}
	opts := &runtimeOptions{stateRoot: root, backends: []core.Backend{backend}, masqueRetirementHost: retirer}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.EnsureWithMASQUEProvision(context.Background(), sender, func() error { return nil }, nil); err != nil {
		t.Fatalf("cannot create committed synthetic MASQUE sender: %v", err)
	}
	path, err := prepareProtectedMenuHandoff(opts, sender.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(path, append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := recordMenuHandoffOrigin(opts, sender.ID); err != nil {
		t.Fatal(err)
	}
	cliOutput := filepath.Join(root, "operator-owned-original.stl")
	if err := writeSensitiveHandoff(cliOutput, append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Remove(context.Background(), sender.ID); err == nil {
		t.Fatal("synthetic interrupted host Stop incorrectly committed")
	}
	store := state.NewFileStore(root)
	unrelated, _ := makeLifecycleDesired(t, "e", "10.70.19.0/31")
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: unrelated})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	unrelatedPath, err := protectedMenuHandoffPath(opts, unrelated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSensitiveHandoff(unrelatedPath, []byte("unrelated-private-file\\n")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, pending := snapshot.FindMASQUEOperation(sender.ID); !pending {
		t.Fatal("missing durable interrupted MASQUE Remove journal")
	}
	if _, present := snapshot.Find(sender.ID); !present {
		t.Fatal("interrupted host Remove already deleted committed Link")
	}
	return interruptedMenuMASQUEFixture{opts, host, store, sender.ID, path, cliOutput, unrelated.ID, unrelatedPath, retirer}
}

func TestMASQUEInterruptedRemoveReconcileRetiresExactMenuOriginal(t *testing.T) {
	fixture := newInterruptedMenuMASQUEFixture(t)
	var out, errOut bytes.Buffer
	command := []string{string(fixture.id), "--confirm", string(fixture.id), "--json"}
	// Simulate a still-visible original: failed absence proof must neither
	// consume the pending journal nor delete its private receiver offer.
	fixture.host.observed = masquebackend.HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true}
	if code := linkMASQUEReconcileCommand(command, &out, &errOut, fixture.options); code == 0 {
		t.Fatal("reconciliation without positive absent host proof was accepted")
	}
	if _, err := os.Lstat(fixture.offerPath); err != nil {
		t.Fatal("ambiguous host proof removed private original")
	}
	fixture.host.observed = masquebackend.HostObservation{}
	out.Reset()
	errOut.Reset()
	if code := linkMASQUEReconcileCommand(command, &out, &errOut, fixture.options); code != 0 {
		t.Fatalf("reconciliation could not retire verified original: %d %s", code, out.String())
	}
	var result struct {
		CommittedRemoved bool   `json:"committed_removed"`
		OriginalRetired  bool   `json:"original_retired"`
		Recovery         string `json:"recovery"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.CommittedRemoved ||
		!result.OriginalRetired || result.Recovery != "completed_remove_after_verified_absence" {
		t.Fatalf("inaccurate MASQUE recovered Remove result: %+v %v", result, err)
	}
	if _, err := os.Lstat(fixture.offerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reconciled Remove left original private menu offer", err)
	}
	for _, file := range []string{fixture.cliOutput, fixture.unrelatedPath} {
		if _, err := os.Lstat(file); err != nil {
			t.Fatal("reconciliation deleted another protected file", err)
		}
	}
	snapshot, err := fixture.store.Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 || len(snapshot.MASQUEOperations) != 0 {
		t.Fatalf("recovery did not isolate original Link: %v", err)
	}
	if _, present := snapshot.Find(fixture.unrelatedID); !present {
		t.Fatal("recovery removed unrelated committed Link")
	}
	receipt, found := snapshot.FindMASQUERemovalReceipt(fixture.id)
	if !found || !receipt.Retired || receipt.Purpose != "removed" {
		t.Fatal("reconciled original material was not retired")
	}
}

func TestMASQUECommittedReconcileMaterialFailureHasExactRetireContinuation(t *testing.T) {
	fixture := newInterruptedMenuMASQUEFixture(t)
	fixture.retirement.fail = errors.New("injected private MASQUE material retirement failure")
	command := []string{string(fixture.id), "--confirm", string(fixture.id), "--json"}
	var out, errOut bytes.Buffer
	code := linkMASQUEReconcileCommand(command, &out, &errOut, fixture.options)
	if code == 0 || errOut.Len() != 0 {
		t.Fatalf("post-commit material failure was accepted: code=%d err=%q", code, errOut.String())
	}
	var failure lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &failure); err != nil ||
		failure.Outcome != "removed_cleanup_incomplete" ||
		failure.PartialResult == nil || !failure.PartialResult.Removed ||
		failure.Error == nil || failure.Error.ReasonCode != "masque_material_retirement_incomplete" ||
		failure.Error.Evidence == nil || failure.Error.Evidence.Stage != "credential_retirement" ||
		failure.Error.Evidence.DesiredState != "committed" ||
		!strings.Contains(failure.Error.NextStep, "stl link retire-masque "+string(fixture.id)+" --confirm "+string(fixture.id)) ||
		!strings.Contains(failure.Error.NextStep, "Do not repeat Remove") {
		t.Fatalf("reconcile lost committed removal or misclassified material error: %+v %v", failure, err)
	}
	snapshot, err := fixture.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, exists := snapshot.FindMASQUERemovalReceipt(fixture.id)
	if !exists || receipt.Retired || receipt.Purpose != "removed" ||
		len(snapshot.MASQUEOperations) != 0 || len(snapshot.Links) != 1 {
		t.Fatalf("state was not durably removed before material retirement error: %+v", snapshot)
	}
	origin, err := menuHandoffOriginPath(fixture.options, fixture.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{fixture.offerPath, origin, fixture.cliOutput, fixture.unrelatedPath} {
		if _, err := os.Lstat(protected); err != nil {
			t.Fatalf("material error destroyed original/private file %s: %v", protected, err)
		}
	}
	// Attempting the exact receipt-bound continuation before the error is
	// resolved must preserve the original and report the same committed truth.
	out.Reset()
	if code = linkMASQUERetirementCommand(command, &out, &errOut, fixture.options); code == 0 {
		t.Fatal("unverified credential retirement allowed private offer deletion")
	}
	var retireFailure lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &retireFailure); err != nil ||
		retireFailure.Outcome != "removed_cleanup_incomplete" ||
		retireFailure.PartialResult == nil || !retireFailure.PartialResult.Removed ||
		retireFailure.Error == nil || retireFailure.Error.ReasonCode != "masque_material_retirement_incomplete" {
		t.Fatalf("receipt-bound retirement error lost committed removal: %+v %v", retireFailure, err)
	}
	if _, err := os.Lstat(fixture.offerPath); err != nil {
		t.Fatal("failed continuation deleted unretired receiver offer", err)
	}
	// The existing, explicitly confirmed command now completes BOTH stages,
	// using the previously committed original material receipt and the exact
	// menu-origin identity. No replay of Remove or host Stop is performed.
	fixture.retirement.fail = nil
	out.Reset()
	errOut.Reset()
	if code = linkMASQUERetirementCommand(command, &out, &errOut, fixture.options); code != 0 || errOut.Len() != 0 {
		t.Fatalf("exact retirement continuation failed: %d %q %q", code, out.String(), errOut.String())
	}
	var success struct {
		Retired bool `json:"retired"`
	}
	if err := json.Unmarshal(out.Bytes(), &success); err != nil || !success.Retired {
		t.Fatalf("retirement continuation did not confirm success: %+v %v", success, err)
	}
	for _, retired := range []string{fixture.offerPath, origin} {
		if _, err := os.Lstat(retired); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("exact retired original artifact survived: %s %v", retired, err)
		}
	}
	for _, kept := range []string{fixture.cliOutput, fixture.unrelatedPath} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("continuation touched independent private file %s: %v", kept, err)
		}
	}
	snapshot, err = fixture.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, exists = snapshot.FindMASQUERemovalReceipt(fixture.id)
	if !exists || !receipt.Retired || len(snapshot.MASQUEOperations) != 0 ||
		len(snapshot.Links) != 1 {
		t.Fatal("original receipt or unrelated State lost during continuation")
	}
	if _, exists := snapshot.Find(fixture.unrelatedID); !exists {
		t.Fatal("continuation removed unrelated Link")
	}
	// A repeated retirement is idempotent and never regenerates an offer.
	out.Reset()
	if code = linkMASQUERetirementCommand(command, &out, &errOut, fixture.options); code != 0 {
		t.Fatalf("already retired original could not be reverified: %d %q", code, out.String())
	}
}

func TestMASQUEMaterialRetirementFailureOperatorAndTerminalTruth(t *testing.T) {
	fixture := newInterruptedMenuMASQUEFixture(t)
	fixture.retirement.fail = errors.New("simulated original mTLS retirement failure")
	var stdout, stderr bytes.Buffer
	id := string(fixture.id)
	rc := linkMASQUEReconcileCommand([]string{id, "--confirm", id}, &stdout, &stderr, fixture.options)
	if rc == 0 || !strings.Contains(stderr.String(), "already removed") ||
		!strings.Contains(stderr.String(), "MASQUE mTLS material retirement is incomplete") ||
		!strings.Contains(stderr.String(), "retire-masque") ||
		!strings.Contains(stderr.String(), "Do not repeat Remove") {
		t.Fatalf("plain CLI lost committed recovery truth: rc=%d err=%s", rc, stderr.String())
	}
	evidence := &stlerr.OperationEvidence{Stage: "credential_retirement", HostMutation: "attempted",
		DesiredState: "committed", Rollback: "not_required"}
	var terminal bytes.Buffer
	renderTerminalLifecycleFailure(&terminal, &stlerr.Error{
		ReasonCode: "masque_material_retirement_incomplete",
		Detail:     "mTLS original material cleanup pending",
		NextStep:   "Do not repeat Remove; run retire-masque after verifying the original receipt",
	}, evidence)
	for _, expected := range []string{"Tunnel removal", "Canonical Engine Remove committed",
		"MASQUE mTLS material", "Private handoff", "Do not repeat Remove"} {
		if !strings.Contains(terminal.String(), expected) {
			t.Fatalf("terminal omitted material/offer separation %q: %s", expected, terminal.String())
		}
	}
}

func TestMASQUEInterruptedRemoveCleanupFailureReportsCommittedTruth(t *testing.T) {
	fixture := newInterruptedMenuMASQUEFixture(t)
	if err := os.Rename(fixture.offerPath, fixture.offerPath+".original"); err != nil {
		t.Fatal(err)
	}
	const unrelated = "unverified-private-generation\n"
	if err := writeSensitiveHandoff(fixture.offerPath, []byte(unrelated)); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	command := []string{string(fixture.id), "--confirm", string(fixture.id), "--json"}
	code := linkMASQUEReconcileCommand(command, &out, &errOut, fixture.options)
	if code == 0 {
		t.Fatal("incomplete protected cleanup was silently reported as full success")
	}
	var failure lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &failure); err != nil ||
		failure.Outcome != "removed_cleanup_incomplete" || failure.PartialResult == nil ||
		!failure.PartialResult.Removed || failure.Error == nil ||
		failure.Error.ReasonCode != "protected_handoff_cleanup_incomplete" {
		t.Fatalf("reconciled removal did not preserve committed-outcome truth: %+v %v", failure, err)
	}
	if actual, err := os.ReadFile(fixture.offerPath); err != nil || string(actual) != unrelated {
		t.Fatal("reconciliation erased an unverified private file", err)
	}
	for _, file := range []string{fixture.cliOutput, fixture.unrelatedPath} {
		if _, err := os.Lstat(file); err != nil {
			t.Fatal("reconciled Remove touched another protected file", err)
		}
	}
	snapshot, err := fixture.store.Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 || len(snapshot.MASQUEOperations) != 0 {
		t.Fatal("reconciled Remove did not isolate Link despite protected cleanup mismatch", err)
	}
	if _, present := snapshot.Find(fixture.unrelatedID); !present {
		t.Fatal("failed cleanup removed unrelated committed Link")
	}
	// Once MASQUE material is already retired, the receipt-bound command
	// still refuses to delete an unknown substituted offer.
	out.Reset()
	if code := linkMASQUERetirementCommand(command, &out, &errOut, fixture.options); code == 0 {
		t.Fatal("retirement continuation adopted a substituted private offer")
	}
	var continuation lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &continuation); err != nil ||
		continuation.Outcome != "removed_cleanup_incomplete" ||
		continuation.Error == nil || continuation.Error.ReasonCode != "protected_handoff_cleanup_incomplete" ||
		continuation.PartialResult == nil || !continuation.PartialResult.Removed {
		t.Fatalf("retirement cleanup failure did not preserve committed truth: %+v %v", continuation, err)
	}
	if actual, err := os.ReadFile(fixture.offerPath); err != nil || string(actual) != unrelated {
		t.Fatal("receipt-bound continuation erased substituted private offer", err)
	}
}
