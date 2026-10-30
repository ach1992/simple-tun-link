package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type managedQUICObservation struct {
	claims []domain.ResourceClaim
	index  int
}

func (o managedQUICObservation) ObservedResources() []domain.ResourceClaim { return o.claims }
func (o managedQUICObservation) QUICOriginalIfIndex() int                  { return o.index }

type managedQUICPlan struct {
	claims []domain.ResourceClaim
	empty  bool
	index  int
}

func (p managedQUICPlan) Empty() bool                       { return p.empty }
func (p managedQUICPlan) Resources() []domain.ResourceClaim { return p.claims }
func (p managedQUICPlan) QUICOriginalRemoveIndex() int      { return p.index }

// This is an Engine ordering model, not a real host or reboot witness. Native
// configuration, guard and helper implementations have their own acceptance.
type managedQUICBackend struct {
	store                                 *state.FileStore
	events                                []string
	boot                                  string
	owners                                map[domain.LinkID]managedQUICObservation
	nextIndex                             int
	active                                bool
	applyCount, rollbackCount, closeCount int
	attestError                           bool
	uncertainApply                        bool
	closedWithOwner                       bool
	recoveryCalls                         int
	recoveryVacancyError                  bool
}

func (b *managedQUICBackend) Kind() domain.Backend { return domain.BackendWireGuardQUIC }
func (b *managedQUICBackend) Inspect(_ context.Context, link domain.Link) (backend.Observation, error) {
	return b.owners[link.ID], nil
}
func (b *managedQUICBackend) Plan(_ context.Context, req backend.Request, observed backend.Observation) (backend.Plan, error) {
	p, err := composition.Build(req.Link, composition.CarrierForLink(req.Link))
	if err != nil {
		return nil, err
	}
	claims, err := composition.WireGuardProviderClaims(req.Link.ID, req.Link.Addresses.Local, req.Link.WireGuard)
	if err != nil {
		return nil, err
	}
	claims, err = validatedClaims(append(claims, p.CarrierClaims()...))
	if err != nil {
		return nil, err
	}
	o := observed.(managedQUICObservation)
	if req.Operation == backend.OperationRemove {
		return managedQUICPlan{claims: claims, empty: o.index == 0, index: o.index}, nil
	}
	return managedQUICPlan{claims: claims, empty: o.index > 0}, nil
}
func (b *managedQUICBackend) Validate(context.Context, backend.Request, backend.Observation, backend.Plan) error {
	if !b.active {
		return fmt.Errorf("scope missing at Validate")
	}
	b.events = append(b.events, "validate")
	return nil
}
func (b *managedQUICBackend) Apply(ctx context.Context, req backend.Request, _ backend.Observation, p backend.Plan) (backend.Rollback, error) {
	if !b.active {
		return nil, fmt.Errorf("scope missing at Apply")
	}
	op, ok := backend.QUICManagedOperation(ctx)
	s, err := b.store.Load(ctx)
	actual, present := s.FindQUICCrashOperation(req.Link.ID)
	if err != nil || !ok || !present || !sameQUICOperation(actual, op) {
		return nil, fmt.Errorf("durable exact journal missing at Apply")
	}
	b.events = append(b.events, "apply")
	b.applyCount++
	before := b.owners[req.Link.ID]
	if req.Operation == backend.OperationEnsure {
		b.nextIndex++
		b.owners[req.Link.ID] = managedQUICObservation{claims: p.Resources(), index: b.nextIndex}
	} else {
		delete(b.owners, req.Link.ID)
	}
	if b.uncertainApply {
		return nil, backend.ErrIndeterminateHostEffect
	}
	return func(context.Context) error {
		if !b.active {
			return fmt.Errorf("scope closed before rollback")
		}
		b.events = append(b.events, "rollback")
		b.rollbackCount++
		if before.index == 0 {
			delete(b.owners, req.Link.ID)
		} else {
			b.owners[req.Link.ID] = before
		}
		return nil
	}, nil
}
func (b *managedQUICBackend) Verify(_ context.Context, req backend.Request) (backend.Observation, error) {
	b.events = append(b.events, "verify")
	o := b.owners[req.Link.ID]
	if (req.Operation == backend.OperationEnsure) != (o.index > 0) {
		return nil, fmt.Errorf("unexpected fake host presence")
	}
	return o, nil
}
func (b *managedQUICBackend) BeginQUIC(ctx context.Context, link domain.Link, _ *state.QUICGeneration) (context.Context, func() error, error) {
	if b.active {
		return nil, nil, fmt.Errorf("nested managed scope")
	}
	b.active = true
	b.events = append(b.events, "begin")
	return ctx, func() error {
		b.events = append(b.events, "close")
		b.closeCount++
		b.active = false
		s, err := b.store.Load(context.Background())
		if err == nil {
			_, b.closedWithOwner = s.Find(link.ID)
		}
		return nil
	}, nil
}
func (b *managedQUICBackend) AttestQUIC(ctx context.Context, link domain.Link) (state.QUICGeneration, error) {
	if !b.active {
		return state.QUICGeneration{}, fmt.Errorf("scope closed before attestation")
	}
	b.events = append(b.events, "attest")
	if b.attestError {
		return state.QUICGeneration{}, fmt.Errorf("material or process drift")
	}
	if prior, ok := backend.QUICGenerationFromContext(ctx); ok {
		prior.WGIfIndex = b.owners[link.ID].index
		prior.KernelBootID = b.boot
		return prior, nil
	}
	op, ok := backend.QUICManagedOperation(ctx)
	if !ok {
		return state.QUICGeneration{}, fmt.Errorf("new creation journal missing")
	}
	return state.QUICGeneration{Version: 1, OriginNonce: backend.QUICOrigin(ctx), MaterialNonce: op.Nonce, KernelBootID: b.boot, KernelBootSource: hostidentity.VerifiedHostBootSourceV1, NetworkNS: "net:[42]", WGIfIndex: b.owners[link.ID].index,
		GuardTableHandle: 1, GuardChainHandle: 2, GuardRuleHandle: 3,
		Files:          state.QUICFileIdentity{Certificate: op.CertificateSHA256, TLSKey: strings.Repeat("f", 64), TrustCA: op.TrustCASHA256, Authorization: op.AuthorizationSHA256, HelperConfig: op.HelperConfigSHA256, DirectoryDevice: 1, DirectoryInode: 5, ReceiptDevice: 1, ReceiptInode: 6},
		ExecutablePath: op.ExecutablePath, ExecutableSHA256: op.ExecutableSHA256, ExecutableDevice: op.ExecutableDevice, ExecutableInode: op.ExecutableInode}, nil
}
func (b *managedQUICBackend) QUICHostVacant(ctx context.Context, link domain.Link) (bool, error) {
	if !backend.HasQUICColdBootExtinctionWitness(ctx, link.ID) && !backend.HasQUICWGDeletionWitness(ctx, link.ID) {
		return false, fmt.Errorf("positive original termination missing")
	}
	return b.owners[link.ID].index == 0, nil
}
func (b *managedQUICBackend) QUICRecoveryHostVacant(ctx context.Context, op state.QUICCrashOperation) (bool, error) {
	b.recoveryCalls++
	if b.recoveryVacancyError {
		return false, fmt.Errorf("fixture host vacancy unverified")
	}
	return b.QUICHostVacant(ctx, op.Managed.Intent)
}

type managedQUICKeyStore struct {
	b    *managedQUICBackend
	fail bool
}

func (k managedQUICKeyStore) EnsureRecipient(domain.LinkID, []byte, string) error {
	return fmt.Errorf("idempotent adopter must never create a new QUIC key")
}
func (k managedQUICKeyStore) PutRecipient(id domain.LinkID, _ []byte, _ string) error {
	s, err := k.b.store.Load(context.Background())
	if err != nil {
		return err
	}
	op, ok := s.FindQUICCrashOperation(id)
	if !ok || op.Managed == nil {
		return fmt.Errorf("key created before managed journal")
	}
	k.b.events = append(k.b.events, "key")
	if k.fail {
		return fmt.Errorf("private key already exists")
	}
	return nil
}

type managedQUICRetirement struct{ calls, abandonedCalls, abandonedVerifications int }

func (r *managedQUICRetirement) RetireAfterRemove(context.Context, domain.Link, state.QUICGeneration) error {
	r.calls++
	return nil
}
func (r *managedQUICRetirement) VerifyAbsent(context.Context, domain.Link, state.QUICGeneration) error {
	return nil
}
func (r *managedQUICRetirement) RetireAfterAbandonment(context.Context, state.QUICAbandonmentReceipt) error {
	r.abandonedCalls++
	return nil
}
func (r *managedQUICRetirement) VerifyAbandonmentAbsent(context.Context, state.QUICAbandonmentReceipt) error {
	r.abandonedVerifications++
	return nil
}

func managedQUICEngineFixture(t *testing.T) (*Engine, *managedQUICBackend, domain.Link) {
	t.Helper()
	root := t.TempDir()
	store := state.NewFileStore(root)
	b := &managedQUICBackend{store: store, boot: testWSSBootBefore, owners: map[domain.LinkID]managedQUICObservation{}, nextIndex: 100}
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	e.kernelBootID = func() (string, error) { return b.boot, nil }
	e.SetQUICRetirementStore(&managedQUICRetirement{})
	intent := quicCrashIntentFixture()
	intent.WireGuard.PeerPort = intent.Plan.Local.RemoteWGUDPPort
	link := domain.Link{ID: intent.Plan.Local.LinkID, DisplayName: "managed-quic", Backend: domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		Underlay: domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: intent.Plan.Physical.Addr()}, Addresses: intent.Addresses, WireGuard: intent.WireGuard,
		QUIC: domain.QUICOptions{Role: "dial", UDPPort: intent.Plan.Physical.Port(), ForwardUDPPort: intent.Plan.Local.LocalHelperUDPPort, TLSServerName: intent.Plan.TLSName}}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	expected := quicExpectedMaterialIdentity(intent)
	e.quicPreviewMaterial = func(string, quic.Plan, uint16, string, quic.CredentialBundle) (quic.HelperConfigIdentity, error) {
		b.events = append(b.events, "preview")
		return expected, nil
	}
	e.quicStageGeneration = func(ctx context.Context, _ string, p quic.Plan, _ uint16, _ string, nonce string, _ quic.CredentialBundle, want quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
		s, err := store.Load(ctx)
		if err != nil {
			return quic.HelperConfigIdentity{}, err
		}
		op, ok := s.FindQUICCrashOperation(p.LinkID)
		if !ok || op.Managed == nil || op.Nonce != nonce {
			return quic.HelperConfigIdentity{}, fmt.Errorf("material staged before durable exact journal")
		}
		b.events = append(b.events, "stage")
		return want, nil
	}
	e.quicInspectGeneration = func(string, quic.Plan, uint16, string, string, quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
		return expected, nil
	}
	e.quicInspectRecordedGeneration = func(context.Context, string, quic.Plan, uint16, string, quic.HelperConfigIdentity) (state.QUICFileIdentity, error) {
		return state.QUICFileIdentity{Certificate: expected.Credentials.CertificateSHA256, TLSKey: strings.Repeat("f", 64), TrustCA: expected.Credentials.TrustCASHA256, Authorization: expected.Credentials.AuthorizationSHA256, HelperConfig: expected.ConfigSHA256, DirectoryDevice: 1, DirectoryInode: 5, ReceiptDevice: 1, ReceiptInode: 6}, nil
	}
	return e, b, link
}

func createManagedQUIC(t *testing.T, e *Engine, b *managedQUICBackend, link domain.Link) {
	t.Helper()
	if _, err := e.EnsureWithQUICCredential(context.Background(), link, []byte("private fixture credential"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestManagedQUICJournalStageHandoffScopeAndAtomicCommit(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	result, err := e.EnsureWithQUICCredential(context.Background(), link, []byte("sensitive fixture"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, func() error { b.events = append(b.events, "handoff"); return nil })
	if err != nil || !result.Changed {
		t.Fatalf("managed creation failed: %+v %v", result, err)
	}
	want := []string{"preview", "key", "stage", "begin", "handoff", "validate", "apply", "verify", "attest", "close"}
	if !reflect.DeepEqual(b.events, want) || !b.closedWithOwner || b.active {
		t.Fatalf("wrong original lifetime/order: %v", b.events)
	}
	s, err := state.NewFileStore(b.store.RootDir()).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r, ok := s.Find(link.ID)
	if !ok || r.QUICGeneration.Validate(link) != nil || len(s.QUICCrashOperations) != 0 {
		t.Fatal("verified original generation did not atomically replace journal")
	}
	calls := b.applyCount
	b.events = nil
	result, err = e.Ensure(context.Background(), link)
	if err != nil || result.Changed || b.applyCount != calls {
		t.Fatalf("committed Ensure is not idempotent: %+v %v", result, err)
	}
	after, _ := b.store.Load(context.Background())
	if !reflect.DeepEqual(s, after) {
		t.Fatal("no-op Ensure rewrote provenance")
	}
}

func TestManagedQUICFailureQuarantineAndDependencyScope(t *testing.T) {
	for _, stage := range []string{"key", "material", "handoff", "attest", "uncertain-apply"} {
		t.Run(stage, func(t *testing.T) {
			e, b, link := managedQUICEngineFixture(t)
			keys := managedQUICKeyStore{b: b}
			var handoff func() error
			switch stage {
			case "key":
				keys.fail = true
			case "material":
				e.quicStageGeneration = func(context.Context, string, quic.Plan, uint16, string, string, quic.CredentialBundle, quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
					return quic.HelperConfigIdentity{}, fmt.Errorf("material failure")
				}
			case "handoff":
				handoff = func() error { return fmt.Errorf("handoff publication failed") }
			case "attest":
				b.attestError = true
			case "uncertain-apply":
				b.uncertainApply = true
			}
			if _, err := e.EnsureWithQUICCredential(context.Background(), link, []byte("fixture private key"), keys, quic.CredentialBundle{}, handoff); err == nil {
				t.Fatal("failed transaction reported success")
			}
			s, err := b.store.Load(context.Background())
			if err != nil || len(s.Links) != 0 || len(s.QUICCrashOperations) != 1 || s.QUICCrashOperations[0].Managed == nil {
				t.Fatalf("uncertain operation lost quarantine: %v", err)
			}
			if stage == "attest" && b.rollbackCount != 1 {
				t.Fatal("known owned effect not rolled back within retained scope")
			}
			if stage == "uncertain-apply" && (b.rollbackCount != 0 || b.owners[link.ID].index == 0) {
				t.Fatal("uncertain effect was destroyed")
			}
			if stage != "attest" && stage != "uncertain-apply" && b.applyCount != 0 {
				t.Fatal("pre-effect failure reached Apply")
			}
			calls := b.applyCount
			if _, err := e.Ensure(context.Background(), link); err == nil || b.applyCount != calls {
				t.Fatal("quarantined initial journal was replayed")
			}
		})
	}
}

type quicUncertainCommitStore struct {
	*state.FileStore
	fail bool
}

func (s *quicUncertainCommitStore) Update(ctx context.Context, fn func(*state.Snapshot) error) error {
	if err := s.FileStore.Update(ctx, fn); err != nil {
		return err
	}
	current, err := s.FileStore.Load(ctx)
	if err != nil {
		return err
	}
	if s.fail && len(current.Links) > 0 {
		s.fail = false
		return &state.PublicationError{Cause: errors.New("injected post-publication fsync failure")}
	}
	return nil
}

func TestManagedQUICVisibleUnconfirmedPublicationPreservesHost(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	e.store = &quicUncertainCommitStore{FileStore: b.store, fail: true}
	_, err := e.EnsureWithQUICCredential(context.Background(), link, []byte("fixture private key"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil)
	evidence := stlerr.EvidenceOf(err)
	if err == nil || evidence == nil || evidence.DesiredState != "visible_unconfirmed" || b.rollbackCount != 0 || b.owners[link.ID].index == 0 || !b.closedWithOwner {
		t.Fatalf("publication uncertainty destroyed host or lost evidence: %v %+v", err, evidence)
	}
	s, _ := b.store.Load(context.Background())
	if len(s.Links) != 1 || len(s.QUICCrashOperations) != 0 {
		t.Fatal("published transaction was not retained")
	}
}

func TestManagedQUICMissingOriginalRequiresTrustedNewKernel(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	createManagedQUIC(t, e, b, link)
	before, _ := b.store.Load(context.Background())
	prior, _ := before.Find(link.ID)
	delete(b.owners, link.ID)
	calls := b.applyCount
	for _, operation := range []func() error{
		func() error { _, err := e.Ensure(context.Background(), link); return err },
		func() error { _, err := e.RestoreAll(context.Background()); return err },
		func() error { _, err := e.Remove(context.Background(), link.ID); return err },
	} {
		if err := operation(); err == nil {
			t.Fatal("same-boot absent original granted recreation or retirement")
		}
	}
	after, _ := b.store.Load(context.Background())
	if !reflect.DeepEqual(before, after) || b.applyCount != calls {
		t.Fatal("missing same-kernel original altered owner or journal")
	}
	b.boot = testWSSBootAfter
	if _, err := e.RestoreAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored, _ := b.store.Load(context.Background())
	current, _ := restored.Find(link.ID)
	if current.QUICGeneration.KernelBootID != testWSSBootAfter || current.QUICGeneration.WGIfIndex == prior.QUICGeneration.WGIfIndex || current.QUICGeneration.MaterialNonce != prior.QUICGeneration.MaterialNonce || current.QUICGeneration.Files != prior.QUICGeneration.Files {
		t.Fatal("trusted new-generation restore replaced credentials or reused stale host identity")
	}
	if _, err := e.Remove(context.Background(), link.ID); err != nil {
		t.Fatal(err)
	}
	removed, _ := b.store.Load(context.Background())
	receipt, ok := removed.FindRemovalReceipt(link.ID)
	if !ok || receipt.QUICOriginalTermination != state.QUICOriginalExactIfIndexDeleted || !receipt.Retired || len(removed.QUICCrashOperations) != 0 {
		t.Fatal("managed Remove did not atomically publish/consume exact receipt")
	}
}

func TestManagedQUICCancellationBeforeJournalHasNoPrivateOrHostEffect(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.EnsureWithQUICCredential(ctx, link, []byte("fixture private key"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil); err == nil {
		t.Fatal("canceled create accepted")
	}
	s, err := b.store.Load(context.Background())
	if err != nil || len(s.QUICCrashOperations) != 0 || b.applyCount != 0 || len(b.events) != 0 {
		t.Fatal("canceled preflight had effects")
	}
}

func TestManagedQUICRepeatedImportCannotIgnoreDifferentPrivateKey(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	createManagedQUIC(t, e, b, link)
	before, _ := b.store.Load(context.Background())
	calls := b.applyCount
	_, err := e.EnsureWithQUICCredential(context.Background(), link, []byte("wrong receiver credential"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil)
	if err == nil {
		t.Fatal("repeat import ignored a different private WireGuard credential")
	}
	after, _ := b.store.Load(context.Background())
	if !reflect.DeepEqual(before, after) || b.applyCount != calls {
		t.Fatal("bad repeat credential mutated committed owner")
	}
}
