package app

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// These deterministic transitions verify Engine policy. They are not proof
// of a physical reboot, namespace extinction or a real systemd transaction.
func TestManagedQUICCompleteAttemptAbandonmentRequiresLaterAttemptKernel(t *testing.T) {
	ctx := context.Background()
	e, b, link := managedQUICEngineFixture(t)
	b.attestError = true
	if _, err := e.EnsureWithQUICCredential(ctx, link, []byte("fixture key"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil); err == nil {
		t.Fatal("failed attestation committed")
	}
	before, _ := b.store.Load(ctx)
	op, ok := before.FindQUICCrashOperation(link.ID)
	if !ok || op.Managed.KernelBootID != b.boot || op.Managed.KernelBootSource == "" || b.rollbackCount != 1 {
		t.Fatal("attempt provenance or bounded rollback missing")
	}
	if _, err := e.ReconcileQUICAfterKernelExtinction(ctx, link.ID); err == nil || b.recoveryCalls != 0 {
		t.Fatal("successful rollback/current absence substituted for kernel extinction")
	}
	after, _ := b.store.Load(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("same-kernel recovery changed journal")
	}
	b.boot = testWSSBootAfter
	calls := b.applyCount
	result, err := e.ReconcileQUICAfterKernelExtinction(ctx, link.ID)
	if err != nil || !result.Changed || result.Removed || b.applyCount != calls {
		t.Fatalf("read-only initial abandonment failed: %+v %v", result, err)
	}
	s, err := b.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := s.FindQUICAbandonmentReceipt(link.ID)
	if !ok || r.Validate() != nil || !sameQUICOperation(r.Operation, op) || len(s.Links) != 0 || len(s.QUICCrashOperations) != 0 {
		t.Fatal("exact initial receipt did not atomically replace journal")
	}
	if _, err := e.EnsureWithQUICCredential(ctx, link, []byte("fixture key"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil); err == nil {
		t.Fatal("abandoned handoff identity could be resurrected")
	}
	retirer := e.quicRetirement.(*managedQUICRetirement)
	if err := e.RetireQUICCredential(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.RetireQUICCredential(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	if retirer.abandonedCalls != 1 || retirer.abandonedVerifications != 1 {
		t.Fatal("retired abandoned material was deleted twice instead of read-only verified")
	}
}

func TestManagedQUICRecoveryKeepsPartialMaterialAndForeignVacancyQuarantined(t *testing.T) {
	for _, failure := range []string{"partial-material", "occupied-host", "material-changes", "untrusted-boot", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			e, b, link := managedQUICEngineFixture(t)
			b.attestError = true
			if _, err := e.EnsureWithQUICCredential(ctx, link, []byte("fixture key"), managedQUICKeyStore{b: b}, quic.CredentialBundle{}, nil); err == nil {
				t.Fatal("failed initial attempt committed")
			}
			before, _ := b.store.Load(ctx)
			b.boot = testWSSBootAfter
			read := e.quicInspectRecordedGeneration
			reads := 0
			switch failure {
			case "partial-material":
				e.quicInspectRecordedGeneration = func(context.Context, string, quic.Plan, uint16, string, quic.HelperConfigIdentity) (state.QUICFileIdentity, error) {
					return state.QUICFileIdentity{}, fmt.Errorf("no complete original receipt")
				}
			case "occupied-host":
				b.recoveryVacancyError = true
			case "material-changes":
				e.quicInspectRecordedGeneration = func(c context.Context, r string, p quic.Plan, port uint16, n string, w quic.HelperConfigIdentity) (state.QUICFileIdentity, error) {
					f, err := read(c, r, p, port, n, w)
					reads++
					if reads > 1 {
						f.ReceiptInode++
					}
					return f, err
				}
			case "untrusted-boot":
				e.kernelBootID = func() (string, error) { return "", fmt.Errorf("untrusted host proc") }
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			calls := b.applyCount
			if _, err := e.ReconcileQUICAfterKernelExtinction(ctx, link.ID); err == nil {
				t.Fatal("uncertain recovery was accepted")
			}
			after, _ := b.store.Load(context.Background())
			if !reflect.DeepEqual(before, after) || b.applyCount != calls {
				t.Fatal("refused recovery changed host or protected reservations")
			}
		})
	}
}

func TestManagedQUICInterruptedCommittedRecoveryPreservesOrRemovesExactOwner(t *testing.T) {
	for _, operation := range []string{"ensure", "remove"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			e, b, link := managedQUICEngineFixture(t)
			createManagedQUIC(t, e, b, link)
			s, _ := b.store.Load(ctx)
			prior, _ := s.Find(link.ID)
			// Record a new interrupted attempt in a kernel newer than the
			// committed original. Its CURRENT boot must still block recovery.
			b.boot = testWSSBootAfter
			host, err := quicPlanForManagedLink(link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := host.HostPlan(link.WireGuard.ListenPort)
			if err != nil {
				t.Fatal(err)
			}
			g := prior.QUICGeneration
			op := state.QUICCrashOperation{Plan: plan, Addresses: link.Addresses, WireGuard: link.WireGuard, Nonce: strings.Repeat("b", 32), Resources: prior.OwnedResources,
				CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization, HelperConfigSHA256: g.Files.HelperConfig,
				ExecutablePath: g.ExecutablePath, ExecutableSHA256: g.ExecutableSHA256, ExecutableDevice: g.ExecutableDevice, ExecutableInode: g.ExecutableInode,
				Managed: &state.QUICManagedOperation{Version: 1, KernelBootID: b.boot, KernelBootSource: g.KernelBootSource, Intent: link, Operation: operation, HadCommittedLink: true, OriginalGeneration: g}}
			if err := b.store.Update(ctx, func(s *state.Snapshot) error { s.QUICCrashOperations = append(s.QUICCrashOperations, op); return nil }); err != nil {
				t.Fatal(err)
			}
			delete(b.owners, link.ID)
			if _, err := e.ReconcileQUICAfterKernelExtinction(ctx, link.ID); err == nil {
				t.Fatal("older committed birth substituted for CURRENT interrupted attempt provenance")
			}
			b.boot = testWSSBootThird
			result, err := e.ReconcileQUICAfterKernelExtinction(ctx, link.ID)
			if err != nil {
				t.Fatal(err)
			}
			s, err = b.store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.QUICCrashOperations) != 0 || len(s.QUICAbandonmentReceipts) != 0 {
				t.Fatal("committed recovery created an initial-attempt receipt or kept its journal")
			}
			if operation == "ensure" {
				current, ok := s.Find(link.ID)
				if !ok || !sameQUICRecord(prior, current) || result.Removed {
					t.Fatal("repair recovery rewrote original owner")
				}
				b.attestError = false
				if _, err := e.RestoreAll(ctx); err != nil {
					t.Fatal(err)
				}
				s, _ = b.store.Load(ctx)
				current, _ = s.Find(link.ID)
				if current.QUICGeneration.KernelBootID != b.boot || current.QUICGeneration.Files != prior.QUICGeneration.Files {
					t.Fatal("ordinary restore did not retain original protected issuance")
				}
			} else {
				r, ok := s.FindRemovalReceipt(link.ID)
				if !ok || r.QUICGeneration != g || r.QUICOriginalTermination != state.QUICOriginalKernelGenerationExtinct || !result.Removed {
					t.Fatal("interrupted Remove did not finish exact original termination receipt")
				}
				if err := e.RetireQUICCredential(ctx, link.ID); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestManagedQUICRecoveryNeverConsumesSourceOnlyJournal(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	// The fixture is an unprepared public intent. Use the real source-only
	// admission to assign its original nonce and complete legacy claims.
	if _, err := e.PrepareQUICCrash(context.Background(), quicCrashIntentFixture(), &quicVacancyProbe{}); err != nil {
		t.Fatal(err)
	}
	before, _ := b.store.Load(context.Background())
	b.boot = testWSSBootAfter
	if _, err := e.ReconcileQUICAfterKernelExtinction(context.Background(), link.ID); err == nil || b.recoveryCalls != 0 {
		t.Fatal("source-only birth journal became managed recovery authority")
	}
	after, _ := b.store.Load(context.Background())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("source-only journal changed")
	}
}

func TestManagedQUICExpiredTLSBlocksEnsureButExactRecordedRemoveWorks(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	createManagedQUIC(t, e, b, link)
	semanticReads := 0
	e.quicInspectGeneration = func(string, quic.Plan, uint16, string, string, quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
		semanticReads++
		return quic.HelperConfigIdentity{}, fmt.Errorf("certificate expired")
	}
	if _, err := e.Ensure(context.Background(), link); err == nil || semanticReads != 1 {
		t.Fatal("expired generation granted current launch trust")
	}
	if _, err := e.Remove(context.Background(), link.ID); err != nil {
		t.Fatal(err)
	}
	if semanticReads != 1 {
		t.Fatal("recorded Remove unnecessarily required present TLS validity")
	}
}

func TestManagedQUICRemoveRejectsChangedRecordedReceipt(t *testing.T) {
	e, b, link := managedQUICEngineFixture(t)
	createManagedQUIC(t, e, b, link)
	before, _ := b.store.Load(context.Background())
	calls := b.applyCount
	read := e.quicInspectRecordedGeneration
	e.quicInspectRecordedGeneration = func(c context.Context, r string, p quic.Plan, port uint16, n string, w quic.HelperConfigIdentity) (state.QUICFileIdentity, error) {
		f, err := read(c, r, p, port, n, w)
		f.ReceiptInode++
		return f, err
	}
	if _, err := e.Remove(context.Background(), link.ID); err == nil {
		t.Fatal("replacement receipt granted original removal authority")
	}
	after, _ := b.store.Load(context.Background())
	if !reflect.DeepEqual(before, after) || b.applyCount != calls {
		t.Fatal("recorded material denial mutated host or State")
	}
}

func TestManagedQUICPlanKeepsCanonicalManagedHelperPolicy(t *testing.T) {
	_, _, link := managedQUICEngineFixture(t)
	want, err := quic.PlanFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	got, err := quicPlanForManagedLink(link)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("Engine rebuilt public plan and lost the fixed managed startup policy")
	}
}
