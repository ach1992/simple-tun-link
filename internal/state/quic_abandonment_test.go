package state

import (
	"context"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

func TestQUICAbandonmentRequiresExactInitialJournalAndLaterKernel(t *testing.T) {
	ctx := context.Background()
	op, record := managedQUICStateFixture(t)
	r := QUICAbandonmentReceipt{Operation: op, Files: record.QUICGeneration.Files, ReconciledKernelBootID: "11234567-89ab-4cde-8fab-0123456789ab", ReconciledKernelBootSource: hostidentity.VerifiedHostBootSourceV1}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	store := NewFileStore(t.TempDir())
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICAbandonmentReceipts = append(s.QUICAbandonmentReceipts, r); return nil }); err == nil {
		t.Fatal("abandonment receipt minted without its original unresolved journal")
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICCrashOperations = append(s.QUICCrashOperations, op); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*QUICAbandonmentReceipt){
		func(r *QUICAbandonmentReceipt) { r.ReconciledKernelBootID = op.Managed.KernelBootID },
		func(r *QUICAbandonmentReceipt) { r.ReconciledKernelBootSource = "" },
		func(r *QUICAbandonmentReceipt) { r.Files.ReceiptInode = 0 },
		func(r *QUICAbandonmentReceipt) { r.Operation.Managed.HadCommittedLink = true },
		func(r *QUICAbandonmentReceipt) { r.Retired = true },
	} {
		candidate := cloneQUICAbandonment(r)
		change(&candidate)
		before, _ := store.Load(ctx)
		if err := store.Update(ctx, func(s *Snapshot) error {
			s.DeleteQUICManagedOperation(op.Plan.Local.LinkID)
			s.QUICAbandonmentReceipts = append(s.QUICAbandonmentReceipts, candidate)
			return nil
		}); err == nil {
			t.Fatal("unproved initial termination/material receipt accepted")
		}
		after, _ := store.Load(ctx)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("denied abandonment changed journal")
		}
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.DeleteQUICManagedOperation(op.Plan.Local.LinkID)
		s.QUICAbandonmentReceipts = append(s.QUICAbandonmentReceipts, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileStore(store.RootDir()).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := s.FindQUICAbandonmentReceipt(op.Plan.Local.LinkID)
	if !ok || !reflect.DeepEqual(actual, r) || len(s.QUICCrashOperations) != 0 {
		t.Fatal("abandonment was not atomic or durable")
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.Upsert(record); return nil }); err == nil {
		t.Fatal("abandoned initial identity became a committed owner")
	}
}

func TestQUICAbandonmentReceiptIsImmutableExceptOneWayRetirement(t *testing.T) {
	ctx := context.Background()
	op, record := managedQUICStateFixture(t)
	store := NewFileStore(t.TempDir())
	r := QUICAbandonmentReceipt{Operation: op, Files: record.QUICGeneration.Files, ReconciledKernelBootID: "11234567-89ab-4cde-8fab-0123456789ab", ReconciledKernelBootSource: hostidentity.VerifiedHostBootSourceV1}
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICCrashOperations = append(s.QUICCrashOperations, op); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.QUICCrashOperations = nil
		s.QUICAbandonmentReceipts = append(s.QUICAbandonmentReceipts, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Snapshot){
		func(s *Snapshot) { s.QUICAbandonmentReceipts = nil },
		func(s *Snapshot) { s.QUICAbandonmentReceipts[0].Files.ReceiptInode++ },
		func(s *Snapshot) { s.QUICAbandonmentReceipts[0].Operation.Resources[0].Key += "changed" },
		func(s *Snapshot) {
			s.QUICAbandonmentReceipts[0].Operation.Managed.KernelBootID = "21234567-89ab-4cde-8fab-0123456789ab"
		},
	} {
		if err := store.Update(ctx, func(s *Snapshot) error { change(s); return nil }); err == nil {
			t.Fatal("abandonment authority was deleted or retargeted")
		}
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICAbandonmentReceipts[0].Retired = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICAbandonmentReceipts[0].Retired = false; return nil }); err == nil {
		t.Fatal("retired receipt reopened destructive cleanup")
	}
}

func TestQUICManagedJournalRequiresTrustedAttemptProvenance(t *testing.T) {
	op, _ := managedQUICStateFixture(t)
	for _, change := range []func(*QUICManagedOperation){
		func(m *QUICManagedOperation) { m.KernelBootID = "" },
		func(m *QUICManagedOperation) { m.KernelBootSource = "" },
		func(m *QUICManagedOperation) { m.KernelBootSource = "namespace-local-observation" },
	} {
		candidate := op
		managed := *op.Managed
		candidate.Managed = &managed
		change(candidate.Managed)
		if err := candidate.Validate(); err == nil {
			t.Fatal("untrusted attempt gained managed effects/recovery authority")
		}
	}
}
