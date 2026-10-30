package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestStateQUICObfuscationMigratesPriorVersionsWithoutPublishing(t *testing.T) {
	for version := 1; version <= 5; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "state.json")
			raw := []byte(fmt.Sprintf(`{"schema_version":%d,"links":[]}`, version))
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			store := NewFileStore(root)
			loaded, err := store.Load(context.Background())
			if err != nil || loaded.SchemaVersion != 6 || len(loaded.Links) != 0 {
				t.Fatalf("prior State did not migrate in memory: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("read-only migration rewrote the prior State document")
			}
			if err := store.Update(context.Background(), func(*Snapshot) error { return nil }); err != nil {
				t.Fatal(err)
			}
			published, err := os.ReadFile(path)
			if err != nil || !bytes.Contains(published, []byte(`"schema_version": 6`)) {
				t.Fatal("authorized publication did not use State 6")
			}
		})
	}
}

func TestStateV5PreservesPlainManagedQUICGenerationsAndJournals(t *testing.T) {
	op, record := managedQUICStateFixture(t)
	for _, snapshot := range []Snapshot{
		{SchemaVersion: 5, Links: []LinkRecord{record}},
		{SchemaVersion: 5, Links: []LinkRecord{}, QUICCrashOperations: []QUICCrashOperation{op}},
		{SchemaVersion: 5, Links: []LinkRecord{}, RemovalReceipts: []RemovalReceipt{{
			LinkID: record.Desired.ID, Backend: domain.BackendWireGuardQUIC, LocalPublicKey: record.Desired.WireGuard.LocalPublicKey,
			QUICLink: record.Desired, QUICGeneration: record.QUICGeneration, QUICOriginalTermination: QUICOriginalExactIfIndexDeleted,
		}}},
	} {
		root := t.TempDir()
		raw, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(bytes.ToLower(raw), []byte("obfuscation")) {
			t.Fatal("plain State gained a newly serialized mode or material field")
		}
		if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := NewFileStore(root).Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		snapshot.SchemaVersion = 6
		if !reflect.DeepEqual(got, snapshot) {
			t.Fatal("State 5 migration changed existing Plain ownership or immutable identity")
		}
	}
}

func TestLegacyStateRejectsQUICObfuscationGraftsBeforeMigration(t *testing.T) {
	for version := 1; version <= 5; version++ {
		for _, graft := range []string{
			`"links":[{"desired":{"quic":{"obfuscation":""}}}]`,
			`"links":[{"desired":{"quic":{"ObFuScAtIoN":null}}}]`,
			`"links":[{"quic_generation":{"files":{"obfuscation_sha256":""}}}]`,
			`"pending_senders":[{"link":{"quic":{"obfuscation":"salamander"}}}]`,
			`"quic_crash_operations":[{"plan":{"obfuscation":null}}]`,
			`"quic_crash_operations":[{"obfuscation_sha256":""}]`,
			`"quic_crash_operations":[{"managed":{"intent":{"quic":{"obfuscation":""}}}}]`,
			`"removal_receipts":[{"quic_link":{"quic":{"obfuscation":""}}}]`,
			`"removal_receipts":[{"quic_generation":{"files":{"ObFuScAtIoN_ShA256":null}}}]`,
			`"quic_abandonment_receipts":[{"operation":{"plan":{"obfuscation":""}}}]`,
			`"quic_abandonment_receipts":[{"files":{"obfuscation_sha256":null}}]`,
			// The final duplicate parent overwrites the first subtree in a
			// map/struct decoder. Raw-key inspection must still reject it.
			`"links":[{"desired":{"quic":{"obf\u0075scation":""}}}],"links":[]`,
		} {
			root := t.TempDir()
			raw := []byte(fmt.Sprintf(`{"schema_version":%d,"links":[],%s}`, version, graft))
			if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(root).Load(context.Background()); err == nil || !strings.Contains(err.Error(), "legacy State cannot contain QUIC obfuscation") {
				t.Fatalf("v%d newly recognized raw field did not fail at the migration guard: %v", version, err)
			}
		}
	}
}

func salamanderStateFixture(t *testing.T) (QUICCrashOperation, LinkRecord) {
	t.Helper()
	op, record := managedQUICStateFixture(t)
	record.Desired.QUIC.Obfuscation = domain.QUICObfuscationSalamander
	record.QUICGeneration.Files.ObfuscationSHA256 = strings.Repeat("9", 64)
	op.Plan.Obfuscation = domain.QUICObfuscationSalamander
	op.ObfuscationSHA256 = record.QUICGeneration.Files.ObfuscationSHA256
	op.Managed.Intent = record.Desired
	if err := op.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := record.QUICGeneration.Validate(record.Desired); err != nil {
		t.Fatal(err)
	}
	return op, record
}

func TestStateQUICSalamanderBindsModeAndIndependentFingerprint(t *testing.T) {
	for _, edit := range []func(*QUICCrashOperation, *LinkRecord){
		func(o *QUICCrashOperation, r *LinkRecord) {
			o.ObfuscationSHA256, r.QUICGeneration.Files.ObfuscationSHA256 = "", ""
		},
		func(o *QUICCrashOperation, r *LinkRecord) {
			o.ObfuscationSHA256 = o.AuthorizationSHA256
			r.QUICGeneration.Files.ObfuscationSHA256 = r.QUICGeneration.Files.Authorization
		},
		func(o *QUICCrashOperation, r *LinkRecord) {
			o.ObfuscationSHA256, r.QUICGeneration.Files.ObfuscationSHA256 = "invalid", "invalid"
		},
		func(o *QUICCrashOperation, r *LinkRecord) {
			o.Plan.Obfuscation, r.Desired.QUIC.Obfuscation = domain.QUICObfuscationPlain, domain.QUICObfuscationPlain
		},
		func(o *QUICCrashOperation, r *LinkRecord) {
			o.Plan.Obfuscation, r.Desired.QUIC.Obfuscation = "automatic", "automatic"
		},
	} {
		op, record := salamanderStateFixture(t)
		edit(&op, &record)
		if err := op.Validate(); err == nil {
			t.Fatal("journal accepted missing or incompatible obfuscation identity")
		}
		if err := record.QUICGeneration.Validate(record.Desired); err == nil {
			t.Fatal("committed generation accepted missing or incompatible obfuscation identity")
		}
	}
	op, _ := salamanderStateFixture(t)
	op.Managed.Intent.QUIC.Obfuscation = domain.QUICObfuscationPlain
	if err := op.Validate(); err == nil {
		t.Fatal("public managed intent disagreed with the journal mode")
	}
}

func TestStateQUICSalamanderAtomicCompletionAndAbandonmentBindSecret(t *testing.T) {
	ctx := context.Background()
	op, record := salamanderStateFixture(t)
	store := NewFileStore(t.TempDir())
	if err := store.Update(ctx, func(s *Snapshot) error { s.QUICCrashOperations = []QUICCrashOperation{op}; return nil }); err != nil {
		t.Fatal(err)
	}
	wrong := record
	wrong.QUICGeneration.Files.ObfuscationSHA256 = strings.Repeat("8", 64)
	if err := store.Update(ctx, func(s *Snapshot) error { s.Upsert(wrong); s.DeleteQUICManagedOperation(record.Desired.ID); return nil }); err == nil {
		t.Fatal("different obfuscation material consumed the immutable journal")
	}
	if err := store.Update(ctx, func(s *Snapshot) error { s.Upsert(record); s.DeleteQUICManagedOperation(record.Desired.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewFileStore(store.RootDir()).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := snapshot.Find(record.Desired.ID)
	if !ok || loaded.Desired != record.Desired || loaded.QUICGeneration != record.QUICGeneration || len(snapshot.QUICCrashOperations) != 0 {
		t.Fatal("canonical State round trip lost mode or protected identity")
	}
	receipt := QUICAbandonmentReceipt{Operation: op, Files: record.QUICGeneration.Files,
		ReconciledKernelBootID: "abcdefab-cdef-4abc-8def-abcdefabcdef", ReconciledKernelBootSource: op.Managed.KernelBootSource}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	receipt.Files.ObfuscationSHA256 = strings.Repeat("8", 64)
	if err := receipt.Validate(); err == nil {
		t.Fatal("abandonment receipt accepted a different obfuscation generation")
	}
}
