package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSharedPrerequisiteRetainsOwnedHostStateUntilLastOwner(t *testing.T) {
	manager := NewSharedPrerequisites(t.TempDir())
	first := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	second := domain.LinkID("lnk_fedcba9876543210fedcba9876543210")
	applies := 0
	rollbacks := 0
	removes := 0
	apply := func(context.Context) (SharedApplyResult, error) {
		applies++
		return SharedApplyResult{Owned: true, Rollback: func(context.Context) error { rollbacks++; return nil }}, nil
	}
	remove := func(context.Context) error { removes++; return nil }

	undoFirst, changed, err := manager.Ensure(context.Background(), first, "fou:port:5555", apply, remove)
	if err != nil || !changed {
		t.Fatalf("first Ensure changed=%v err=%v", changed, err)
	}
	_, changed, err = manager.Ensure(context.Background(), second, "fou:port:5555", apply, remove)
	if err != nil || !changed {
		t.Fatalf("second Ensure changed=%v err=%v", changed, err)
	}
	if applies != 1 {
		t.Fatalf("applies=%d, want 1", applies)
	}

	if err := undoFirst(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rollbacks != 0 || removes != 0 {
		t.Fatal("undo removed a prerequisite still owned by another Link")
	}

	removed, err := manager.Release(context.Background(), second, "fou:port:5555", remove)
	if err != nil || !removed {
		t.Fatalf("last Release removed=%v err=%v", removed, err)
	}
	if removes != 1 {
		t.Fatalf("removes=%d, want 1", removes)
	}
}

func TestSharedPrerequisiteNeverRemovesExternalPrerequisite(t *testing.T) {
	manager := NewSharedPrerequisites(t.TempDir())
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	removeCalls := 0
	_, _, err := manager.Ensure(context.Background(), id, "module:external", func(context.Context) (SharedApplyResult, error) {
		return SharedApplyResult{Owned: false}, nil
	}, func(context.Context) error { removeCalls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Release(context.Background(), id, "module:external", func(context.Context) error { removeCalls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if removeCalls != 0 {
		t.Fatalf("external prerequisite remove calls=%d, want 0", removeCalls)
	}
}

func TestSharedPrerequisiteRemoveFailureRestoresOwnership(t *testing.T) {
	manager := NewSharedPrerequisites(t.TempDir())
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	_, _, err := manager.Ensure(context.Background(), id, "module:example", func(context.Context) (SharedApplyResult, error) {
		return SharedApplyResult{Owned: true, Rollback: func(context.Context) error { return nil }}, nil
	}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("remove failed")
	if _, err := manager.Release(context.Background(), id, "module:example", func(context.Context) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("Release error=%v, want %v", err, wantErr)
	}
	owners, err := manager.Owners(context.Background(), "module:example")
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != id {
		t.Fatalf("owners=%v, want retained owner %s", owners, id)
	}
}

func TestSharedPrerequisiteEnsureIsIdempotentPerOwner(t *testing.T) {
	manager := NewSharedPrerequisites(t.TempDir())
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	applies := 0
	apply := func(context.Context) (SharedApplyResult, error) {
		applies++
		return SharedApplyResult{Owned: false}, nil
	}
	if _, changed, err := manager.Ensure(context.Background(), id, "module:example", apply, nil); err != nil || !changed {
		t.Fatalf("first Ensure changed=%v err=%v", changed, err)
	}
	if _, changed, err := manager.Ensure(context.Background(), id, "module:example", apply, nil); err != nil || changed {
		t.Fatalf("second Ensure changed=%v err=%v", changed, err)
	}
	if applies != 1 {
		t.Fatalf("applies=%d, want 1", applies)
	}
}

func TestSharedPrerequisiteFailsClosedOnOrphanedMetadata(t *testing.T) {
	root := t.TempDir()
	manager := NewSharedPrerequisites(root)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	key := "module:orphaned"
	dir := filepath.Join(root, "shared", sharedKeyHash(key))
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedMetadata(dir, sharedMetadata{SchemaVersion: sharedMetadataVersion, Owned: true}); err != nil {
		t.Fatal(err)
	}
	applied := false
	_, _, err := manager.Ensure(context.Background(), id, key, func(context.Context) (SharedApplyResult, error) {
		applied = true
		return SharedApplyResult{Owned: true, Rollback: func(context.Context) error { return nil }}, nil
	}, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("expected orphaned metadata to fail closed")
	}
	if applied {
		t.Fatal("orphaned metadata caused host prerequisite to be re-applied")
	}
}

func TestSharedPrerequisiteExistingOwnerRequiresValidMetadata(t *testing.T) {
	root := t.TempDir()
	manager := NewSharedPrerequisites(root)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	key := "module:corrupt"
	dir := filepath.Join(root, "shared", sharedKeyHash(key))
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := createOwnerMarker(filepath.Join(dir, "owner-"+string(id))); err != nil {
		t.Fatal(err)
	}
	_, _, err := manager.Ensure(context.Background(), id, key, func(context.Context) (SharedApplyResult, error) {
		return SharedApplyResult{Owned: false}, nil
	}, nil)
	if err == nil {
		t.Fatal("expected missing metadata for existing owner to fail closed")
	}
}

func TestSharedPrerequisiteRejectsUnknownMetadataFields(t *testing.T) {
	root := t.TempDir()
	manager := NewSharedPrerequisites(root)
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	key := "module:unknown-field"
	dir := filepath.Join(root, "shared", sharedKeyHash(key))
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(`{"schema_version":1,"owned":true,"unexpected":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Ensure(context.Background(), id, key, func(context.Context) (SharedApplyResult, error) {
		return SharedApplyResult{Owned: true, Rollback: func(context.Context) error { return nil }}, nil
	}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("expected unknown metadata field to fail closed")
	}
}

func TestSharedPrerequisiteConcurrentEnsureAppliesOnce(t *testing.T) {
	manager := NewSharedPrerequisites(t.TempDir())
	ids := []domain.LinkID{
		"lnk_0123456789abcdef0123456789abcdef",
		"lnk_fedcba9876543210fedcba9876543210",
	}
	var applies atomic.Int32
	start := make(chan struct{})
	errCh := make(chan error, len(ids))
	for _, id := range ids {
		id := id
		go func() {
			<-start
			_, _, err := manager.Ensure(context.Background(), id, "module:concurrent", func(context.Context) (SharedApplyResult, error) {
				applies.Add(1)
				time.Sleep(20 * time.Millisecond)
				return SharedApplyResult{Owned: false}, nil
			}, nil)
			errCh <- err
		}()
	}
	close(start)
	for range ids {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if got := applies.Load(); got != 1 {
		t.Fatalf("shared prerequisite applied %d times, want 1", got)
	}
	owners, err := manager.Owners(context.Background(), "module:concurrent")
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 {
		t.Fatalf("owners=%v, want 2 owners", owners)
	}
}
