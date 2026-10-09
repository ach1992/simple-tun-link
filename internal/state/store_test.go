package state

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func testLink(t *testing.T, id domain.LinkID, local, peer string) domain.Link {
	t.Helper()
	return domain.Link{
		ID: id,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix(local),
			Peer:  netip.MustParsePrefix(peer),
		},
		Backend:       domain.BackendGRE,
		Encapsulation: domain.EncapNative,
	}
}

func TestFileStorePersistsCollectionAtomicallyWithPrivateMode(t *testing.T) {
	root := t.TempDir()
	store := NewFileStore(root)
	id1, _ := domain.NewLinkID()
	id2, _ := domain.NewLinkID()
	first := testLink(t, id1, "10.80.20.0/31", "10.80.20.1/31")
	second := testLink(t, id2, "10.80.21.0/31", "10.80.21.1/31")

	for _, link := range []domain.Link{first, second} {
		link := link
		if err := store.Update(context.Background(), func(s *Snapshot) error {
			s.Upsert(LinkRecord{Desired: link, OwnedResources: []domain.ResourceClaim{{Kind: "interface", Key: string(link.ID)}}})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Links) != 2 {
		t.Fatalf("len(Links) = %d, want 2", len(got.Links))
	}
	info, err := os.Stat(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state mode = %o, want 600", perm)
	}
}

func TestFileStoreRejectsUnknownNewerSchema(t *testing.T) {
	root := t.TempDir()
	payload, _ := json.Marshal(map[string]any{"schema_version": SchemaVersion + 1, "links": []any{}})
	if err := os.WriteFile(filepath.Join(root, "state.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewFileStore(root).Load(context.Background())
	if err == nil {
		t.Fatal("expected unsupported schema error")
	}
}

func TestFileStoreConcurrentUpdatesDoNotLoseLinks(t *testing.T) {
	root := t.TempDir()
	store := NewFileStore(root)
	const count = 12
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func(i int) {
			defer wg.Done()
			id, _ := domain.NewLinkID()
			link := testLink(t, id, "10.80.20.0/31", "10.80.20.1/31")
			if err := store.Update(context.Background(), func(s *Snapshot) error {
				s.Upsert(LinkRecord{Desired: link})
				return nil
			}); err != nil {
				t.Errorf("Update(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Links) != count {
		t.Fatalf("len(Links) = %d, want %d", len(got.Links), count)
	}
}

func TestResourceLocksSerializeSameClaimAndRespectContext(t *testing.T) {
	manager := NewLockManager(t.TempDir())
	claim := domain.ResourceClaim{Kind: "interface", Key: "stl-test"}
	release, err := manager.Acquire(context.Background(), []domain.ResourceClaim{claim})
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := manager.Acquire(ctx, []domain.ResourceClaim{claim}); err == nil {
		t.Fatal("expected second acquisition to block until context deadline")
	}
}

func TestFileStorePostPublicationFailureIsExplicitlyIndeterminate(t *testing.T) {
	root := t.TempDir()
	s := NewFileStore(root)
	s.afterPublish = func() error { return os.ErrPermission }
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	link := testLink(t, id, "10.80.124.0/31", "10.80.124.1/31")
	err = s.Update(context.Background(), func(snapshot *Snapshot) error {
		snapshot.Upsert(LinkRecord{Desired: link})
		return nil
	})
	var postPublish *PublicationError
	if !errors.As(err, &postPublish) {
		t.Fatalf("post-rename failure was not identified as indeterminate: %v", err)
	}
	snapshot, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snapshot.Find(id); !exists {
		t.Fatal("post-publication error was incorrectly treated as uncommitted")
	}
}

func TestFileStoreMigratesCompatibleV1AndRejectsIncompleteGREV1(t *testing.T) {
	id, _ := domain.NewLinkID()
	base := testLink(t, id, "10.80.30.0/31", "10.80.30.1/31")

	t.Run("native", func(t *testing.T) {
		root := t.TempDir()
		legacy := Snapshot{SchemaVersion: legacySchemaVersion, Links: []LinkRecord{{Desired: base}}}
		payload, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "state.json"), payload, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := NewFileStore(root).Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != SchemaVersion || len(got.Links) != 1 || got.Links[0].Desired != base {
			t.Fatalf("unexpected migrated state: %#v", got)
		}
	})

	for _, tc := range []struct {
		name string
		link domain.Link
	}{
		{"gre_options", func() domain.Link { l := base; l.GRE = domain.GREOptions{KeyEnabled: true, Key: 7}; return l }()},
		{"gre_fou_without_port", func() domain.Link { l := base; l.Encapsulation = domain.EncapFOU; return l }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			legacy := Snapshot{SchemaVersion: legacySchemaVersion, Links: []LinkRecord{{Desired: tc.link}}}
			payload, err := json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "state.json"), payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(root).Load(context.Background()); err == nil || !strings.Contains(err.Error(), "legacy") {
				t.Fatalf("incomplete legacy GRE state accepted: %v", err)
			}
		})
	}
}
