package linux

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// These integration tests wire the real Engine and real unit-file manager
// together, replacing only backend traffic and systemctl with isolated fakes.
type unitEngineBackend struct {
	live       bool
	owned      string
	applyCount int
	undos      int
}

type unitEngineObservation struct{ live bool }

func (o unitEngineObservation) ObservedResources() []domain.ResourceClaim { return nil }

type unitEnginePlan struct {
	remove bool
	name   string
}

func (p unitEnginePlan) Empty() bool { return false }
func (p unitEnginePlan) Resources() []domain.ResourceClaim {
	if p.remove {
		return nil
	}
	return []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: p.name}}
}
func (b *unitEngineBackend) Kind() domain.Backend { return domain.BackendGRE }
func (b *unitEngineBackend) Inspect(context.Context, domain.Link) (backend.Observation, error) {
	return unitEngineObservation{live: b.live}, nil
}
func (b *unitEngineBackend) Plan(_ context.Context, request backend.Request, _ backend.Observation) (backend.Plan, error) {
	return unitEnginePlan{remove: request.Operation == backend.OperationRemove, name: request.Link.DisplayName}, nil
}
func (b *unitEngineBackend) Validate(context.Context, backend.Request, backend.Observation, backend.Plan) error {
	return nil
}
func (b *unitEngineBackend) Apply(_ context.Context, request backend.Request, _ backend.Observation, _ backend.Plan) (backend.Rollback, error) {
	priorLive, priorOwner := b.live, b.owned
	b.live = request.Operation != backend.OperationRemove
	b.owned = request.Link.DisplayName
	b.applyCount++
	return func(context.Context) error {
		b.live = priorLive
		b.owned = priorOwner
		b.undos++
		return nil
	}, nil
}
func (b *unitEngineBackend) Verify(_ context.Context, request backend.Request) (backend.Observation, error) {
	if b.live != (request.Operation != backend.OperationRemove) {
		return nil, errors.New("backend not in expected state")
	}
	return unitEngineObservation{live: b.live}, nil
}

func testUnitEngineLink(t *testing.T) domain.Link {
	t.Helper()
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	return domain.Link{
		ID: id, DisplayName: "engine-old",
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.30"),
			Peer:  netip.MustParseAddr("198.51.100.40"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.80.251.0/31"),
			Peer:  netip.MustParsePrefix("10.80.251.1/31"),
		},
		Backend: domain.BackendGRE, Encapsulation: domain.EncapNative,
	}
}
func unitEngineFor(t *testing.T, b *unitEngineBackend, store *state.FileStore, root string, manager *SystemdPersistence, executable string) *app.Engine {
	t.Helper()
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	locks := state.NewLockManager(root)
	if manager == nil {
		engine, err := app.New(registry, store, locks)
		if err != nil {
			t.Fatal(err)
		}
		return engine
	}
	engine, err := app.NewWithRestorePersistence(registry, store, locks, manager, executable)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestEngineUnitPostPublicationFailureKeepsCommittedIntentConsistent(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement bool
	}{
		{"first install", false}, {"replace owned enabled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			unitDir := t.TempDir()
			store := state.NewFileStore(root)
			b := &unitEngineBackend{}
			runner := &recordingRunner{}
			normal := &SystemdPersistence{
				Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil },
			}
			link := testUnitEngineLink(t)
			if tc.replacement {
				initial := unitEngineFor(t, b, store, root, normal, "/usr/local/bin/stl")
				if _, err := initial.Ensure(context.Background(), link); err != nil {
					t.Fatal(err)
				}
			}
			risky := &SystemdPersistence{
				Runner: runner, UnitDir: unitDir,
				VerifyExecutable: func(string) error { return nil },
				afterUnitPublish: func() error { return errUnitAfterRename },
			}
			executable := "/usr/local/bin/stl"
			expectedOwner := ""
			if tc.replacement {
				executable = "/opt/stl/stl" // Forces the same owned unit to change.
				expectedOwner = link.DisplayName
				link.DisplayName = "engine-new"
			}
			engine := unitEngineFor(t, b, store, root, risky, executable)
			_, err := engine.Ensure(context.Background(), link)
			if stlerr.CodeOf(err) != stlerr.CodeState || !errors.Is(err, errUnitAfterRename) {
				t.Fatalf("post-publication failure not reported: %v", err)
			}
			committed, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			record, exists := committed.Find(link.ID)
			if exists != tc.replacement {
				t.Fatalf("published unit incorrectly committed intent: %+v", record)
			}
			if exists && record.Desired.DisplayName != expectedOwner {
				t.Fatalf("prior desired intent overwritten: %+v", record)
			}
			if b.live != tc.replacement || b.owned != expectedOwner || b.undos != 1 {
				t.Fatalf("backend rollback inconsistent with committed intent: live=%t owner=%q undos=%d", b.live, b.owned, b.undos)
			}
			unitPath := filepath.Join(unitDir, restoreSystemdUnitName)
			contents, readErr := os.ReadFile(unitPath)
			if tc.replacement {
				if readErr != nil || !strings.Contains(string(contents), "ExecStart=/usr/local/bin/stl link restore --all") {
					t.Fatalf("previous durable boot command not retained: %q %v", contents, readErr)
				}
				if !runner.enabled[restoreSystemdUnitName] {
					t.Fatal("prior enabled unit lost enablement")
				}
			} else {
				if !errors.Is(readErr, os.ErrNotExist) || runner.enabled[restoreSystemdUnitName] {
					t.Fatalf("failed first install left orphaned unit: %v enabled=%t", readErr, runner.enabled[restoreSystemdUnitName])
				}
			}
		})
	}
}

func TestEngineLastLinkRemovalReportsOrphanEnabledUnit(t *testing.T) {
	root := t.TempDir()
	unitDir := t.TempDir()
	store := state.NewFileStore(root)
	b := &unitEngineBackend{}
	link := testUnitEngineLink(t)
	normal := unitEngineFor(t, b, store, root, nil, "")
	if _, err := normal.Ensure(context.Background(), link); err != nil {
		t.Fatal(err)
	}

	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := &SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
	engine := unitEngineFor(t, b, store, root, manager, "/usr/local/bin/stl")
	result, err := engine.Remove(context.Background(), link.ID)
	if stlerr.CodeOf(err) != stlerr.CodeState || !result.Removed || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("orphan enabled unit failure hidden: %+v %v", result, err)
	}
	committed, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(committed.Links) != 0 || b.live || runner.enabled[restoreSystemdUnitName] == false {
		t.Fatalf("last-link state or enablement mismatched: saved=%d backend=%t enabled=%t",
			len(committed.Links), b.live, runner.enabled[restoreSystemdUnitName])
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}
