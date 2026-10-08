package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type restoreObservation struct{ present bool }

func (o restoreObservation) ObservedResources() []domain.ResourceClaim { return nil }

type restorePlan struct{ absent bool }

func (p restorePlan) Empty() bool                       { return !p.absent }
func (p restorePlan) Resources() []domain.ResourceClaim { return nil }

type restoreBackend struct {
	applied int
	fail    bool
}

func (*restoreBackend) Kind() domain.Backend { return domain.BackendGRE }
func (*restoreBackend) Inspect(context.Context, domain.Link) (backend.Observation, error) {
	return restoreObservation{present: false}, nil
}
func (*restoreBackend) Plan(context.Context, backend.Request, backend.Observation) (backend.Plan, error) {
	return restorePlan{absent: true}, nil
}
func (*restoreBackend) Validate(context.Context, backend.Request, backend.Observation, backend.Plan) error {
	return nil
}
func (b *restoreBackend) Apply(context.Context, backend.Request, backend.Observation, backend.Plan) (backend.Rollback, error) {
	if b.fail {
		return nil, errors.New("private_key=DO-NOT-LEAK")
	}
	b.applied++
	return func(context.Context) error { b.applied--; return nil }, nil
}
func (*restoreBackend) Verify(context.Context, backend.Request) (backend.Observation, error) {
	return restoreObservation{present: true}, nil
}

func restoreTestLink(t *testing.T, id string, kind domain.Backend, local, peer string) domain.Link {
	t.Helper()
	return domain.Link{
		ID:          domain.LinkID("lnk_" + strings.Repeat(id, 32)),
		DisplayName: "stl-test",
		Underlay:    domain.Underlay{Local: netip.MustParseAddr("192.0.2.2"), Peer: netip.MustParseAddr("198.51.100.3")},
		Addresses:   domain.LinkAddresses{Local: netip.MustParsePrefix(local), Peer: netip.MustParsePrefix(peer)},
		Backend:     kind, Encapsulation: domain.EncapNative,
	}
}

func seedRestoreState(t *testing.T, root string, links ...domain.Link) {
	t.Helper()
	err := state.NewFileStore(root).Update(context.Background(), func(snapshot *state.Snapshot) error {
		for _, link := range links {
			snapshot.Upsert(state.LinkRecord{Desired: link})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type fakeSystemctl struct {
	commands   []string
	enabled    bool
	failEnable bool
}

func (r *fakeSystemctl) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name != "systemctl" {
		return linux.CommandResult{}, errors.New("unrecognized binary")
	}
	cmd := strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	switch {
	case strings.HasPrefix(cmd, "is-enabled "):
		if r.enabled {
			return linux.CommandResult{Stdout: []byte("enabled\n")}, nil
		}
		return linux.CommandResult{Stdout: []byte("disabled\n")}, errors.New("disabled")
	case strings.HasPrefix(cmd, "enable "):
		if r.failEnable {
			return linux.CommandResult{}, errors.New("failed")
		}
		r.enabled = true
	case strings.HasPrefix(cmd, "disable "):
		r.enabled = false
	}
	return linux.CommandResult{}, nil
}

func TestRestoreCommandUsesPersistedStateAndOwnedSystemdUnit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	unitDir := filepath.Join(t.TempDir(), "units")
	link := restoreTestLink(t, "a", domain.BackendGRE, "10.80.100.0/31", "10.80.100.1/31")
	seedRestoreState(t, root, link)
	b, systemctl := &restoreBackend{}, &fakeSystemctl{}
	options := &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{b},
		restorePersistence: linux.SystemdPersistence{Runner: systemctl, UnitDir: unitDir},
		executable:         "/usr/local/bin/stl",
	}
	var out, errs bytes.Buffer
	if code := runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, options); code != 0 {
		t.Fatalf("restore code=%d stderr=%q", code, errs.String())
	}
	if b.applied != 1 || !strings.Contains(out.String(), "restored 1 link(s)") {
		t.Fatalf("restore did not reach canonical Engine.Ensure: applied=%d stdout=%q", b.applied, out.String())
	}
	payload, err := os.ReadFile(filepath.Join(unitDir, "simple-tun-link-restore.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !systemctl.enabled || !strings.Contains(string(payload), "ExecStart=/usr/local/bin/stl link restore --all") {
		t.Fatalf("owned restart activation missing: enabled=%t unit=%q", systemctl.enabled, payload)
	}
	for _, command := range systemctl.commands {
		if strings.Contains(command, "start") || strings.Contains(command, "restart") || strings.Contains(command, "--now") {
			t.Fatalf("restore activation disturbed live service: %q", command)
		}
	}
}

func TestRestoreCommandCannotSilentlySucceedOnMissingBackend(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	seedRestoreState(t, root, restoreTestLink(t, "b", domain.BackendGRE, "10.80.101.0/31", "10.80.101.1/31"))
	var out, errs bytes.Buffer
	code := runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, &runtimeOptions{stateRoot: root})
	if code != 1 || !strings.Contains(errs.String(), "unsupported") || out.Len() != 0 {
		t.Fatalf("missing backend falsely succeeded: code=%d out=%q err=%q", code, out.String(), errs.String())
	}
}

func TestRestoreCommandReportsSafeFailureAndPartialProgress(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	seedRestoreState(t, root,
		restoreTestLink(t, "1", domain.BackendGRE, "10.80.102.0/31", "10.80.102.1/31"),
		restoreTestLink(t, "2", domain.BackendIPIP, "10.80.103.0/31", "10.80.103.1/31"))
	b := &restoreBackend{}
	var out, errs bytes.Buffer
	code := runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, &runtimeOptions{stateRoot: root, backends: []backend.Backend{b}})
	if code != 1 || b.applied != 1 || !strings.Contains(errs.String(), "after 1 link(s)") {
		t.Fatalf("partial restore not reported: code=%d applied=%d err=%q", code, b.applied, errs.String())
	}
	if out.Len() != 0 {
		t.Fatalf("false success output: %q", out.String())
	}
	b.fail = true
	root = filepath.Join(t.TempDir(), "state")
	seedRestoreState(t, root, restoreTestLink(t, "3", domain.BackendGRE, "10.80.104.0/31", "10.80.104.1/31"))
	errs.Reset()
	code = runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, &runtimeOptions{stateRoot: root, backends: []backend.Backend{b}})
	if code != 1 || strings.Contains(errs.String(), "DO-NOT-LEAK") {
		t.Fatalf("unsafe backend failure surfaced: code=%d err=%q", code, errs.String())
	}
}

func TestRestoreCommandEmptyAndMalformedInvocation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new-state")
	var out, errs bytes.Buffer
	if code := runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, &runtimeOptions{stateRoot: root}); code != 0 {
		t.Fatalf("empty-state restore failed: code=%d err=%q", code, errs.String())
	}
	if !strings.Contains(out.String(), "restored 0 link(s)") {
		t.Fatalf("empty-state success missing: %q", out.String())
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty restore unexpectedly created state directory: %v", err)
	}
	for _, args := range [][]string{{"link"}, {"link", "restore"}, {"link", "restore", "--all", "--json"}, {"link", "remove", "--all"}} {
		out.Reset()
		errs.Reset()
		if code := runWithRuntime(args, &out, &errs, &runtimeOptions{stateRoot: root}); code != 2 {
			t.Fatalf("bad invocation %v unexpectedly accepted with code %d", args, code)
		}
	}
}

func TestRestoreCommandPropagatesSystemdEnableFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	unitDir := filepath.Join(t.TempDir(), "units")
	seedRestoreState(t, root, restoreTestLink(t, "f", domain.BackendGRE, "10.80.105.0/31", "10.80.105.1/31"))
	b, runner := &restoreBackend{}, &fakeSystemctl{failEnable: true}
	var out, errs bytes.Buffer
	code := runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{b},
		restorePersistence: linux.SystemdPersistence{Runner: runner, UnitDir: unitDir},
		executable:         "/usr/local/bin/stl",
	})
	if code != 1 || b.applied != 0 || !strings.Contains(errs.String(), "state_failed") {
		t.Fatalf("persistence failure not propagated and rolled back: code=%d applied=%d err=%q", code, b.applied, errs.String())
	}
	if _, err := os.Stat(filepath.Join(unitDir, "simple-tun-link-restore.service")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit was left behind after failed enable: %v", err)
	}
}

func TestRestoreCommandReconcilesCommittedEmptyStateAndOwnedUnit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	unitDir := filepath.Join(t.TempDir(), "units")
	seedRestoreState(t, root)
	runner := &fakeSystemctl{}
	manager := linux.SystemdPersistence{Runner: runner, UnitDir: unitDir}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := runWithRuntime([]string{"link", "restore", "--all"}, &out, &errs, &runtimeOptions{
		stateRoot: root, restorePersistence: manager, executable: "/usr/local/bin/stl",
	})
	if code != 0 || runner.enabled {
		t.Fatalf("empty-state cleanup failed: code=%d enabled=%t stderr=%q", code, runner.enabled, errs.String())
	}
	if _, err := os.Stat(filepath.Join(unitDir, "simple-tun-link-restore.service")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned restore unit was left installed: %v", err)
	}
}
