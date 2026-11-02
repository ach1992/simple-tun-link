package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestRemovalRuntimeInitializesOnlySelectedTunnelType(t *testing.T) {
	for _, kind := range []domain.Backend{
		domain.BackendGRE, domain.BackendIPIP, domain.BackendL2TPv3,
		domain.BackendWireGuard, domain.BackendWireGuardWSS,
		domain.BackendWireGuardQUIC,
	} {
		t.Run(string(kind), func(t *testing.T) {
			runtime, err := assembleRuntimeBackendOptions(filepath.Join(t.TempDir(), "state"), kind)
			if err != nil {
				t.Fatalf("selected backend must be available independently of unrelated types: %v", err)
			}
			if len(runtime.backends) != 1 || runtime.backends[0].Kind() != kind {
				t.Fatalf("selected Remove assembled unrelated backends: %+v", runtime.backends)
			}
		})
	}
	if _, err := assembleRuntimeBackendOptions(filepath.Join(t.TempDir(), "state"), domain.Backend("foreign")); err == nil {
		t.Fatal("unknown saved type must not become an empty Engine authority")
	}
}

func TestRemovalRuntimeFindsSavedBackendWithoutInstallingPrerequisites(t *testing.T) {
	// A real state-backed selection; no host command, network, or current
	// gateway is consulted. It makes no decision about mutation authority.
	opts, _, links := manageFixture(t, 1)
	kind, err := savedBackendForRemoval(opts.stateRoot, links[0].ID)
	if err != nil || kind != links[0].Backend {
		t.Fatalf("saved Link did not select its own backend: %v %v", err, kind)
	}
	scope, err := assembleRuntimeBackendOptions(opts.stateRoot, kind)
	if err != nil || len(scope.backends) != 1 || scope.backends[0].Kind() != kind {
		t.Fatalf("saved backend resolved unrelated runtime: %v %+v", err, scope)
	}
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 {
		t.Fatal("read-only runtime selection altered State", err)
	}
}
