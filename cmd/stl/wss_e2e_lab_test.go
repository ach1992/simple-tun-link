//go:build stl_e2e_lab

package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// The test-only child runs the REAL CLI and production backend composition
// with the single narrowly injected StateRoot. It cannot be present in the
// official release executable (no stl_e2e_lab tag).
func TestWSSLabCLI(t *testing.T) {
	raw := os.Getenv("STL_E2E_ARGS")
	if raw == "" {
		t.Skip("test-only entrypoint")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatal(err)
	}
	// Only WSS is exercised by this disposable two-peer fixture.
	// Initializing unrelated MASQUE would demand a production-installed
	// canonical STL binary, which this build-tag-only test binary is not.
	// The selected WSS Backend and its Engine remain production-wired.
	opts, err := assembleRuntimeOptionsForBackend("/var/lib/stl-r1-state", domain.BackendWireGuardWSS)
	if err != nil {
		t.Fatalf("assemble production runtime: %v", err)
	}
	if code := runWithRuntimeInput(args, os.Stdin, os.Stdout, os.Stderr, opts); code != 0 {
		t.Fatalf("real CLI returned exit %d", code)
	}
}
