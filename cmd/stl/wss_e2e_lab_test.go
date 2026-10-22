//go:build stl_e2e_lab

package main

import (
	"encoding/json"
	"os"
	"testing"
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
	opts, err := assembleRuntimeOptions("/var/lib/stl-r1-state")
	if err != nil {
		t.Fatalf("assemble production runtime: %v", err)
	}
	if code := runWithRuntimeInput(args, os.Stdin, os.Stdout, os.Stderr, opts); code != 0 {
		t.Fatalf("real CLI returned exit %d", code)
	}
}
