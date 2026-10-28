package quic

import (
	"os"
	"path/filepath"
	"testing"
)

// A synthetic executable must never pass the official per-architecture pin.
// This test does not execute, download, install or launch the helper.
func TestOfficialHysteriaPinCannotBeSelectedByCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hysteria")
	if err := os.WriteFile(path, []byte("fake helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPinnedHysteria(path); err == nil {
		t.Fatal("untrusted helper accepted under official pinned identity")
	}
}

// This is opt-in and read-only. A hash-checked upstream helper path may be
// supplied explicitly in the disposable lab; default Go CI does not require
// Hysteria to be present or install it.
func TestPinnedOfficialHysteriaBinaryWhenAvailable(t *testing.T) {
	path := os.Getenv("STL_QUIC_HYSTERIA_BIN")
	if path == "" {
		t.Skip("optional exact official Hysteria binary not supplied")
	}
	id, err := InspectPinnedHysteria(path)
	if err != nil || id.Inode == 0 {
		t.Fatalf("official helper provenance not accepted: %v", err)
	}
}
