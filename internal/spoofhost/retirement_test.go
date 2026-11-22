package spoofhost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSpoofRetirementQuarantineMarkerExactAndForeignPreserved(t *testing.T) {
	link := domain.Link{ID: "lnk_1234567890abcdef1234567890abcdef", Backend: domain.BackendSpoof}
	dir := filepath.Join(t.TempDir(), "original")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stampSpoofRetirement(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := stampSpoofRetirement(dir, link); err != nil {
		t.Fatalf("exact interrupted marker not idempotent: %v", err)
	}
	if err := verifySpoofRetirementMarker(dir, link); err != nil {
		t.Fatal(err)
	}
	different := link
	different.Spoof.ListenPort = 48882
	if err := verifySpoofRetirementMarker(dir, different); err == nil {
		t.Fatal("different committed Link receipt adopted original quarantine")
	}
	if err := os.Remove(filepath.Join(dir, "history.json")); err != nil {
		t.Fatal(err)
	}
	if err := verifySpoofRetirementMarker(dir, link); err != nil {
		t.Fatalf("partial protected-material unlink incorrectly disowns verified quarantine: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stampSpoofRetirement(dir, link); err == nil || !strings.Contains(err.Error(), "foreign") {
		t.Fatal("unexpected foreign file not preserved")
	}
	if _, err := os.Stat(filepath.Join(dir, "foreign")); err != nil {
		t.Fatal("foreign file lost")
	}
}
