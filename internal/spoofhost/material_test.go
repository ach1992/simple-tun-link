package spoofhost

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func randomKey(t *testing.T) [32]byte {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStageProtectedSpoofIdentityAndRejectReplace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMaterial(id, "creator", randomKey(t), randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := StageMaterial(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatal("protected file hash not returned")
	}
	again, err := StageMaterial(root, m)
	if err != nil || digest != again {
		t.Fatalf("exact original material not idempotent: %v", err)
	}
	got, sha, err := ReadMaterial(root, id, digest)
	if err != nil || sha != digest || got != m {
		t.Fatalf("protected material changed: %v", err)
	}
	wrong, err := NewMaterial(id, "creator", randomKey(t), randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StageMaterial(root, wrong); err == nil {
		t.Fatal("original key replaced without revoke")
	}
	secretJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(secretJSON), "bootstrap") || strings.Contains(m.String(), "private") {
		t.Fatal("generic material representation leaked secrets")
	}
	path, err := MaterialFile(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMaterial(root, id, digest); err == nil {
		t.Fatal("unsafe material permissions accepted")
	}
}

func TestProtectedSpoofMaterialRequiresPrivateDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	id, _ := domain.NewLinkID()
	m, _ := NewMaterial(id, "recipient", randomKey(t), randomKey(t))
	if _, err := StageMaterial(root, m); err == nil {
		t.Fatal("unsafe root accepted")
	}
}
