//go:build linux

package spoofhost

import (
	"os"
	"path/filepath"
	"testing"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSpoofStatusReportsNoOutgoingSourcesEvenWithStaleHandshake(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "spoof", string(id)), 0700); err != nil {
		t.Fatal(err)
	}
	a := newAgent(root, domain.Link{ID: id}, Material{}, nil)
	a.handshake = &carrier.Handshake{}
	a.publishStatus()
	recorded, err := ReadRuntimeStatus(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.State != "NO_WORKING_PATH" || recorded.Authenticated || recorded.BilateralConfirmed {
		t.Fatalf("stale discovery status must not obscure absent local Source inventory: %+v", recorded)
	}
}
