//go:build linux

package spoofhost

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	spoofcarrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// This test only runs in disposable, explicitly authorized native VM guests.
// It uses real root-owned State, disk fsync, systemctl and /sys TUN checks,
// but never touches an existing live Link, host-wide sysctls or firewall.
func TestPrivilegedSpoofRetirementCrashQuarantineRecovery(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("STL_SPOOF_PRIVILEGED_ACCEPTANCE") != "1" {
		t.Skip("requires explicitly opted-in root test on task-owned guest")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	h, err := New(root, "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	makeOriginal := func() (domain.Link, string, state.Store) {
		t.Helper()
		id, err := domain.NewLinkID()
		if err != nil {
			t.Fatal(err)
		}
		priv, pub, err := spoofcarrier.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		material, err := NewMaterial(id, "creator", priv, secret)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := material.Digest()
		if err != nil {
			t.Fatal(err)
		}
		link := domain.Link{
			ID: id, Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
			Underlay:  domain.Underlay{Local: netip.MustParseAddr("10.246.62.165"), Peer: netip.MustParseAddr("10.246.62.245")},
			Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.245.188.1/32"), Peer: netip.MustParsePrefix("10.245.188.2/32")},
			Spoof: domain.SpoofOptions{
				Role: "creator", SourceFile: "/root/stl/spoof/sources.txt",
				OuterProtocol: "udp", ListenPort: 48101, PeerPort: 48102,
				BindIPv4:       netip.MustParseAddr("10.246.62.165"),
				LocalPublicKey: base64.RawURLEncoding.EncodeToString(pub[:]),
				MaterialSHA256: digest,
			},
		}
		if err := link.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := StageMaterial(root, material); err != nil {
			t.Fatal(err)
		}
		if err := StageConfig(root, link); err != nil {
			t.Fatal(err)
		}
		store := state.NewFileStore(root)
		if err := store.Update(context.Background(), func(s *state.Snapshot) error {
			s.SpoofRemovalReceipts = append(s.SpoofRemovalReceipts, state.SpoofRemovalReceipt{Link: link})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		path, err := MaterialFile(root, id)
		if err != nil {
			t.Fatal(err)
		}
		return link, filepath.Dir(path), store
	}
	t.Run("interrupted_rename_and_partial_unlink", func(t *testing.T) {
		link, original, store := makeOriginal()
		if err := stampSpoofRetirement(original, link); err != nil {
			t.Fatal(err)
		}
		quarantine := filepath.Join(filepath.Dir(original), ".retired-"+string(link.ID)+"-"+link.Spoof.MaterialSHA256)
		if err := os.Rename(original, quarantine); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(quarantine, "material.json")); err != nil {
			t.Fatal(err)
		}
		if err := h.RetireAfterRemove(context.Background(), link); err != nil {
			t.Fatal(err)
		}
		if err := h.RetireAfterRemove(context.Background(), link); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(quarantine); !os.IsNotExist(err) {
			t.Fatalf("quarantine still present: %v", err)
		}
		s, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := s.FindSpoofRemovalReceipt(link.ID); !ok || !r.Retired {
			t.Fatal("exact receipt not retired")
		}
	})
	t.Run("foreign_original_is_preserved", func(t *testing.T) {
		link, original, store := makeOriginal()
		foreign := filepath.Join(original, "foreign.critical")
		if err := os.WriteFile(foreign, []byte("untouchable"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := h.RetireAfterRemove(context.Background(), link); err == nil || !strings.Contains(err.Error(), "foreign") {
			t.Fatalf("foreign original resource not rejected: %v", err)
		}
		if got, err := os.ReadFile(foreign); err != nil || string(got) != "untouchable" {
			t.Fatal("foreign resource modified")
		}
		s, err := store.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := s.FindSpoofRemovalReceipt(link.ID); !ok || r.Retired {
			t.Fatal("foreign case falsely marked retired")
		}
		if err := os.Remove(foreign); err != nil {
			t.Fatal(err)
		}
		if err := h.RetireAfterRemove(context.Background(), link); err != nil {
			t.Fatalf("supported retry after restoring original: %v", err)
		}
	})
}
