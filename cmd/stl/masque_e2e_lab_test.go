//go:build stl_e2e_lab

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/masquehost"
)

// This test-only stage entrypoint issues the SAME production per-Link
// material and writes via the production protected StageFiles implementation.
// A separate rootless namespace harness runs the actual production STL
// helper on two kernel TUNs, without affecting any host systemd service.
func TestMASQUEKernelLabStage(t *testing.T) {
	root := os.Getenv("STL_MASQUE_LAB_ROOT")
	if root == "" {
		t.Skip("requires explicit disposable rootless namespace lab")
	}
	// Test-only staging has powerful root-owned filesystem effects. A caller
	// cannot bypass the namespace launcher by executing this tagged binary
	// directly as real root or supplying a random State root.
	if os.Geteuid() != 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("MASQUE lab stage requires isolated mapped root and a canonical root")
	}
	guard := os.Getenv("STL_MASQUE_LAB_GUARD")
	written, err := os.ReadFile(filepath.Join(root, "guard"))
	if err != nil || len(guard) != 32 || string(written) != guard {
		t.Fatal("MASQUE lab stage lacks verified launcher guard")
	}
	oldUser, err := os.ReadFile(filepath.Join(root, "host-user-ns"))
	if err != nil {
		t.Fatal(err)
	}
	oldNet, err := os.ReadFile(filepath.Join(root, "host-net-ns"))
	if err != nil {
		t.Fatal(err)
	}
	userNS, userErr := os.Readlink("/proc/self/ns/user")
	netNS, netErr := os.Readlink("/proc/self/ns/net")
	uidMap, mapErr := os.ReadFile("/proc/self/uid_map")
	mapping := strings.Fields(string(uidMap))
	if userErr != nil || netErr != nil || mapErr != nil ||
		userNS == strings.TrimSpace(string(oldUser)) ||
		netNS == strings.TrimSpace(string(oldNet)) || len(mapping) != 3 ||
		mapping[0] != "0" || mapping[2] != "1" {
		t.Fatal("MASQUE lab stage is not in a fresh root-mapped user and network namespace")
	}
	stat, err := os.Lstat(root)
	if err != nil || !stat.IsDir() || stat.Mode().Perm()&0o077 != 0 {
		t.Fatal("MASQUE lab scratch root has unsafe type or permissions")
	}
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	listener := domain.Link{
		ID: id, Backend: domain.BackendMASQUE, Encapsulation: domain.EncapTLS,
		Underlay: domain.Underlay{Local: netip.MustParseAddr("198.51.100.21"),
			Peer: netip.MustParseAddr("198.51.100.22")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.252.97.1/32"),
			Peer: netip.MustParsePrefix("10.252.97.2/32")},
		MASQUE: domain.MASQUEOptions{Role: "listen", TCPPort: 59443,
			TLSServerName: "198.51.100.21", PublicTLS: true},
	}
	dialer := listener
	dialer.MASQUE.Role = "dial"
	dialer.Underlay.Local, dialer.Underlay.Peer = listener.Underlay.Peer, listener.Underlay.Local
	dialer.Addresses.Local, dialer.Addresses.Peer = listener.Addresses.Peer, listener.Addresses.Local
	pair, err := masque.GeneratePair(id, listener.MASQUE.TLSServerName, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	for _, tc := range []struct {
		side string
		link domain.Link
	}{{"alpha", listener}, {"beta", dialer}} {
		stateRoot := filepath.Join(root, tc.side+"-state")
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		owned, files, err := masquehost.BuildMaterial(stateRoot, tc.link, pair)
		if err != nil {
			t.Fatal(err)
		}
		if err := masquehost.StageFiles(stateRoot, owned, files); err != nil {
			masquehost.ClearFiles(files)
			t.Fatal(err)
		}
		masquehost.ClearFiles(files)
	}
}
