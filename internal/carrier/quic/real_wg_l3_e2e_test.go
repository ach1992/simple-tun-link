package quic

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// This fixture is ONLY consumed by the disposable network-namespace E2E.
// It does not create a managed Link, spawn services or own host resources.
func TestPinnedHysteriaKernelWGPairFixture(t *testing.T) {
	if os.Getenv("STL_QUIC_WG_L3_FIXTURE") != "approved" {
		t.Skip("requires isolated QUIC + native WireGuard launcher")
	}
	root, binary := os.Getenv("STL_QUIC_WG_L3_ROOT"), os.Getenv("STL_QUIC_HYSTERIA_BIN")
	if root == "" || binary == "" || !strings.HasPrefix(root, "/tmp/stl-quic-wg-l3.") ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		t.Fatal("QUIC fixture needs a private absolute root and pinned helper")
	}
	parentUser, parentNet := os.Getenv("STL_QUIC_PARENT_USERNS"), os.Getenv("STL_QUIC_PARENT_NETNS")
	currentUser, errUser := os.Readlink("/proc/self/ns/user")
	currentNet, errNet := os.Readlink("/proc/self/ns/net")
	// Protected files are staged BEFORE unshare; only native network effects
	// run in the disposable child. This retains the production pinnedexec
	// parent-path validation without weakening it for unmapped root UIDs.
	if errUser != nil || errNet != nil || parentUser == "" || parentNet == "" ||
		currentUser != parentUser || currentNet != parentNet {
		t.Fatal("QUIC fixture must be staged by the launching user")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("QUIC fixture root must be an existing private 0700 directory")
	}
	statRoot, ok := info.Sys().(*syscall.Stat_t)
	if !ok || statRoot.Uid != uint32(os.Geteuid()) {
		t.Fatal("QUIC fixture root is not controlled by the launching user")
	}
	if _, err := InspectPinnedHysteria(binary); err != nil {
		t.Fatal("official helper identity could not be verified")
	}
	const physical = "172.31.247.2:52212"
	const tlsName = "quic-probe.invalid"
	link := domain.LinkID("lnk_b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0")
	server, client, err := GeneratePair(link, tlsName)
	if err != nil {
		t.Fatal("isolated QUIC credentials could not be issued")
	}
	defer server.Clear()
	defer client.Clear()

	// Role roots and 0600 credential files remain disjoint as on two hosts.
	for _, entry := range []struct {
		role   Role
		name   string
		bundle CredentialBundle
	}{
		{Listen, "server", server}, {Dial, "client", client},
	} {
		storage := filepath.Join(root, entry.name)
		if err := os.Mkdir(storage, 0o700); err != nil {
			t.Fatal("isolated role root unavailable")
		}
		plan := Plan{LinkID: link, Role: entry.role,
			Underlay: netip.MustParseAddrPort(physical), TLSName: tlsName}
		var localWG uint16
		if entry.role == Listen {
			plan.LocalWGUDPPort = 51820
			localWG = 51820
		} else {
			plan.LocalForwardUDPPort = 52211
			plan.PeerWGUDPPort = 51820
			localWG = 51821
		}
		if _, err := StageCredentials(storage, plan, entry.bundle); err != nil {
			t.Fatalf("protected %s credentials could not be staged", entry.name)
		}
		created, err := StageHelperConfig(storage, plan, localWG, binary)
		if err != nil {
			t.Fatalf("protected %s helper config could not be staged", entry.name)
		}
		readback, err := InspectHelperConfig(storage, plan, localWG, binary)
		if err != nil || readback != created {
			t.Fatalf("protected %s exact helper config readback failed", entry.name)
		}
		target := filepath.Join(storage, "credentials", "quic", string(link), "helper.json")
		conf, err := os.ReadFile(target)
		if err != nil || len(conf) == 0 || bytes.Contains(conf, []byte("\"insecure\": true")) {
			clear(conf)
			t.Fatalf("protected %s config was absent or insecure", entry.name)
		}
		clear(conf)
		stat, err := os.Lstat(target)
		if err != nil || stat.Mode().Perm() != 0o600 {
			t.Fatalf("protected %s config must be a private 0600 regular file", entry.name)
		}
	}
	// This is only a test-owned disposable nft CREATE plan, not an Engine
	// journal or an original ownership receipt. Executed exclusively in the
	// sibling namespace by the opt-in launcher after namespace attestation.
	guard, err := linux.NewQUICWGIngressPlan(link, 51820, "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal("isolated QUIC ingress guard plan unavailable")
	}
	batch, err := guard.NFTBatch()
	if err != nil {
		t.Fatal("isolated QUIC guard batch invalid")
	}
	if err := os.WriteFile(filepath.Join(root, "guard.nft"), []byte(batch), 0o600); err != nil {
		t.Fatal("isolated private nft guard batch could not be staged")
	}
	t.Log("PASS: two distinct protected role configurations and shared QUIC nft guard plan")
}

// After the launcher applies the exact test-only nft batch, this entrypoint
// runs in the disposable sibling namespace and checks actual kernel objects
// using the shared strict read-only inspector. Not an ownership receipt.
func TestPinnedHysteriaKernelWGGuardReadback(t *testing.T) {
	if os.Getenv("STL_QUIC_WG_L3_GUARD_CHECK") != "approved" {
		t.Skip("requires disposable sibling network namespace")
	}
	parentUser, parentNet := os.Getenv("STL_QUIC_PARENT_USERNS"), os.Getenv("STL_QUIC_PARENT_NETNS")
	currentUser, errUser := os.Readlink("/proc/self/ns/user")
	currentNet, errNet := os.Readlink("/proc/self/ns/net")
	if os.Getuid() != 0 || errUser != nil || errNet != nil ||
		parentUser == "" || parentNet == "" || currentUser == parentUser || currentNet == parentNet {
		t.Fatal("QUIC nft readback cannot run outside disposable user/net namespace")
	}
	link := domain.LinkID("lnk_b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0")
	guard, err := linux.NewQUICWGIngressPlan(link, 51820, "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal("disposable QUIC guard plan invalid")
	}
	observed, err := linux.InspectWGIngressGuard(context.Background(), linux.ExecRunner{}, guard)
	if err != nil || !observed {
		t.Fatal("disposable live QUIC nft guard differs from exact planned table")
	}
	t.Log("PASS: actual kernel nft table/chain/rule strictly match the QUIC guard plan")
}
