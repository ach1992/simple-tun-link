package ipsec

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// This test mutates ONLY its caller's network namespace. Run it strictly
// inside an ephemeral --network none container with CAP_NET_ADMIN, not in the
// host namespace or an SSH/MCP agent control-plane namespace.
func TestXFRMVacancyIsolatedKernelE2E(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_XFRM_ISOLATED") != "approved" {
		t.Skip("requires explicit isolated disposable NET_ADMIN namespace authorization")
	}
	ctx := context.Background()
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	inspect := NewXFRMVacancyInspector("ip")
	if err := inspect.RequireVacant(ctx, p); err != nil {
		t.Fatalf("disposable test namespace must start free of selected XFRM identity: %v", err)
	}
	run := func(args ...string) error {
		// Every argument is a predetermined test-only kernel resource.
		cmd := exec.CommandContext(ctx, "ip", args...)
		return cmd.Run()
	}
	// Foreign device with a DIFFERENT name but the SAME if_id. Detection
	// cannot rely on matching interface names or owner-looking aliases.
	t.Run("same-id-different-name", func(t *testing.T) {
		const name = "stlxotherprobe"
		if err := run("link", "add", "name", name, "type", "xfrm", "if_id", strconv.FormatUint(uint64(p.InterfaceID), 10)); err != nil {
			t.Fatalf("XFRM kernel prerequisite unavailable: %v", err)
		}
		t.Cleanup(func() {
			if err := run("link", "del", "dev", name); err != nil {
				t.Errorf("failed to delete only the test-owned XFRM interface: %v", err)
			}
		})
		if err := inspect.RequireVacant(ctx, p); err == nil {
			t.Fatal("foreign XFRM interface with colliding if_id was overlooked")
		}
	})
	if err := inspect.RequireVacant(ctx, p); err != nil {
		t.Fatal("released XFRM id still occupied:", err)
	}

	// Foreign device with the exact planned name but a DIFFERENT if_id.
	t.Run("same-name-different-id", func(t *testing.T) {
		id := p.InterfaceID + 1
		if id == 0 {
			id = 1
		}
		if err := run("link", "add", "name", p.InterfaceName, "type", "xfrm", "if_id", strconv.FormatUint(uint64(id), 10)); err != nil {
			t.Fatalf("XFRM kernel prerequisite unavailable: %v", err)
		}
		t.Cleanup(func() {
			if err := run("link", "del", "dev", p.InterfaceName); err != nil {
				t.Errorf("failed to delete only test-owned XFRM interface: %v", err)
			}
		})
		if err := inspect.RequireVacant(ctx, p); err == nil {
			t.Fatal("foreign interface with canonical name was incorrectly trusted")
		}
	})
	if err := inspect.RequireVacant(ctx, p); err != nil {
		t.Fatal("released interface name still occupied:", err)
	}

	// Reproduce the actual iproute2 6.1 -json xfrm policy output: legacy
	// text containing an orphan if_id. The inspector must reject this too.
	t.Run("orphan-policy-text-inventory", func(t *testing.T) {
		local := "10.251.1.1/32"
		remote := "10.251.1.2/32"
		id := strconv.FormatUint(uint64(p.InterfaceID), 10)
		add := []string{"xfrm", "policy", "add", "src", local, "dst", remote, "dir", "out", "if_id", id,
			"tmpl", "src", "192.0.2.10", "dst", "192.0.2.11", "proto", "esp", "reqid", "17", "mode", "tunnel"}
		if err := run(add...); err != nil {
			t.Fatalf("XFRM policy kernel prerequisite unavailable: %v", err)
		}
		t.Cleanup(func() {
			if err := run("xfrm", "policy", "del", "src", local, "dst", remote, "dir", "out", "if_id", id); err != nil {
				t.Errorf("failed to remove only the test-owned orphan XFRM policy: %v", err)
			}
		})
		if err := inspect.RequireVacant(ctx, p); err == nil || !strings.Contains(err.Error(), "policy or SA already uses Link interface ID") {
			t.Fatalf("real kernel orphan policy was not positively identified as collision: %v", err)
		}
	})
	if err := inspect.RequireVacant(ctx, p); err != nil {
		t.Fatal("owned test policy cleanup failed:", err)
	}
	// Caller verifies context/environment via explicit success marker; no
	// production VICI/SA/PSK operation has occurred in this test.
	t.Log("ISOLATED_XFRM_REAL_KERNEL_COLLISION_CHECK=PASS")
	if strings.Contains(p.InterfaceName, "/") || len(p.InterfaceName) >= 16 {
		t.Fatal("invalid bounded test XFRM interface name")
	}
}
