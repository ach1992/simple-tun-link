//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	l2tp "github.com/ach1992/simple-tun-link/internal/backend/l2tpv3"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/managedmtu"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

// TestL2TPv3NetnsE2E is an explicit privileged, two-netns real-Linux
// acceptance entrypoint; ordinary go test never applies host resources.
func TestL2TPv3NetnsE2E(t *testing.T) {
	if os.Getenv("STL_L2TPV3_NETNS_E2E") != "approved" {
		t.Skip("requires isolated disposable root network namespaces")
	}
	role := os.Getenv("STL_L2TPV3_E2E_ROLE")
	action := os.Getenv("STL_L2TPV3_E2E_ACTION")
	root := os.Getenv("STL_L2TPV3_E2E_STATE_ROOT")
	if (role != "a" && role != "b") || root == "" {
		t.Fatal("role or isolated state directory unavailable")
	}
	link := domain.Link{
		ID: "lnk_1234567890abcdef1234567890abcdef", Backend: domain.BackendL2TPv3, Encapsulation: domain.EncapNative,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("198.18.115.1"), Peer: netip.MustParseAddr("198.18.115.2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.253.115.1/30"), Peer: netip.MustParsePrefix("10.253.115.2/30")},
		MTU:       domain.MTUPolicy{Mode: domain.MTUAuto},
	}
	// The secondary Link shares the SAME public underlay with the primary.
	// It must remain usable after the primary Link is removed.
	switch os.Getenv("STL_L2TPV3_E2E_SLOT") {
	case "", "primary":
	case "secondary":
		link.ID = "lnk_abcdefabcdefabcdefabcdefabcdefab"
		link.Addresses = domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.253.116.1/30"),
			Peer:  netip.MustParsePrefix("10.253.116.2/30"),
		}
	default:
		t.Fatal("unrecognized L2TPv3 test Link slot")
	}
	if role == "b" {
		link = pairing.Invert(link)
	}
	runner := linux.ExecRunner{}
	locks := state.NewLockManager(root)
	b, err := l2tp.New(l2tp.Options{Runner: runner, Routes: linux.RouteResolver{Runner: runner},
		Firewall:   linux.IPTablesFirewall{Runner: runner, Locks: locks},
		Collisions: linux.CollisionInspector{Snapshotter: linux.HostSnapshotter{Runner: runner}}})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := app.New(reg, state.NewFileStore(root), locks)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetMTUManager(managedmtu.HostMTUManager{Runner: runner, SetByIndex: linux.SetLinkMTUByIndex})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch action {
	case "ensure":
		res, err := engine.Ensure(ctx, link)
		if err != nil {
			t.Fatalf("real Linux L2TPv3 Ensure: %v", err)
		}
		t.Logf("L2TPV3_NETNS_ENSURE_OK role=%s changed=%t", role, res.Changed)
	case "exclusive-neighbor":
		observed, err := b.DiagnosticState(ctx, link)
		if err != nil || observed.IfIndex <= 0 {
			t.Fatalf("cannot identify original interface: %+v %v", observed, err)
		}
		// A competing exclusive Add must not replace the already owned peer
		// neighbor. The same kernel netlink primitive is used in production.
		err = linux.AddPermanentIPv4NeighborByIndex(ctx, observed.IfIndex,
			link.Addresses.Peer.Addr(), "02:ae:01:02:03:04")
		if !errors.Is(err, unix.EEXIST) {
			t.Fatalf("kernel neighbor did not refuse an occupied peer: %v", err)
		}
		result, err := engine.Ensure(ctx, link)
		if err != nil || result.Changed {
			t.Fatalf("exclusive add changed existing L2TPv3 neighbor/Link: %+v %v", result, err)
		}
		t.Logf("L2TPV3_KERNEL_NEIGHBOR_EXCLUSIVE_PASS role=%s", role)
	case "restore":
		res, err := engine.RestoreAll(ctx)
		if err != nil || len(res) != 1 || !res[0].Changed {
			t.Fatalf("real kernel Link cold restore: %+v %v", res, err)
		}
		t.Logf("L2TPV3_NETNS_RESTORE_OK role=%s", role)
	case "check":
		observed, err := b.DiagnosticState(ctx, link)
		if err != nil || observed.IfIndex <= 0 {
			t.Fatalf("real kernel L2TPv3 status: %+v %v", observed, err)
		}
		t.Logf("L2TPV3_NETNS_STATUS_OK role=%s %+v", role, observed)
	case "remove":
		res, err := engine.Remove(ctx, link.ID)
		if err != nil || !res.Changed {
			t.Fatalf("real kernel L2TPv3 Remove: %+v %v", res, err)
		}
		t.Logf("L2TPV3_NETNS_REMOVE_OK role=%s", role)
	default:
		t.Fatalf("invalid gated action %q", action)
	}
}
