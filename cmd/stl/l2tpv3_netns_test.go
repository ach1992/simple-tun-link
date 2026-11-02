//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
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
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"golang.org/x/sys/unix"
)

// Inject an error only AFTER the real kernel has accepted a destructive
// iproute2 operation. This runner cannot manufacture successful kernel calls.
type l2tpPostEffectRunner struct {
	linux.Runner
	command  string
	injected bool
}

func (r *l2tpPostEffectRunner) Run(ctx context.Context, binary string, args ...string) (linux.CommandResult, error) {
	out, err := r.Runner.Run(ctx, binary, args...)
	if err == nil && r.command != "" && !r.injected &&
		strings.HasPrefix(strings.Join(args, " "), r.command) {
		r.injected = true
		return out, errors.New("injected post-effect L2TPv3 kernel delete error")
	}
	return out, err
}

func realL2TPInterfaceMTU(ctx context.Context, runner linux.Runner, name string) (index, mtu int, err error) {
	result, err := runner.Run(ctx, "ip", "-json", "link", "show", "dev", name)
	if err != nil {
		return 0, 0, err
	}
	var rows []struct {
		IfIndex int
		MTU     int
	}
	if err = json.Unmarshal(result.Stdout, &rows); err != nil || len(rows) != 1 {
		return 0, 0, errors.New("cannot verify exact Linux L2TPv3 interface MTU")
	}
	return rows[0].IfIndex, rows[0].MTU, nil
}

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
	if action == "compensate-session" || action == "compensate-tunnel" {
		link.MTU = domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1300}
	}
	faultRunner := &l2tpPostEffectRunner{Runner: linux.ExecRunner{}}
	var runner linux.Runner = faultRunner
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
	case "compensate-session", "compensate-tunnel":
		// A fresh committed manual-MTU Link in this isolated namespace.
		// The injected error happens AFTER the actual destructive kernel
		// operation, so the replacement l2tpeth cannot inherit the old MTU.
		if _, err := engine.Ensure(ctx, link); err != nil {
			t.Fatalf("manual MTU Ensure before injection: %v", err)
		}
		name, err := l2tp.InterfaceName(link.ID)
		if err != nil {
			t.Fatal(err)
		}
		firstIndex, firstMTU, err := realL2TPInterfaceMTU(ctx, runner, name)
		if err != nil || firstMTU != 1300 {
			t.Fatalf("original kernel managed MTU missing: index=%d mtu=%d err=%v", firstIndex, firstMTU, err)
		}
		if action == "compensate-session" {
			faultRunner.command = "l2tp del session"
		} else {
			faultRunner.command = "l2tp del tunnel"
		}
		_, err = engine.Remove(ctx, link.ID)
		proof := stlerr.EvidenceOf(err)
		if err == nil || !faultRunner.injected || proof == nil ||
			proof.Stage != "apply" || proof.Rollback != "completed_unverified" {
			t.Fatalf("real kernel post-delete compensation failed: %v %+v injected=%t", err, proof, faultRunner.injected)
		}
		secondIndex, secondMTU, err := realL2TPInterfaceMTU(ctx, runner, name)
		if err != nil || secondIndex == firstIndex || secondMTU != firstMTU {
			t.Fatalf("real recreated L2TPv3 did not restore exact manual MTU: old=%d/%d new=%d/%d err=%v", firstIndex, firstMTU, secondIndex, secondMTU, err)
		}
		if _, err := b.Verify(ctx, backend.Request{Operation: backend.OperationEnsure, Link: link}); err != nil {
			t.Fatalf("real restored backend/firewall ownership unavailable: %v", err)
		}
		snap, err := state.NewFileStore(root).Load(ctx)
		rec, found := snap.Find(link.ID)
		if err != nil || !found || rec.Desired.MTU != link.MTU {
			t.Fatalf("real committed State lost on compensated Remove: %v %+v", err, rec)
		}
		if _, err := engine.Remove(ctx, link.ID); err != nil {
			t.Fatalf("normal real kernel cleanup after injected error: %v", err)
		}
		snap, err = state.NewFileStore(root).Load(ctx)
		if err != nil || len(snap.Links) != 0 {
			t.Fatalf("real cleanup retained committed State: %v %+v", err, snap.Links)
		}
		t.Logf("L2TPV3_REAL_KERNEL_MANUAL_MTU_REMOVE_COMPENSATION_PASS action=%s", action)
	default:
		t.Fatalf("invalid gated action %q", action)
	}
}
