package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type stagedCrashGuard struct {
	wssVacancyTestHost
	ensureCount int
	undoCount   int
}

func (h *stagedCrashGuard) EnsureGuard(_ context.Context, _ domain.Link) (core.Rollback, error) {
	h.ensureCount++
	return func(context.Context) error { h.undoCount++; return nil }, nil
}

// Regression for the precise security issue: a successful kernel NEWLINK
// may be followed by an error, deadline or cancellation before the caller
// sees the kernel ACK or captures the original staging ifindex. Never
// execute the nft guard's rollback just because no creationProgress flag
// was returned. Durable original journal will gate explicit recovery.
func TestWSSStagedNewLinkAmbiguousAckNeverRemovesGuard(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cause error
	}{
		{"dispatched_error", errors.New("ACK transport lost")},
		{"deadline", context.DeadlineExceeded},
		{"canceled", context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, link, _, _, _ := fixture(t)
			link.Backend = domain.BackendWireGuardWSS
			link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
			link.Addresses.Local = netip.MustParsePrefix("10.92.20.1/30")
			link.Addresses.Peer = netip.MustParsePrefix("10.92.20.2/30")
			if err := link.Validate(); err != nil {
				t.Fatal(err)
			}
			host := &stagedCrashGuard{}
			b.wssHost = host
			createCalled := false
			b.wssCreateStaged = func(_ context.Context, name string) error {
				if len(name) != 15 || name[0] != 'w' {
					return fmt.Errorf("non-original staging name")
				}
				createCalled = true
				// A successful host effect with an unknown caller-visible
				// outcome is indistinguishable from an error before dispatch.
				return tt.cause
			}
			ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			name, err := InterfaceName(link.ID)
			if err != nil {
				t.Fatal(err)
			}
			undo, err := b.ensureWSS(ctx, core.Request{Operation: core.OperationEnsure, Link: link},
				observation{}, plan{link: link, name: name, guardChange: true, interfaceChange: true})
			if !errors.Is(err, core.ErrIndeterminateHostEffect) {
				t.Fatalf("ambiguous RTM_NEWLINK treated as ordinary reversible failure: %v", err)
			}
			if !createCalled || host.ensureCount != 1 || host.undoCount != 0 || undo != nil {
				t.Fatalf("unproven kernel effect allowed firewall rollback: create=%t ensure=%d undo=%d callback=%v",
					createCalled, host.ensureCount, host.undoCount, undo != nil)
			}
		})
	}
}

// Run only with unshare -Urn in a fresh root-mapped, single-loopback-only
// namespace. Here RTM_NEWLINK really succeeds BEFORE returning a simulated
// deadline error. This establishes that the product keeps the guard rollback
// unavailable for a genuinely surviving, originally nonce-named WG object.
func TestWSSStagedNewLinkPostEffectLateAckNetNS(t *testing.T) {
	if os.Getenv("STL_WSS_ORIGIN_NETNS") != "1" {
		t.Skip("isolated fresh user/net namespace required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("not isolated root-mapped")
	}
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(mapping)), "0 ") {
		t.Fatal("no user mapping")
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) != 1 || ifaces[0].Name != "lo" {
		t.Fatal("not an empty fresh netns")
	}
	b, link, _, _, _ := fixture(t)
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	guard := &stagedCrashGuard{}
	b.wssHost = guard
	ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	stage, err := linux.WSSStagingName(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		t.Fatal(err)
	}
	b.wssCreateStaged = func(c context.Context, name string) error {
		if name != stage {
			t.Fatal("kernel staging resource identity changed")
		}
		if err := linux.CreateWSSWireGuardStaged(c, name); err != nil {
			return err
		}
		return context.DeadlineExceeded // AFTER actual kernel effect
	}
	name, _ := InterfaceName(link.ID)
	undo, err := b.ensureWSS(ctx, core.Request{Operation: core.OperationEnsure, Link: link},
		observation{}, plan{link: link, name: name, guardChange: true, interfaceChange: true})
	if !errors.Is(err, core.ErrIndeterminateHostEffect) || undo != nil || guard.undoCount != 0 {
		t.Fatalf("actual kernel creation uncertainty removed protection: %v", err)
	}
	present, err := net.InterfaceByName(stage)
	if err != nil || present.Index <= 0 {
		t.Fatal("original staged kernel WG object did not survive injected ACK failure")
	}
	defer func() {
		if err := linux.DeleteLinkByIndex(ctx, present.Index); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatal("unconfirmed staging creation was prematurely renamed")
	}
}
