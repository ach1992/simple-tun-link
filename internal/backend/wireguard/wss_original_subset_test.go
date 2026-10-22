package wireguard

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

func TestWSSOriginalRecoveryRejectsForeignUnmarkedStaging(t *testing.T) {
	b, link, _, kernel, _ := fixture(t)
	b.wssHost = wssVacancyTestHost{}
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	stage, err := linux.WSSStagingName(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		t.Fatal(err)
	}
	// A foreign WG object was created with the exact expected staging name
	// after an STL nft guard, but before any verified exclusive NEWLINK ACK.
	foreign := observedLink{Exists: true, Name: stage, IfIndex: 17}
	kernel.target = foreign
	obs := observation{WSSLink: link, Links: []observedLink{foreign}, GuardPresent: true}
	if err := b.CrashCompensateOriginal(ctx, link, obs); err == nil || !strings.Contains(err.Error(), "unmarked WSS staging") {
		t.Fatalf("unmarked foreign staging accepted: %v", err)
	}
	if kernel.deletedInterfaces != 0 || !kernel.target.Exists {
		t.Fatal("foreign staging kernel object deleted or changed")
	}
	for _, call := range kernel.calls {
		if len(call) > 0 && call[0] == "wg" {
			t.Fatal("unmarked staging should be denied before inferred WG configuration checks")
		}
	}
}

func TestWSSOriginalRecoveryAcceptsOnlyIntendedPartialConfig(t *testing.T) {
	_, link, _, _, _ := fixture(t)
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	p := observedLink{PublicKey: link.WireGuard.LocalPublicKey,
		ListenPort: link.WireGuard.ListenPort, Peers: []string{link.WireGuard.PeerPublicKey},
		AllowedIPs: netip.PrefixFrom(link.Addresses.Peer.Addr(), 32).String(),
		Keepalive:  link.WireGuard.LocalKeepalive}
	for name, change := range map[string]func(*observedLink){
		"empty":                      func(s *observedLink) { *s = observedLink{} },
		"listen_only":                func(s *observedLink) { *s = observedLink{ListenPort: link.WireGuard.ListenPort} },
		"local_key_only":             func(s *observedLink) { *s = observedLink{PublicKey: link.WireGuard.LocalPublicKey} },
		"key_and_listen":             func(s *observedLink) { s.Peers = nil; s.AllowedIPs = ""; s.Keepalive = 0 },
		"peer_without_allowedips":    func(s *observedLink) { s.AllowedIPs = ""; s.Keepalive = 0 },
		"peer_partial_keepalive":     func(s *observedLink) { s.Keepalive = 0 },
		"configured_with_local_addr": func(s *observedLink) { s.IPv4Addresses = []netip.Prefix{link.Addresses.Local} },
		"configured_and_up":          func(s *observedLink) { s.IPv4Addresses = []netip.Prefix{link.Addresses.Local}; s.Up = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := p
			change(&s)
			if !originalWSSWGConfigSubset(s, link) {
				t.Fatal("genuinely original intermediate state denied")
			}
		})
	}
	for name, change := range map[string]func(*observedLink){
		"foreign_key":           func(s *observedLink) { s.PublicKey = link.WireGuard.PeerPublicKey },
		"foreign_port":          func(s *observedLink) { s.ListenPort++ },
		"foreign_peer":          func(s *observedLink) { s.Peers = []string{link.WireGuard.LocalPublicKey} },
		"extra_peer":            func(s *observedLink) { s.Peers = append(s.Peers, link.WireGuard.LocalPublicKey) },
		"foreign_allowed_ip":    func(s *observedLink) { s.AllowedIPs = "0.0.0.0/0" },
		"foreign_keepalive":     func(s *observedLink) { s.Keepalive++ },
		"unexpected_endpoint":   func(s *observedLink) { s.Endpoint = "192.0.2.9:3" },
		"address_before_config": func(s *observedLink) { s.AllowedIPs = ""; s.IPv4Addresses = []netip.Prefix{link.Addresses.Local} },
		"foreign_address":       func(s *observedLink) { s.IPv4Addresses = []netip.Prefix{netip.MustParsePrefix("10.10.0.1/32")} },
		"up_without_address":    func(s *observedLink) { s.Up = true },
		"up_with_partial_config": func(s *observedLink) {
			s.AllowedIPs = ""
			s.Up = true
			s.IPv4Addresses = []netip.Prefix{link.Addresses.Local}
		},
		"peer_without_key": func(s *observedLink) { s.PublicKey = "" },
	} {
		t.Run(name, func(t *testing.T) {
			s := p
			change(&s)
			if originalWSSWGConfigSubset(s, link) {
				t.Fatal("non-original partial state admitted")
			}
		})
	}
}

func TestWSSOriginalAddressInventoryRejectsNonIPv4AndIncomplete(t *testing.T) {
	base := `[{"ifindex":17,"ifname":"stlwg0123456789","addr_info":[] }]`
	for name, raw := range map[string]string{
		"correct_empty":       base,
		"unexpected_ipv6":     `[{"ifindex":17,"ifname":"stlwg0123456789","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}]}]`,
		"missing_list":        `[{"ifindex":17,"ifname":"stlwg0123456789"}]`,
		"null_list":           `[{"ifindex":17,"ifname":"stlwg0123456789","addr_info":null}]`,
		"wrong_ifindex":       `[{"ifindex":18,"ifname":"stlwg0123456789","addr_info":[]}]`,
		"duplicate_ifindex":   `[{"ifindex":17,"ifindex":17,"ifname":"stlwg0123456789","addr_info":[]}]`,
		"duplicate_addr_list": `[{"ifindex":17,"ifname":"stlwg0123456789","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}],"addr_info":[]}]`,
		"family_case_alias":   `[{"ifindex":17,"ifname":"stlwg0123456789","addr_info":[{"family":"inet6","Family":"inet","local":"fe80::1","prefixlen":64}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			addresses, err := parseOriginalWSSAddresses([]byte(raw), "stlwg0123456789", 17)
			if name == "correct_empty" {
				if err != nil || len(addresses) != 0 {
					t.Fatalf("expected empty address inventory: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe address inventory admitted")
			}
		})
	}
}

// The original alias and ifindex are independently verified before any
// destructive effect; then original partial configuration is compensated
// in the same helper -> kernel -> guard order as a complete original.
type originalPartialCompensationHost struct {
	wssVacancyTestHost
	guard   bool
	deleted int
}

func (h *originalPartialCompensationHost) GuardPresent(context.Context, domain.Link) (bool, error) {
	return h.guard, nil
}
func (h *originalPartialCompensationHost) RemoveGuard(context.Context, domain.Link) (core.Rollback, error) {
	h.guard = false
	h.deleted++
	return nil, nil
}
func TestWSSOriginalTaggedPartialConfigurationCompensatesOnlyOriginal(t *testing.T) {
	for _, field := range []string{"key", "port", "peer", "configured", "address", "up"} {
		t.Run(field, func(t *testing.T) {
			b, link, _, kernel, _ := fixture(t)
			link.Backend = domain.BackendWireGuardWSS
			link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
			if err := link.Validate(); err != nil {
				t.Fatal(err)
			}
			ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			tag, err := linux.WSSOwnerTag(link.ID, core.WSSOrigin(ctx))
			if err != nil {
				t.Fatal(err)
			}
			name, _ := InterfaceName(link.ID)
			target := observedLink{Exists: true, IfIndex: 17, Name: name, Alias: tag, Owner: link.ID}
			switch field {
			case "key", "port", "peer", "configured", "address", "up":
				target.PublicKey = link.WireGuard.LocalPublicKey
			}
			if field != "key" {
				target.ListenPort = link.WireGuard.ListenPort
			}
			if field == "peer" || field == "configured" || field == "address" || field == "up" {
				target.Peers = []string{link.WireGuard.PeerPublicKey}
			}
			if field == "configured" || field == "address" || field == "up" {
				target.AllowedIPs = netip.PrefixFrom(link.Addresses.Peer.Addr(), 32).String()
				target.Keepalive = link.WireGuard.LocalKeepalive
			}
			if field == "address" || field == "up" {
				target.IPv4Addresses = []netip.Prefix{link.Addresses.Local}
			}
			target.Up = field == "up"
			kernel.target = target
			host := &originalPartialCompensationHost{guard: true}
			b.wssHost = host
			current, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.CrashCompensateOriginal(ctx, link, current); err != nil {
				t.Fatalf("genuine tagged partial refused: %v", err)
			}
			if kernel.deletedInterfaces != 1 || kernel.target.Exists || host.guard || host.deleted != 1 {
				t.Fatalf("original not fully retired: kernelDelete=%d guardDelete=%d guard=%t", kernel.deletedInterfaces, host.deleted, host.guard)
			}
			again, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.CrashCompensateOriginal(ctx, link, again); err != nil {
				t.Fatalf("idempotent compensation denied: %v", err)
			}
			if kernel.deletedInterfaces != 1 || host.deleted != 1 {
				t.Fatal("idempotent recovery repeated host deletion")
			}
		})
	}
}
