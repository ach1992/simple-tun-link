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

type liveOrdinaryWSSHost struct {
	originalPartialCompensationHost
}

func (h *liveOrdinaryWSSHost) HelperPresent(context.Context, domain.Link) (bool, error) {
	return true, nil
}
func (h *liveOrdinaryWSSHost) Preflight(context.Context, domain.Link, bool) error {
	return nil
}

func ordinaryWSSFixture(t *testing.T) (*Backend, domain.Link, *fakeKernel, *liveOrdinaryWSSHost, context.Context) {
	t.Helper()
	b, link, _, k, _ := fixture(t)
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	h := &liveOrdinaryWSSHost{originalPartialCompensationHost: originalPartialCompensationHost{guard: true}}
	b.wssHost = h
	ctx, err := core.WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	name, err := InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := linux.WSSOwnerTag(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		t.Fatal(err)
	}
	k.target = observedLink{
		Exists: true, IfIndex: 17, Name: name, Alias: alias, Owner: link.ID, Up: true,
		PublicKey: link.WireGuard.LocalPublicKey, ListenPort: link.WireGuard.ListenPort,
		Peers:         []string{link.WireGuard.PeerPublicKey},
		AllowedIPs:    netip.PrefixFrom(link.Addresses.Peer.Addr(), 32).String(),
		Keepalive:     link.WireGuard.LocalKeepalive,
		IPv4Addresses: []netip.Prefix{link.Addresses.Local},
		Endpoint:      "203.0.113.170:55223", // authorized dynamic roaming
	}
	return b, link, k, h, ctx
}

func TestWSSOrdinaryValidateRejectsOriginalConfigurationDrift(t *testing.T) {
	for _, tc := range []struct {
		name  string
		drift func(*fakeKernel)
	}{
		{"fwmark", func(k *fakeKernel) { k.target.FwMark = 0x7744 }},
		{"preshared_key", func(k *fakeKernel) { k.presharedDrift = true }},
		{"foreign_scope", func(k *fakeKernel) { k.addressExtra = map[string]any{"scope": "link"} }},
		{"address_peer", func(k *fakeKernel) { k.addressExtra = map[string]any{"peer": "10.80.50.10"} }},
		{"address_lifetime", func(k *fakeKernel) { k.addressExtra = map[string]any{"valid_life_time": 90} }},
		{"unexpected_ipv6", func(k *fakeKernel) { k.extraIPV6 = true }},
		{"wrong_allowed", func(k *fakeKernel) { k.target.AllowedIPs = "0.0.0.0/0" }},
		{"wrong_peer", func(k *fakeKernel) { k.target.Peers = []string{k.target.PublicKey} }},
		{"wrong_owner", func(k *fakeKernel) { k.target.Alias = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, link, k, h, ctx := ordinaryWSSFixture(t)
			req := core.Request{Operation: core.OperationEnsure, Link: link, OwnedResources: []domain.ResourceClaim{
				{Kind: domain.ResourceInterface, Key: k.target.Name},
				wssGuardClaim(link.ID),
			}}
			tc.drift(k)
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(ctx, req, obs, plan); err == nil {
				t.Fatal("ordinary Ensure accepted untrusted WSS kernel config")
			} else if strings.Contains(err.Error(), strings.Repeat("X", 43)) {
				t.Fatal("PSK secret leaked in Ensure error")
			}
			if k.deletedInterfaces != 0 || !h.guard || h.deleted != 0 {
				t.Fatal("failed validation mutated protected original/guard")
			}
		})
	}
}

func TestWSSOrdinaryRemoveReinspectionBlocksDrift(t *testing.T) {
	for _, tc := range []struct {
		name  string
		drift func(*fakeKernel)
	}{
		{"fwmark", func(k *fakeKernel) { k.target.FwMark = 0x77 }},
		{"preshared_key", func(k *fakeKernel) { k.presharedDrift = true }},
		{"unexpected_ipv6", func(k *fakeKernel) { k.extraIPV6 = true }},
		{"foreign_peer_addr", func(k *fakeKernel) { k.addressExtra = map[string]any{"broadcast": "10.80.50.1"} }},
		{"wrong_ifindex", func(k *fakeKernel) { k.target.IfIndex = 18 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, link, k, h, ctx := ordinaryWSSFixture(t)
			req := core.Request{Operation: core.OperationRemove, Link: link, Prior: &link, OwnedResources: []domain.ResourceClaim{
				{Kind: domain.ResourceInterface, Key: k.target.Name},
				wssGuardClaim(link.ID),
			}}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(ctx, req, obs, plan); err != nil {
				t.Fatalf("healthy preflight refused: %v", err)
			}
			tc.drift(k) // between last Engine Validate and Backend Apply
			undo, err := b.Apply(ctx, req, obs, plan)
			if err == nil {
				t.Fatal("ordinary Remove deleted re-drifted original")
			}
			if undo == nil {
				t.Fatal("original failure lost known scoped rollback")
			}
			if k.deletedInterfaces != 0 || !k.target.Exists || !h.guard || h.deleted != 0 {
				t.Fatal("Remove touched original kernel/ingress despite drift")
			}
			if strings.Contains(err.Error(), strings.Repeat("X", 43)) {
				t.Fatal("PSK secret leaked in removal error")
			}
		})
	}
}

func TestWSSOrdinaryHealthyRoamingAccepted(t *testing.T) {
	b, link, k, _, ctx := ordinaryWSSFixture(t)
	// Authenticated WireGuard endpoint roaming is normal, not owner drift.
	k.target.Endpoint = "198.51.100.250:50992"
	req := core.Request{Operation: core.OperationEnsure, Link: link, OwnedResources: []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: k.target.Name}, wssGuardClaim(link.ID),
	}}
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(ctx, req); err != nil {
		t.Fatal(err)
	}
}

// Engine verification is a separate last trusted step after Apply. A newly
// drifted WG object must not be committed as a healthy WSS Link.
func TestWSSOrdinaryVerifyRejectsPSKAndAddressDrift(t *testing.T) {
	for _, name := range []string{"preshared_key", "address_scope", "ipv6", "fwmark"} {
		t.Run(name, func(t *testing.T) {
			b, link, k, _, ctx := ordinaryWSSFixture(t)
			switch name {
			case "preshared_key":
				k.presharedDrift = true
			case "address_scope":
				k.addressExtra = map[string]any{"scope": "link"}
			case "ipv6":
				k.extraIPV6 = true
			case "fwmark":
				k.target.FwMark = 44
			}
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			if _, err := b.Verify(ctx, req); err == nil {
				t.Fatal("WSS Verify accepted post-Apply WG drift")
			}
		})
	}
}
