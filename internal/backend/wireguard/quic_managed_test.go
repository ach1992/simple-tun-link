package wireguard

import (
	"context"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type ordinaryQUICHost struct{ liveOrdinaryWSSHost }

func (h *ordinaryQUICHost) Begin(ctx context.Context, _ domain.Link, _ *state.QUICGeneration) (context.Context, func() error, error) {
	return ctx, func() error { return nil }, nil
}
func (h *ordinaryQUICHost) Attest(context.Context, domain.Link) (state.QUICGeneration, error) {
	return state.QUICGeneration{}, nil
}

func ordinaryQUICFixture(t *testing.T) (*Backend, domain.Link, *fakeKernel, context.Context) {
	t.Helper()
	b, link, k, _, _ := ordinaryWSSFixture(t)
	link.Backend = domain.BackendWireGuardQUIC
	link.WSS = domain.WSSOptions{}
	link.QUIC = domain.QUICOptions{Role: "listen", UDPPort: 59443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	b.wssHost = nil
	b.quicHost = &ordinaryQUICHost{liveOrdinaryWSSHost: liveOrdinaryWSSHost{originalPartialCompensationHost: originalPartialCompensationHost{guard: true}}}
	ctx, err := core.WithQUICOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	ctx = core.WithQUICGeneration(ctx, state.QUICGeneration{Version: 1, WGIfIndex: k.target.IfIndex})
	k.target.Alias, err = linux.QUICWGOwnerTag(link.ID, core.QUICOrigin(ctx))
	if err != nil {
		t.Fatal(err)
	}
	return b, link, k, ctx
}

func TestManagedQUICOriginalIfindexAndFullConfigurationGate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fakeKernel)
	}{
		{"recycled-ifindex", func(k *fakeKernel) { k.target.IfIndex++ }},
		{"fwmark", func(k *fakeKernel) { k.target.FwMark = 19 }},
		{"PSK", func(k *fakeKernel) { k.presharedDrift = true }},
		{"foreign-address-metadata", func(k *fakeKernel) { k.addressExtra = map[string]any{"scope": "link"} }},
		{"unexpected-ipv6", func(k *fakeKernel) { k.extraIPV6 = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, link, k, ctx := ordinaryQUICFixture(t)
			if err := b.requireCompleteQUICOriginal(ctx, link, k.target, k.target.Name); err != nil {
				t.Fatalf("valid original rejected: %v", err)
			}
			tc.change(k)
			if err := b.requireCompleteQUICOriginal(ctx, link, k.target, k.target.Name); err == nil {
				t.Fatal("changed original was admitted for managed lifecycle")
			}
		})
	}
}

func TestManagedQUICDoesNotExposeNativePhysicalOverheadOrUnboundDiagnostics(t *testing.T) {
	b, link, _, _ := ordinaryQUICFixture(t)
	if _, err := Overhead(link); err == nil {
		t.Fatal("QUIC framing was treated as fixed native WG overhead")
	}
	if _, err := b.DiagnosticState(context.Background(), link); err == nil {
		t.Fatal("unbound current shape granted managed QUIC diagnostic ownership")
	}
}
