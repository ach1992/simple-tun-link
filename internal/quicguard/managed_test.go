package quicguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func managedGuardFixture(t *testing.T) (*Managed, *guardTestRunner, domain.Link, context.Context, *int) {
	t.Helper()
	runner, wg := guardFixture(t)
	root := t.TempDir()
	store := state.NewFileStore(root)
	link := domain.Link{ID: fixtureID, DisplayName: "guard-managed", Backend: domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("198.51.100.60"), Peer: netip.MustParseAddr("192.0.2.10")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.96.20.0/31"), Peer: netip.MustParsePrefix("10.96.20.1/31")}, WireGuard: wg, QUIC: domain.QUICOptions{Role: "listen", UDPPort: 443}}
	host, err := composition.QUICHostPlanForLink(link)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composition.WireGuardProviderClaims(link.ID, link.Addresses.Local, wg)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := host.Local.CarrierClaims()
	if err != nil {
		t.Fatal(err)
	}
	unique := map[string]domain.ResourceClaim{}
	for _, c := range append(provider, carrier...) {
		unique[c.Canonical()] = c
	}
	var claims []domain.ResourceClaim
	for _, c := range unique {
		claims = append(claims, c)
	}
	op := state.QUICCrashOperation{Managed: &state.QUICManagedOperation{Version: 1, Intent: link, Operation: "ensure"}, Plan: host, Addresses: link.Addresses, WireGuard: wg, Nonce: fixtureNonce, Resources: claims,
		CertificateSHA256: strings.Repeat("a", 64), TrustCASHA256: strings.Repeat("b", 64), AuthorizationSHA256: strings.Repeat("c", 64), HelperConfigSHA256: strings.Repeat("d", 64), ExecutablePath: "/usr/local/libexec/stl/hysteria", ExecutableSHA256: strings.Repeat("e", 64), ExecutableDevice: 1, ExecutableInode: 2}
	if err := store.Update(context.Background(), func(s *state.Snapshot) error { s.QUICCrashOperations = append(s.QUICCrashOperations, op); return nil }); err != nil {
		t.Fatal(err)
	}
	m, err := NewManaged(root, store)
	if err != nil {
		t.Fatal(err)
	}
	m.runner = liveGuardReader{runner}
	m.kernelBootID = func() (string, error) { return testBootID, nil }
	dispatches := 0
	m.apply = func(_ context.Context, batch string) error {
		dispatches++
		if strings.HasPrefix(batch, "delete table ") {
			runner.present = false
			runner.nftRules = []byte(emptyRuleset)
		} else {
			runner.present = true
			runner.nftRules = runner.exact
		}
		return nil
	}
	ctx, err := core.WithQUICOrigin(context.Background(), fixtureNonce)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = core.WithQUICManagedOperation(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = m.Begin(ctx, link, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, runner, link, ctx, &dispatches
}

func TestManagedGuardNeverPromotesPreexistingShapeAndRequiresOriginalDeletion(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	m, runner, link, ctx, calls := managedGuardFixture(t)
	runner.present = true
	if _, err := m.EnsureGuard(ctx, link); err == nil || *calls != 0 {
		t.Fatal("pre-existing same-byte guard became an original")
	}
	runner.present = false
	if _, err := m.EnsureGuard(ctx, link); err != nil || *calls != 1 {
		t.Fatalf("exclusive managed original create failed: %v", err)
	}
	if _, err := m.Attest(ctx, link); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RemoveGuard(ctx, link); err == nil || *calls != 1 || !runner.present {
		t.Fatal("guard removed without positive original WG deletion")
	}
	deleted, err := core.WithQUICWGDeleted(ctx, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	runner.ssAll = "ESTAB 0 0 0.0.0.0:51820 192.0.2.10:60000\n"
	if _, err := m.RemoveGuard(deleted, link); err == nil || *calls != 1 || !runner.present {
		t.Fatal("connected UDP competitor did not preserve guard")
	}
	runner.ssAll = ""
	if _, err := m.RemoveGuard(deleted, link); err != nil || *calls != 2 || runner.present {
		t.Fatalf("verified guard retirement failed: %v", err)
	}
}

func TestManagedGuardRequiresRealDurableJournalAndQuarantinesUnknownCreate(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	m, runner, link, ctx, calls := managedGuardFixture(t)
	op, _ := core.QUICManagedOperation(ctx)
	op.HelperConfigSHA256 = strings.Repeat("f", 64)
	forged, err := core.WithQUICManagedOperation(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnsureGuard(forged, link); err == nil || *calls != 0 {
		t.Fatal("caller context substituted for durable journal")
	}
	m.apply = func(context.Context, string) error { *calls++; runner.present = true; return fmt.Errorf("ACK lost") }
	if _, err := m.EnsureGuard(ctx, link); !errors.Is(err, core.ErrIndeterminateHostEffect) || *calls != 1 || !runner.present {
		t.Fatal("unknown guard dispatch was not quarantined")
	}
	deleted, err := core.WithQUICWGDeleted(ctx, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RemoveGuard(deleted, link); err == nil || *calls != 1 {
		t.Fatal("failed create minted guard deletion authority")
	}
}
