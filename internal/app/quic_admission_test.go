package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type quicVacancyProbe struct {
	calls    int
	claims   []domain.ResourceClaim
	occupied bool
	err      error
}

func (p *quicVacancyProbe) Vacant(_ context.Context, claims []domain.ResourceClaim) (bool, error) {
	p.calls++
	p.claims = append([]domain.ResourceClaim(nil), claims...)
	return !p.occupied, p.err
}

func quicReadinessFixture() (composition.QUICLocalAdmission, QUICWireGuardProvider) {
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	plan := composition.QUICLocalAdmission{
		LinkID: id, Role: composition.Dial, LocalWGUDPPort: 51821,
		LocalHelperUDPPort: 52211, RemoteWGUDPPort: 51820,
	}
	provider := QUICWireGuardProvider{
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.96.20.0/31"),
			Peer:  netip.MustParsePrefix("10.96.20.1/31"),
		},
		WireGuard: domain.WireGuardOptions{
			LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32)),
			PeerPublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32)),
			ListenPort:     51821, PeerPort: 52211,
		},
	}
	return plan, provider
}

func quicClaim(kind, key string) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: kind, Key: key}
}

func TestQUICAdmissionCanonicalUnionAndReadOnlyMultiLink(t *testing.T) {
	ctx := context.Background()
	e, store := newEngine(t, newFakeBackend())
	plan, provider := quicReadinessFixture()
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	probe := &quicVacancyProbe{}
	claims, err := e.CheckQUICPreparation(ctx, plan, provider, probe)
	if err != nil {
		t.Fatal(err)
	}
	name, err := composition.WireGuardInterfaceName(plan.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	want := unionClaims([]domain.ResourceClaim{
		quicClaim(domain.ResourceInterface, name),
		quicClaim(domain.ResourceLinkAddress, "10.96.20.0"),
		quicClaim(domain.ResourceLinkSubnet, "10.96.20.0/31"),
		quicClaim(domain.ResourceUDPListenPort, "51821"),
		quicClaim(domain.ResourceBackendID, "wireguard/local-public/"+provider.WireGuard.LocalPublicKey),
		quicClaim(domain.ResourceBackendID, "quic/helper/"+string(plan.LinkID)),
		quicClaim(domain.ResourceBackendID, "quic/tls-identity/"+string(plan.LinkID)),
		quicClaim(domain.ResourceFirewall, "quic/nft/"+string(plan.LinkID)),
		quicClaim(domain.ResourceUDPListenPort, "52211"),
	})
	if !reflect.DeepEqual(want, claims) {
		t.Fatalf("composed claims incomplete or duplicated:\ngot %v\nwant %v", claims, want)
	}
	if probe.calls != 1 {
		t.Fatalf("live probe count = %d", probe.calls)
	}
	for _, c := range probe.claims {
		if c.Kind != domain.ResourceInterface && c.Kind != domain.ResourceLinkAddress &&
			c.Kind != domain.ResourceLinkSubnet && c.Kind != domain.ResourceUDPListenPort {
			t.Fatalf("uninspectable host claim was silently treated as verified: %+v", c)
		}
	}
	if !slices.Contains(probe.claims, quicClaim(domain.ResourceUDPListenPort, "51821")) ||
		!slices.Contains(probe.claims, quicClaim(domain.ResourceUDPListenPort, "52211")) ||
		slices.Contains(probe.claims, quicClaim(domain.ResourceUDPListenPort, "51820")) {
		t.Fatalf("physical/local and remote port reservation mixed up: %+v", probe.claims)
	}
	second := plan
	second.LinkID = domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	second.LocalHelperUDPPort = 52212
	second.RemoteWGUDPPort = plan.RemoteWGUDPPort // same remote peer is allowed
	other := provider
	other.Addresses.Local = netip.MustParsePrefix("10.96.22.0/31")
	other.Addresses.Peer = netip.MustParsePrefix("10.96.22.1/31")
	other.WireGuard.ListenPort = 51822
	second.LocalWGUDPPort = other.WireGuard.ListenPort
	other.WireGuard.PeerPort = second.LocalHelperUDPPort
	other.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	if _, err := e.CheckQUICPreparation(ctx, second, other, probe); err != nil {
		t.Fatalf("independent same-peer candidate was limited: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only preview wrote State: %v", err)
	}
}

func TestQUICAdmissionRejectsInvalidInputAndExactLinkIdentity(t *testing.T) {
	ctx := context.Background()
	e, store := newEngine(t, newFakeBackend())
	plan, provider := quicReadinessFixture()
	for _, tc := range []struct {
		name   string
		change func(*composition.QUICLocalAdmission, *QUICWireGuardProvider)
	}{
		{"no-link-id", func(p *composition.QUICLocalAdmission, _ *QUICWireGuardProvider) { p.LinkID = "lnk_bad" }},
		{"invalid-address", func(_ *composition.QUICLocalAdmission, w *QUICWireGuardProvider) {
			w.Addresses.Local = netip.MustParsePrefix("0.0.0.0/0")
		}},
		{"same-address", func(_ *composition.QUICLocalAdmission, w *QUICWireGuardProvider) {
			w.Addresses.Peer = w.Addresses.Local
		}},
		{"bad-key", func(_ *composition.QUICLocalAdmission, w *QUICWireGuardProvider) {
			w.WireGuard.LocalPublicKey = "not-a-key"
		}},
		{"missing-wg-port", func(_ *composition.QUICLocalAdmission, w *QUICWireGuardProvider) { w.WireGuard.ListenPort = 0 }},
		{"wrong-wg-peer-port", func(_ *composition.QUICLocalAdmission, w *QUICWireGuardProvider) { w.WireGuard.PeerPort = 51820 }},
		{"same-wg-helper-port", func(p *composition.QUICLocalAdmission, w *QUICWireGuardProvider) {
			p.LocalHelperUDPPort = w.WireGuard.ListenPort
		}},
		{"wrong-listen-acl", func(p *composition.QUICLocalAdmission, _ *QUICWireGuardProvider) {
			p.Role = composition.Listen
			p.LocalWGUDPPort = 51820
			p.LocalHelperUDPPort = 0
			p.RemoteWGUDPPort = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, w := plan, provider
			tc.change(&p, &w)
			probe := &quicVacancyProbe{}
			if _, err := e.CheckQUICPreparation(ctx, p, w, probe); stlerr.CodeOf(err) != stlerr.CodeInvalid || probe.calls != 0 {
				t.Fatalf("unsafe plan admitted or inspected: %v, calls=%d", err, probe.calls)
			}
		})
	}
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, nil); stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("missing inspector accepted: %v", err)
	}
	if _, err := e.CheckQUICPreparation(nil, plan, provider, &quicVacancyProbe{}); stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("missing context accepted: %v", err)
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		link := linkFor(t, "existing", "10.97.0.0/31", "10.97.0.1/31")
		link.ID = plan.LinkID
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	probe := &quicVacancyProbe{}
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, probe); stlerr.CodeOf(err) != stlerr.CodeConflict || probe.calls != 0 {
		t.Fatalf("already committed Link reused: %v", err)
	}
}

func TestQUICAdmissionRejectsOtherLinkReservationsAndFreshLockedState(t *testing.T) {
	ctx := context.Background()
	e, store := newEngine(t, newFakeBackend())
	plan, provider := quicReadinessFixture()
	other := linkFor(t, "other", "10.99.0.0/31", "10.99.0.1/31")
	other.ID = domain.LinkID("lnk_cccccccccccccccccccccccccccccccc")
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: other, OwnedResources: []domain.ResourceClaim{quicClaim(domain.ResourceUDPListenPort, "52211")}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	probe := &quicVacancyProbe{}
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, probe); stlerr.CodeOf(err) != stlerr.CodeConflict || probe.calls != 0 {
		t.Fatalf("other Link UDP claim ignored: %v", err)
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error { s.Delete(other.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	// Hold the exact UDP lock so the contender must refresh State after
	// waiting, not reuse a stale snapshot taken before the lock.
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{quicClaim(domain.ResourceUDPListenPort, "51821")})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	defer once.Do(func() { _ = release() })
	result := make(chan error, 1)
	go func() { _, err := e.CheckQUICPreparation(ctx, plan, provider, &quicVacancyProbe{}); result <- err }()
	select {
	case err := <-result:
		t.Fatalf("admission bypassed held resource lock: %v", err)
	case <-time.After(35 * time.Millisecond):
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: other, OwnedResources: []domain.ResourceClaim{quicClaim(domain.ResourceUDPListenPort, "51821")}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { _ = release() })
	select {
	case err := <-result:
		if stlerr.CodeOf(err) != stlerr.CodeConflict {
			t.Fatalf("did not refresh State after lock wait: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC lock admission deadlocked")
	}
}

func TestQUICAdmissionProtectsSharedIPsecUDPWithoutPerLinkClaims(t *testing.T) {
	ctx := context.Background()
	e, store := newEngine(t, newFakeBackend())
	plan, provider := quicReadinessFixture()
	plan.Role = composition.Listen
	plan.LocalHelperUDPPort = 4500
	plan.RemoteWGUDPPort = 0
	plan.LocalWGUDPPort = provider.WireGuard.ListenPort
	ipsecLink := stagedIPsecLink("lnk_dddddddddddddddddddddddddddddddd", "10.98.20.0/31")
	profile, err := ipsec.NewProfile(ipsecLink)
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range profile.ResourceClaims() {
		if claim.Kind == domain.ResourceUDPListenPort {
			t.Fatal("IPsec test accidentally has per-Link UDP claims")
		}
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: ipsecLink, OwnedResources: profile.ResourceClaims()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	probe := &quicVacancyProbe{}
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, probe); stlerr.CodeOf(err) != stlerr.CodeConflict || probe.calls != 0 {
		t.Fatalf("shared strongSwan 4500 incorrectly declared vacant: %v", err)
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Delete(ipsecLink.ID)
		s.PendingIPsec = append(s.PendingIPsec, state.PendingIPsec{Link: ipsecLink, Origin: "recipient"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	probe.calls = 0
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, probe); stlerr.CodeOf(err) != stlerr.CodeConflict || probe.calls != 0 {
		t.Fatalf("pending IPsec 4500 reservation ignored: %v", err)
	}
	// A separate QUIC port remains eligible even with other active IPsec
	// Links. Do not impose an artificial one-Carrier-per-host limitation.
	plan.LocalHelperUDPPort = 54433
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, probe); err != nil {
		t.Fatalf("non-overlapping QUIC wrongly blocked: %v", err)
	}
}

func TestQUICAdmissionFailsClosedOnOccupiedAndUnknownHost(t *testing.T) {
	ctx := context.Background()
	e, _ := newEngine(t, newFakeBackend())
	plan, provider := quicReadinessFixture()
	occupied := &quicVacancyProbe{occupied: true}
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, occupied); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("occupied live host accepted: %v", err)
	}
	probe := &quicVacancyProbe{err: errors.New("private diagnostic token=not-to-print")}
	if _, err := e.CheckQUICPreparation(ctx, plan, provider, probe); err == nil || strings.Contains(err.Error(), "not-to-print") {
		t.Fatalf("unknown host inventory accepted or leaked private evidence: %v", err)
	}
}
