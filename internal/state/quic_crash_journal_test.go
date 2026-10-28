package state

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func quicCrashFixture(t *testing.T) QUICCrashOperation {
	t.Helper()
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	wg := domain.WireGuardOptions{
		LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32)),
		PeerPublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x36}, 32)),
		ListenPort:     51821, PeerPort: 52211,
	}
	local := composition.QUICLocalAdmission{LinkID: id, Role: composition.Dial,
		LocalWGUDPPort: 51821, LocalHelperUDPPort: 52211, RemoteWGUDPPort: 51820}
	provider, err := composition.WireGuardProviderClaims(id, netip.MustParsePrefix("10.96.20.0/31"), wg)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := local.CarrierClaims()
	if err != nil {
		t.Fatal(err)
	}
	claims := make(map[string]domain.ResourceClaim)
	for _, c := range append(provider, carrier...) {
		claims[c.Canonical()] = c
	}
	all := make([]domain.ResourceClaim, 0, len(claims))
	for _, c := range claims {
		all = append(all, c)
	}
	return QUICCrashOperation{
		Plan:      composition.QUICHostPlan{Local: local, Physical: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60"},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.96.20.0/31"), Peer: netip.MustParsePrefix("10.96.20.1/31")},
		WireGuard: wg, Nonce: strings.Repeat("a", 32), Resources: all,
		CertificateSHA256: strings.Repeat("a", 64), TrustCASHA256: strings.Repeat("b", 64),
		AuthorizationSHA256: strings.Repeat("c", 64), HelperConfigSHA256: strings.Repeat("d", 64),
		ExecutablePath: "/usr/local/libexec/stl/hysteria", ExecutableSHA256: strings.Repeat("e", 64),
		ExecutableDevice: 1, ExecutableInode: 2,
	}
}

func TestQUICCrashJournalDurableRoundTripAndImmutableQuarantine(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := NewFileStore(root)
	op := quicCrashFixture(t)
	if err := op.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, func(s *Snapshot) error {
		s.QUICCrashOperations = append(s.QUICCrashOperations, op)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first, err := NewFileStore(root).Load(ctx) // real-disk restart recovery
	if err != nil {
		t.Fatal(err)
	}
	found, ok := first.FindQUICCrashOperation(op.Plan.Local.LinkID)
	if !ok || found.Nonce != op.Nonce || found.HelperConfigSHA256 != op.HelperConfigSHA256 ||
		found.Plan != op.Plan || len(first.Links) != 0 {
		t.Fatalf("QUIC journal missing/mutated across restart: %+v", found)
	}
	mode, err := os.Stat(filepath.Join(root, "state.json"))
	if err != nil || mode.Mode().Perm() != 0o600 {
		t.Fatalf("journal not in existing private State store: %v, %v", mode, err)
	}
	baseline, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name string
		fn   func(*Snapshot)
	}{
		{"remove", func(s *Snapshot) { s.QUICCrashOperations = nil }},
		{"change-TLS", func(s *Snapshot) { s.QUICCrashOperations[0].Plan.TLSName = "server.example" }},
		{"change-expected-fingerprint", func(s *Snapshot) { s.QUICCrashOperations[0].HelperConfigSHA256 = strings.Repeat("f", 64) }},
		{"change-claims-in-place", func(s *Snapshot) { s.QUICCrashOperations[0].Resources[0].Key += "x" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			if err := store.Update(ctx, func(s *Snapshot) error { mutate.fn(s); return nil }); err == nil {
				t.Fatal("quarantined journal was mutable")
			}
			after, err := os.ReadFile(filepath.Join(root, "state.json"))
			if err != nil || !bytes.Equal(baseline, after) {
				t.Fatalf("failed operation changed durable State: %v", err)
			}
		})
	}
	if _, err := NewFileStore(root).Load(ctx); err != nil {
		t.Fatalf("failed mutation invalidated journal: %v", err)
	}
}

func TestQUICCrashJournalRejectsIncompleteOrForgedState(t *testing.T) {
	original := quicCrashFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*QUICCrashOperation)
	}{
		{"removed-udp-claim", func(op *QUICCrashOperation) { op.Resources = op.Resources[:len(op.Resources)-1] }},
		{"duplicated-claim", func(op *QUICCrashOperation) { op.Resources = append(op.Resources, op.Resources[0]) }},
		{"extra-foreign-claim", func(op *QUICCrashOperation) {
			op.Resources = append(op.Resources, domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: "44444"})
		}},
		{"missing-nonce", func(op *QUICCrashOperation) { op.Nonce = "" }},
		{"malformed-fingerprint", func(op *QUICCrashOperation) { op.HelperConfigSHA256 = strings.Repeat("F", 64) }},
		{"missing-inode", func(op *QUICCrashOperation) { op.ExecutableInode = 0 }},
		{"path-replacement", func(op *QUICCrashOperation) { op.ExecutablePath = "/usr/local/../tmp/hysteria" }},
		{"reserved-local-route", func(op *QUICCrashOperation) { op.Addresses.Local = netip.MustParsePrefix("127.0.0.2/32") }},
		{"reserved-peer-route", func(op *QUICCrashOperation) { op.Addresses.Peer = netip.MustParsePrefix("126.0.0.2/7") }},
		{"physical-private-route", func(op *QUICCrashOperation) {
			op.Plan.Physical = netip.MustParseAddrPort("10.96.20.1:443")
			op.Plan.TLSName = "10.96.20.1"
		}},
		{"bad-physical-TLS-SAN", func(op *QUICCrashOperation) { op.Plan.TLSName = "198.51.100.61" }},
		{"bad-peer-forward-port", func(op *QUICCrashOperation) { op.WireGuard.PeerPort = 51820 }},
		{"bad-role-ports", func(op *QUICCrashOperation) { op.Plan.Local.Role = composition.Listen }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := original
			v.Resources = append([]domain.ResourceClaim(nil), original.Resources...)
			tc.mutate(&v)
			if err := v.Validate(); err == nil {
				t.Fatal("forged QUIC public identity accepted")
			}
		})
	}
}

func TestQUICCrashJournalReservesAcrossLinksAndSurvivesPublicationUncertainty(t *testing.T) {
	ctx := context.Background()
	store := NewFileStore(t.TempDir())
	op := quicCrashFixture(t)
	store.afterPublish = func() error { return errors.New("post-rename fsync unavailable") }
	err := store.Update(ctx, func(s *Snapshot) error {
		s.QUICCrashOperations = append(s.QUICCrashOperations, op)
		return nil
	})
	var uncertain *PublicationError
	if !errors.As(err, &uncertain) {
		t.Fatalf("missing publication ambiguity: %v", err)
	}
	loaded, err := NewFileStore(store.root).Load(ctx)
	if err != nil || len(loaded.QUICCrashOperations) != 1 {
		t.Fatalf("journal lost after state fsync failure: %v %+v", err, loaded)
	}
	if err := NewFileStore(store.root).Update(ctx, func(s *Snapshot) error {
		s.QUICCrashOperations = nil
		return nil
	}); err == nil {
		t.Fatal("ambiguous on-disk journal was cleared")
	}
	// A second, independent source-only pending intent can coexist with the
	// same physical peer when every local resource identity is distinct.
	other := quicCrashFixture(t)
	other.Plan.Local.LinkID = domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	other.Plan.Local.LocalWGUDPPort = 51822
	other.Plan.Local.LocalHelperUDPPort = 52212
	other.Addresses.Local = netip.MustParsePrefix("10.96.21.0/31")
	other.Addresses.Peer = netip.MustParsePrefix("10.96.21.1/31")
	other.WireGuard.ListenPort, other.WireGuard.PeerPort = 51822, 52212
	other.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x29}, 32))
	provider, _ := composition.WireGuardProviderClaims(other.Plan.Local.LinkID, other.Addresses.Local, other.WireGuard)
	carrier, _ := other.Plan.Local.CarrierClaims()
	byCanonical := make(map[string]domain.ResourceClaim)
	for _, c := range append(provider, carrier...) {
		byCanonical[c.Canonical()] = c
	}
	other.Resources = nil
	for _, c := range byCanonical {
		other.Resources = append(other.Resources, c)
	}
	if err := other.Validate(); err != nil {
		t.Fatal(err)
	}
	freshStore := NewFileStore(store.root)
	if err := freshStore.Update(ctx, func(s *Snapshot) error {
		s.QUICCrashOperations = append(s.QUICCrashOperations, other)
		return nil
	}); err != nil {
		t.Fatalf("independent same-peer QUIC intents cannot coexist: %v", err)
	}
	found, err := freshStore.Load(ctx)
	if err != nil || len(found.QUICCrashOperations) != 2 {
		t.Fatalf("multi-Link state lost: %v %+v", err, found)
	}
	collision := other
	collision.Plan.Local.LinkID = domain.LinkID("lnk_cccccccccccccccccccccccccccccccc")
	// Re-derive *valid* canonical claims for this new Link identity. The
	// failure must be a genuine cross-Link port/subnet collision, not a
	// malformed claim/identity fixture.
	collision.Resources = exactQUICCrashClaims(t, collision)
	if err := collision.Validate(); err != nil {
		t.Fatalf("collision fixture was not itself a valid intent: %v", err)
	}
	if err := freshStore.Update(ctx, func(s *Snapshot) error {
		s.QUICCrashOperations = append(s.QUICCrashOperations, collision)
		return nil
	}); err == nil {
		t.Fatal("two QUIC intents adopted same local ports/subnet")
	}
}

func TestQUICCrashJournalRejectsLegacySchemaGraft(t *testing.T) {
	op := quicCrashFixture(t)
	for _, version := range []int{1, 2, 3} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			root := t.TempDir()
			raw, err := json.Marshal(Snapshot{SchemaVersion: version, Links: []LinkRecord{}, QUICCrashOperations: []QUICCrashOperation{op}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(root).Load(context.Background()); err == nil {
				t.Fatal("legacy schema was allowed to claim new QUIC journal semantics")
			}
		})
	}
}

func TestQUICCrashJournalLoadRejectsTamperedProtectedState(t *testing.T) {
	op := quicCrashFixture(t)
	raw, err := json.Marshal(Snapshot{SchemaVersion: SchemaVersion, Links: []LinkRecord{}, QUICCrashOperations: []QUICCrashOperation{op}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	arr := doc["quic_crash_operations"].([]any)
	current := arr[0].(map[string]any)
	current["helper_config_sha256"] = "bad"
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "state.json"), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(root).Load(context.Background()); err == nil {
		t.Fatal("malformed persisted journal was treated as free resources")
	}
}

func TestQUICCrashJournalRejectsMixedPendingAndSharedIPsecReservations(t *testing.T) {
	ctx := context.Background()
	initial := quicCrashFixture(t)
	for _, tc := range []struct {
		name   string
		want   string
		mutate func(*Snapshot, *QUICCrashOperation)
	}{
		{"pending-native-WG-subnet", "pending WireGuard sender", func(s *Snapshot, _ *QUICCrashOperation) {
			pending := testLink(t, domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "10.96.20.0/31", "10.96.20.1/31")
			pending.Backend, pending.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
			pending.WireGuard = quicCrashFixture(t).WireGuard
			pending.WireGuard.ListenPort, pending.WireGuard.PeerPort = 52600, 52601
			s.PendingSenders = append(s.PendingSenders, PendingSender{Link: pending, HandoffSHA256: strings.Repeat("a", 64)})
		}},
		{"pending-IPsec-subnet", "pending IPsec Link Address", func(s *Snapshot, _ *QUICCrashOperation) {
			pending := pendingIPsecFixture()
			pending.Link.Addresses.Local = netip.MustParsePrefix("10.96.20.0/31")
			pending.Link.Addresses.Peer = netip.MustParsePrefix("10.96.20.1/31")
			s.PendingIPsec = append(s.PendingIPsec, pending)
		}},
		{"shared-IPsec-500", "strongSwan daemon", func(s *Snapshot, op *QUICCrashOperation) {
			pending := pendingIPsecFixture()
			s.PendingIPsec = append(s.PendingIPsec, pending)
			op.Plan.Local.LocalHelperUDPPort = 500
			op.WireGuard.PeerPort = 500
			op.Resources = exactQUICCrashClaims(t, *op)
		}},
		{"committed-IPsec-4500", "strongSwan daemon", func(s *Snapshot, op *QUICCrashOperation) {
			ipsec := pendingIPsecFixture().Link
			s.Links = append(s.Links, LinkRecord{Desired: ipsec})
			op.Plan.Local.LocalHelperUDPPort = 4500
			op.WireGuard.PeerPort = 4500
			op.Resources = exactQUICCrashClaims(t, *op)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewFileStore(t.TempDir())
			op := initial
			op.Resources = append([]domain.ResourceClaim(nil), initial.Resources...)
			err := store.Update(ctx, func(s *Snapshot) error {
				tc.mutate(s, &op)
				if err := op.Validate(); err != nil {
					t.Fatalf("test provided invalid standalone QUIC intent: %v", err)
				}
				s.QUICCrashOperations = append(s.QUICCrashOperations, op)
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong cross-reservation rejection (wanted %q): %v", tc.want, err)
			}
			got, err := store.Load(ctx)
			if err != nil || len(got.QUICCrashOperations) != 0 || len(got.Links) != 0 {
				t.Fatalf("rejected mixed State was still published: %+v %v", got, err)
			}
		})
	}
}

func exactQUICCrashClaims(t *testing.T, op QUICCrashOperation) []domain.ResourceClaim {
	t.Helper()
	provider, err := composition.WireGuardProviderClaims(op.Plan.Local.LinkID, op.Addresses.Local, op.WireGuard)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := op.Plan.Local.CarrierClaims()
	if err != nil {
		t.Fatal(err)
	}
	byCanonical := make(map[string]domain.ResourceClaim)
	for _, claim := range append(provider, carrier...) {
		byCanonical[claim.Canonical()] = claim
	}
	all := make([]domain.ResourceClaim, 0, len(byCanonical))
	for _, claim := range byCanonical {
		all = append(all, claim)
	}
	return all
}
