//go:build stl_e2e_lab

package linux

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// These pure State/nft regression fixtures use the existing tagged source
// seam with the ACTUAL current proc Boot ID. They neither change namespaces
// nor claim physical-host provenance, a reboot, or real firewall effects.
type managedSiblingFixture struct {
	snapshot        state.Snapshot
	wss             WSSWGIngressPlan
	quic            QUICWGIngressPlan
	wssRaw, quicRaw string
}

func newManagedSiblingFixture(t *testing.T) managedSiblingFixture {
	t.Helper()
	rawBoot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	boot := strings.TrimSpace(string(rawBoot))
	if !hostidentity.ValidBootID(boot) {
		t.Fatal("actual proc Boot ID is invalid")
	}
	ns, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	oldSource := managedNamespaceLabBootSource
	managedNamespaceLabBootSource = func() (string, error) { return boot, nil }
	t.Cleanup(func() { managedNamespaceLabBootSource = oldSource })
	w, q, _, _ := testWGCoexistenceGuards(t)
	link := func(id domain.LinkID, kind domain.Backend, port uint16, network string, localByte byte) domain.Link {
		local := netip.MustParsePrefix(network)
		l := domain.Link{ID: id, DisplayName: "mixed-guard", Backend: kind, Encapsulation: domain.EncapUDP,
			Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.60")},
			Addresses: domain.LinkAddresses{Local: local, Peer: netip.PrefixFrom(local.Addr().Next(), local.Bits())},
			WireGuard: domain.WireGuardOptions{LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{localByte}, 32)), PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{localByte + 1}, 32)), ListenPort: port, PeerPort: 51990}}
		if kind == domain.BackendWireGuardWSS {
			l.WSS = domain.WSSOptions{Role: "listen", TCPPort: 443}
		} else {
			l.QUIC = domain.QUICOptions{Role: "listen", UDPPort: 443}
		}
		if err := l.Validate(); err != nil {
			t.Fatal(err)
		}
		return l
	}
	wl := link(w.LinkID, domain.BackendWireGuardWSS, w.ListenPort, "10.96.40.0/31", 0x31)
	ql := link(q.LinkID, domain.BackendWireGuardQUIC, q.ListenPort, "10.96.41.0/31", 0x41)
	claims := func(l domain.Link) []domain.ResourceClaim {
		provider, err := composition.WireGuardProviderClaims(l.ID, l.Addresses.Local, l.WireGuard)
		if err != nil {
			t.Fatal(err)
		}
		path, err := composition.Build(l, composition.CarrierForLink(l))
		if err != nil {
			t.Fatal(err)
		}
		// The existing WSS backend adds its ingress guard to the native
		// provider's desiredResources. WSS CarrierClaims deliberately contains
		// only helper/TLS/listener claims; QUIC includes its guard there.
		if l.Backend == domain.BackendWireGuardWSS {
			provider = append(provider, domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: "wss/nft/" + string(l.ID)})
		}
		return append(provider, path.CarrierClaims()...)
	}
	digest := strings.Repeat("a", 64)
	wr := state.LinkRecord{Desired: wl, OwnedResources: claims(wl), WSSOrigin: w.OriginalNonce,
		WSSFiles:        state.WSSFileIdentity{Certificate: digest, TLSKey: digest, TrustCA: digest, Authorization: digest, Restrictions: digest},
		WSSKernelBootID: boot, WSSKernelBootSource: hostidentity.VerifiedHostBootSourceV1}
	qr := state.LinkRecord{Desired: ql, OwnedResources: claims(ql), QUICGeneration: state.QUICGeneration{Version: 1, OriginNonce: q.OriginalNonce, MaterialNonce: q.OriginalNonce,
		KernelBootID: boot, KernelBootSource: hostidentity.VerifiedHostBootSourceV1, NetworkNS: ns, WGIfIndex: 101, GuardTableHandle: 1, GuardChainHandle: 1, GuardRuleHandle: 2,
		Files:          state.QUICFileIdentity{Certificate: digest, TLSKey: digest, TrustCA: digest, Authorization: digest, HelperConfig: digest, DirectoryDevice: 1, DirectoryInode: 2, ReceiptDevice: 1, ReceiptInode: 3},
		ExecutablePath: "/usr/local/libexec/stl/hysteria", ExecutableSHA256: digest, ExecutableDevice: 1, ExecutableInode: 4}}
	// Validate the positive baseline through canonical State, so rejection of
	// a negative case cannot be attributed to an already invalid Link fixture.
	store := state.NewFileStore(t.TempDir())
	if err := store.Update(context.Background(), func(s *state.Snapshot) error { s.Upsert(wr); s.Upsert(qr); return nil }); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range snapshot.Links {
		family := "wss"
		if r.Desired.Backend == domain.BackendWireGuardQUIC {
			family = "quic"
		}
		if err := RequireOwned(r.Desired.ID, domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: family + "/nft/" + string(r.Desired.ID)}, r.OwnedResources); err != nil {
			t.Fatalf("positive committed guard fixture is incomplete: %v", err)
		}
	}
	return managedSiblingFixture{snapshot: snapshot, wss: w, quic: q, wssRaw: wgIngressSnapshot(t, w.spec()), quicRaw: wgIngressSnapshot(t, q.spec())}
}

type managedSiblingRunner struct {
	quicCoexistenceRunner
	tables    map[string][]byte
	census    []byte
	commands  []string
	unbounded int
}

func newManagedSiblingRunner(t *testing.T, raws ...string) *managedSiblingRunner {
	t.Helper()
	r := &managedSiblingRunner{tables: map[string][]byte{}}
	var inventory wssNFTDump
	for _, raw := range raws {
		var dump wssNFTDump
		if err := json.Unmarshal([]byte(raw), &dump); err != nil {
			t.Fatal(err)
		}
		for _, entry := range dump.Nftables {
			if entry["metainfo"] != nil && len(inventory.Nftables) == 0 {
				inventory.Nftables = append(inventory.Nftables, entry)
			}
			if item := entry["table"]; item != nil {
				var table wssNFTTable
				if err := json.Unmarshal(item, &table); err != nil {
					t.Fatal(err)
				}
				if _, exists := r.tables[table.Name]; exists {
					t.Fatal("duplicate table in fixture")
				}
				r.tables[table.Name] = []byte(raw)
				inventory.Nftables = append(inventory.Nftables, entry)
			}
		}
	}
	var err error
	r.census, err = json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	r.nft = []byte(combineWGIngressSnapshots(t, raws...))
	return r
}

func (r *managedSiblingRunner) Run(context.Context, string, ...string) (CommandResult, error) {
	r.unbounded++
	return CommandResult{}, fmt.Errorf("unexpected unbounded sibling host query")
}
func (r *managedSiblingRunner) RunBounded(ctx context.Context, limits CaptureLimits, name string, args ...string) (CommandResult, error) {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	if limits.Stdout <= 0 || limits.Stderr <= 0 {
		return CommandResult{}, fmt.Errorf("unbounded sibling capture")
	}
	if name == "nft" && reflect.DeepEqual(args, []string{"-j", "list", "tables"}) {
		return CommandResult{Stdout: r.census}, nil
	}
	if name == "nft" && len(args) == 5 && reflect.DeepEqual(args[:4], []string{"-j", "list", "table", "inet"}) {
		raw, ok := r.tables[args[4]]
		if !ok {
			return CommandResult{}, fmt.Errorf("exact table absent")
		}
		return CommandResult{Stdout: raw}, nil
	}
	return r.quicCoexistenceRunner.RunBounded(ctx, limits, name, args...)
}

func assertManagedSiblingReadOnly(t *testing.T, r *managedSiblingRunner) {
	t.Helper()
	if r.unbounded != 0 {
		t.Fatal("shared sibling reader used an unbounded query")
	}
	for _, command := range r.commands {
		if strings.HasPrefix(command, "nft -j list table") || command == "nft -j list ruleset" || command == "iptables -V" || command == "ip6tables -V" || command == "iptables-legacy-save" || command == "ip6tables-legacy-save" {
			continue
		}
		t.Fatalf("unexpected sibling command: %s", command)
	}
}

func TestManagedWGIngressSiblingsAdmitBothCommittedCarrierOrderings(t *testing.T) {
	f := newManagedSiblingFixture(t)
	for _, kind := range []domain.Backend{domain.BackendWireGuardQUIC, domain.BackendWireGuardWSS} {
		t.Run(string(kind), func(t *testing.T) {
			snapshot := state.EmptySnapshot()
			target := f.quic.LinkID
			raw := f.wssRaw
			if kind == domain.BackendWireGuardWSS {
				target, raw = f.wss.LinkID, f.quicRaw
			}
			for _, r := range f.snapshot.Links {
				if r.Desired.ID != target {
					snapshot.Upsert(r)
				}
			}
			runner := newManagedSiblingRunner(t, raw)
			before := append([]state.LinkRecord(nil), snapshot.Links...)
			ws, qs, err := VerifiedManagedWGIngressSiblings(context.Background(), runner, snapshot, target)
			if err != nil {
				t.Fatal(err)
			}
			if kind == domain.BackendWireGuardQUIC {
				if !reflect.DeepEqual(ws, []WSSWGIngressPlan{f.wss}) || len(qs) != 0 {
					t.Fatal("new QUIC lost the independently committed WSS sibling")
				}
				err = f.quic.ProbeQUICWGFirewallCoexistenceWithVerifiedCurrent(context.Background(), runner, ws, qs, false)
			} else {
				if len(ws) != 0 || !reflect.DeepEqual(qs, []QUICWGIngressPlan{f.quic}) {
					t.Fatal("new WSS lost the independently committed QUIC sibling")
				}
				err = f.wss.ProbeWSSWGFirewallCoexistenceWithVerifiedCurrent(context.Background(), runner, ws, qs, false)
			}
			if err != nil {
				t.Fatalf("shared reader did not support actual opposite-family preflight: %v", err)
			}
			if !reflect.DeepEqual(before, snapshot.Links) {
				t.Fatal("read-only sibling reader altered protected State")
			}
			assertManagedSiblingReadOnly(t, runner)
		})
	}
	// With both families already committed, each target excludes only itself
	// and separately passes its exact current-guard observation to preflight.
	for _, target := range []domain.LinkID{f.wss.LinkID, f.quic.LinkID} {
		runner := newManagedSiblingRunner(t, f.wssRaw, f.quicRaw)
		ws, qs, err := VerifiedManagedWGIngressSiblings(context.Background(), runner, f.snapshot, target)
		if err != nil {
			t.Fatal(err)
		}
		if target == f.wss.LinkID {
			if len(ws) != 0 || !reflect.DeepEqual(qs, []QUICWGIngressPlan{f.quic}) {
				t.Fatal("WSS current target excluded another family")
			}
			err = f.wss.ProbeWSSWGFirewallCoexistenceWithVerifiedCurrent(context.Background(), runner, ws, qs, true)
		} else {
			if len(qs) != 0 || !reflect.DeepEqual(ws, []WSSWGIngressPlan{f.wss}) {
				t.Fatal("QUIC current target excluded another family")
			}
			err = f.quic.ProbeQUICWGFirewallCoexistenceWithVerifiedCurrent(context.Background(), runner, ws, qs, true)
		}
		if err != nil {
			t.Fatalf("exact current target and opposite-family sibling rejected: %v", err)
		}
		assertManagedSiblingReadOnly(t, runner)
	}
}

func TestManagedWGIngressSiblingsRequireExactQUICGenerationAndClaims(t *testing.T) {
	for _, failure := range []string{"boot", "boot-source", "namespace", "origin-nonce", "table-handle", "chain-handle", "rule-handle", "missing-claim", "foreign-claim", "untrusted-current-boot"} {
		t.Run(failure, func(t *testing.T) {
			f := newManagedSiblingFixture(t)
			r, ok := f.snapshot.Find(f.quic.LinkID)
			if !ok {
				t.Fatal("missing fixture")
			}
			switch failure {
			case "boot":
				before := r.QUICGeneration.KernelBootID
				r.QUICGeneration.KernelBootID = "11111111-1111-4111-8111-111111111111"
				if r.QUICGeneration.KernelBootID == before {
					r.QUICGeneration.KernelBootID = "22222222-2222-4222-8222-222222222222"
				}
			case "boot-source":
				r.QUICGeneration.KernelBootSource = "namespace-observation"
			case "namespace":
				before := r.QUICGeneration.NetworkNS
				r.QUICGeneration.NetworkNS = "net:[1]"
				if before == r.QUICGeneration.NetworkNS {
					r.QUICGeneration.NetworkNS = "net:[2]"
				}
			case "origin-nonce":
				r.QUICGeneration.OriginNonce = strings.Repeat("f", 32)
			case "table-handle":
				r.QUICGeneration.GuardTableHandle++
			case "chain-handle":
				r.QUICGeneration.GuardChainHandle++
			case "rule-handle":
				r.QUICGeneration.GuardRuleHandle++
			case "missing-claim", "foreign-claim":
				var claims []domain.ResourceClaim
				for _, c := range r.OwnedResources {
					if c.Kind == domain.ResourceFirewall {
						if failure == "foreign-claim" {
							c.Key = "quic/nft/" + string(f.wss.LinkID)
							claims = append(claims, c)
						}
						continue
					}
					claims = append(claims, c)
				}
				r.OwnedResources = claims
			case "untrusted-current-boot":
				managedNamespaceLabBootSource = func() (string, error) { return "", fmt.Errorf("untrusted current host") }
			}
			f.snapshot.Upsert(r)
			runner := newManagedSiblingRunner(t, f.wssRaw, f.quicRaw)
			ws, qs, err := VerifiedManagedWGIngressSiblings(context.Background(), runner, f.snapshot, f.wss.LinkID)
			if err == nil || len(ws) != 0 || len(qs) != 0 {
				t.Fatal("drifted QUIC generation or unowned claim became WSS compatibility authority")
			}
			assertManagedSiblingReadOnly(t, runner)
		})
	}
}

func TestManagedWGIngressSiblingsRejectForeignOrMutatedGuardShapes(t *testing.T) {
	for _, carrier := range []string{"wss", "quic"} {
		for _, failure := range []string{"accept-verdict", "wrong-port", "wrong-nonce"} {
			t.Run(carrier+"/"+failure, func(t *testing.T) {
				f := newManagedSiblingFixture(t)
				raw, spec := f.wssRaw, f.wss.spec()
				if carrier == "quic" {
					raw, spec = f.quicRaw, f.quic.spec()
				}
				switch failure {
				case "accept-verdict":
					raw = string(mutateWGIngressDropVerdict(t, []byte(raw), spec))
				case "wrong-port":
					raw = strings.Replace(raw, fmt.Sprintf(`"right":%d`, spec.listenPort), `"right":59999`, 1)
				case "wrong-nonce":
					raw = strings.Replace(raw, spec.ruleComment(), strings.Replace(spec.ruleComment(), quicTestNonce, strings.Repeat("f", 32), 1), 1)
				}
				if !json.Valid([]byte(raw)) || spec.VerifyNFTJSON([]byte(raw)) == nil {
					t.Fatal("negative guard fixture was not a valid-JSON shape mutation")
				}
				if carrier == "wss" {
					f.wssRaw = raw
				} else {
					f.quicRaw = raw
				}
				runner := newManagedSiblingRunner(t, f.wssRaw, f.quicRaw)
				ws, qs, err := VerifiedManagedWGIngressSiblings(context.Background(), runner, f.snapshot, "lnk_dddddddddddddddddddddddddddddddd")
				if err == nil || len(ws) != 0 || len(qs) != 0 {
					t.Fatal("foreign or changed DROP-only sibling was excluded from host policy")
				}
				assertManagedSiblingReadOnly(t, runner)
			})
		}
	}
}

func TestManagedWGIngressSiblingsNeverPromoteSourceOnlyQUICJournal(t *testing.T) {
	f := newManagedSiblingFixture(t)
	saved, ok := f.snapshot.Find(f.quic.LinkID)
	if !ok {
		t.Fatal("missing fixture")
	}
	host, err := composition.QUICHostPlanForLink(saved.Desired)
	if err != nil {
		t.Fatal(err)
	}
	g := saved.QUICGeneration
	op := state.QUICCrashOperation{Plan: host, Addresses: saved.Desired.Addresses, WireGuard: saved.Desired.WireGuard, Nonce: g.OriginNonce, Resources: saved.OwnedResources,
		CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization, HelperConfigSHA256: g.Files.HelperConfig,
		ExecutablePath: g.ExecutablePath, ExecutableSHA256: g.ExecutableSHA256, ExecutableDevice: g.ExecutableDevice, ExecutableInode: g.ExecutableInode}
	if err := op.Validate(); err != nil {
		t.Fatalf("source-only fixture must be fully valid: %v", err)
	}
	f.snapshot.Delete(f.quic.LinkID)
	f.snapshot.QUICCrashOperations = []state.QUICCrashOperation{op}
	newWSS, err := NewWSSWGIngressPlan("lnk_cccccccccccccccccccccccccccccccc", 51833)
	if err != nil {
		t.Fatal(err)
	}
	newWSS.OriginalNonce = quicTestNonce
	runner := newManagedSiblingRunner(t, f.wssRaw, f.quicRaw)
	ws, qs, err := VerifiedManagedWGIngressSiblings(context.Background(), runner, f.snapshot, newWSS.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ws, []WSSWGIngressPlan{f.wss}) || len(qs) != 0 {
		t.Fatal("source-only journal became a managed sibling attestation")
	}
	if err := newWSS.ProbeWSSWGFirewallCoexistenceWithVerifiedCurrent(context.Background(), runner, ws, qs, false); err == nil {
		t.Fatal("unattested source-only QUIC guard ceased blocking WSS preflight")
	}
	if f.snapshot.QUICCrashOperations[0].Managed != nil {
		t.Fatal("observational sibling check promoted source-only State")
	}
	assertManagedSiblingReadOnly(t, runner)
}
