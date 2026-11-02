package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	l2tp "github.com/ach1992/simple-tun-link/internal/backend/l2tpv3"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Override only the native L2TP preflight for this test. The shared GRE
// fixture must still be able to simulate a missing L2TP kernel.
type guidedL2TPv3Runner struct{ *guidedTestRunner }

func (r *guidedL2TPv3Runner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	command := name + " " + strings.Join(args, " ")
	if command == "ip -json l2tp show tunnel" || command == "ip -json l2tp show session" {
		r.calls = append(r.calls, command)
		return linux.CommandResult{Stdout: []byte("[]")}, nil
	}
	return r.guidedTestRunner.Run(ctx, name, args...)
}

type guidedL2TPv3Backend struct{ *lifecycleFakeBackend }

func (*guidedL2TPv3Backend) Kind() domain.Backend { return domain.BackendL2TPv3 }
func (b *guidedL2TPv3Backend) DiagnosticState(_ context.Context, link domain.Link) (l2tp.DiagnosticState, error) {
	if !b.present[link.ID] {
		return l2tp.DiagnosticState{}, context.Canceled
	}
	name, _ := l2tp.InterfaceName(link.ID)
	return l2tp.DiagnosticState{Interface: name, IfIndex: 17, Encapsulation: domain.EncapNative}, nil
}

// The guided operator route must not bypass the Engine, renumber existing
// transport choices or disclose any secrets in the plaintext Setup Link.
func TestGuidedL2TPv3Option8CreateAndPairing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	host := &guidedL2TPv3Runner{guidedTestRunner: &guidedTestRunner{}}
	fake := &guidedL2TPv3Backend{lifecycleFakeBackend: newLifecycleFake()}
	opts := &runtimeOptions{
		stateRoot: root, probeRunner: host, backends: []backend.Backend{fake},
		packagePreview: readyGuidedPackagePreview,
		moduleObserve:  func(context.Context, string) linux.KernelModuleState { return linux.KernelModuleLoaded },
		mtuManager:     guidedMTUFake{},
		createLinkID:   func() (domain.LinkID, error) { return createTestID, nil },
	}
	for number, expected := range map[string]domain.Backend{
		"1": domain.BackendGRE, "2": domain.BackendWireGuard,
		"3": domain.BackendIPIP, "8": domain.BackendL2TPv3,
	} {
		if got := basicTunnelOptions[number]; got.backend != expected {
			t.Fatalf("operator choice %s was renumbered: %v", number, got)
		}
	}
	code, out, errorsOut := runGuidedTest(opts, "1\n8\n192.0.2.20\n\nn\nYES\nn\n8\n")
	if code != 0 || errorsOut != "" {
		t.Fatalf("option 8 Create path failed: %d output=%q err=%q", code, out, errorsOut)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 {
		t.Fatalf("L2TPv3 Link was not saved: %v %+v\nMENU=%s", err, saved, out)
	}
	link := saved.Links[0].Desired
	if link.Backend != domain.BackendL2TPv3 || link.Encapsulation != domain.EncapNative ||
		link.Underlay.Local != netip.MustParseAddr("192.0.2.10") ||
		link.Underlay.Peer != netip.MustParseAddr("192.0.2.20") ||
		len(fake.applies) != 1 || fake.applies[0] != createTestID {
		t.Fatalf("option 8 did not create L2TPv3 through Engine: %+v", link)
	}
	setup := regexp.MustCompile("stl://[^[:space:]]+").FindString(out)
	offer, err := pairing.DecodeSetupLink(setup)
	if err != nil || offer.ReceiverLink().Backend != domain.BackendL2TPv3 ||
		offer.ReceiverLink().Underlay.Local != link.Underlay.Peer {
		t.Fatalf("missing canonical L2TPv3 receiver inversion: %v", err)
	}
	if !strings.Contains(out, "L2TPV3") ||
		!strings.Contains(out, "L2TPv3 Direct-IP is not encrypted or authenticated") ||
		!strings.Contains(out, "Import setup link -> 1 (GRE / IPIP / L2TPv3)") ||
		strings.Contains(out, "GRE/IPIP is unencrypted") {
		t.Fatalf("L2TPv3 operator pairing warning or receiver instruction is misleading: %q", out)
	}
	for _, cmd := range host.calls {
		if strings.Contains(cmd, "l2tp add") || strings.Contains(cmd, "iptables") {
			t.Fatalf("UI bypassed backend authority: %s", cmd)
		}
	}
}
