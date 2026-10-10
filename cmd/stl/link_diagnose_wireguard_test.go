package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type readWireGuardDiagnosticBackend struct {
	backend.Backend
	state                 wgbackend.DiagnosticState
	capability            linux.CapabilityStatus
	err                   error
	capCalls, statusCalls int
}

func (*readWireGuardDiagnosticBackend) Kind() domain.Backend { return domain.BackendWireGuard }
func (b *readWireGuardDiagnosticBackend) Capability(context.Context, domain.Link) (linux.CapabilityStatus, error) {
	b.capCalls++
	if b.err != nil {
		return linux.CapabilityStatus{}, b.err
	}
	return b.capability, nil
}
func (b *readWireGuardDiagnosticBackend) DiagnosticState(context.Context, domain.Link) (wgbackend.DiagnosticState, error) {
	b.statusCalls++
	if b.err != nil {
		return wgbackend.DiagnosticState{}, b.err
	}
	return b.state, nil
}

func fixtureWireGuardDiagnose(t *testing.T) (string, domain.Link, *readWireGuardDiagnosticBackend, *readGREProbeRunner) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_99999999999999999999999999999999", "10.83.10.0/31", "10.83.10.1/31", domain.BackendWireGuard)
	link.Encapsulation = domain.EncapUDP
	completeWireGuardFixture(t, &link, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32)))
	storeReadLinks(t, root, link)
	name, err := wgbackend.InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	inspector := &readWireGuardDiagnosticBackend{
		capability: linux.CapabilityStatus{Available: true},
		state: wgbackend.DiagnosticState{
			Interface: name, IfIndex: 77, LocalPublicKey: link.WireGuard.LocalPublicKey,
			PeerPublicKey: link.WireGuard.PeerPublicKey, ListenPort: link.WireGuard.ListenPort,
			LatestHandshakeUnix: 1700000000, RXBytes: 1234, TXBytes: 5678,
		},
	}
	return root, link, inspector, &readGREProbeRunner{link: link, name: name, observedIndex: 77}
}

func runWireGuardDiagnose(t *testing.T, root string, impl *readWireGuardDiagnosticBackend, probe linux.Runner, id domain.LinkID, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := runWithRuntime(append([]string{"link", "diagnose", string(id)}, args...), &stdout, &stderr,
		&runtimeOptions{stateRoot: root, backends: []backend.Backend{impl}, probeRunner: probe})
	return code, stdout.String(), stderr.String()
}

func TestWireGuardDiagnoseVersionedReadOnlyMeasuredResult(t *testing.T) {
	root, link, b, runner := fixtureWireGuardDiagnose(t)
	code, out, stderr := runWireGuardDiagnose(t, root, b, runner, link.ID, "--json")
	if code != 0 || stderr != "" || strings.Contains(out, "private_key") || strings.Contains(out, "DO_NOT_EXPOSE") {
		t.Fatalf("unsafe or failed WireGuard diagnosis: code=%d out=%q err=%q", code, out, stderr)
	}
	var report diagnostics.WireGuardReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.LinkID != link.ID || report.Backend != domain.BackendWireGuard ||
		report.State.RXBytes != 1234 || report.State.TXBytes != 5678 ||
		report.State.PeerPublicKey != link.WireGuard.PeerPublicKey ||
		report.State.LatestHandshakeUnix != 1700000000 || !report.MTU.Verified ||
		report.MTU.SelectedMTU != 1360 || report.MTU.CeilingMTU != 1360 ||
		!report.Quality.Reachable || report.Quality.PacketsReceived != 5 ||
		b.capCalls != 1 || b.statusCalls != 1 || runner.probes != 6 {
		t.Fatalf("incorrect WireGuard report or inspection budget: %+v cap=%d state=%d probes=%d", report, b.capCalls, b.statusCalls, runner.probes)
	}
	for _, call := range runner.commands {
		if strings.Contains(call, "iptables") || strings.Contains(call, "link set") ||
			strings.Contains(call, "route add") || strings.Contains(call, "private_key") {
			t.Fatalf("WireGuard diagnostic invoked a sensitive or mutating action: %q", call)
		}
	}

	// Manual is an explicit proposal, never claimed as PMTU-confirmed.
	root, link, b, runner = fixtureWireGuardDiagnose(t)
	code, out, _ = runWireGuardDiagnose(t, root, b, runner, link.ID, "--mtu", "1300", "--json")
	if code != 0 || strings.Contains(out, "private_key") {
		t.Fatalf("manual WireGuard diagnosis failed: %d %q", code, out)
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.MTU.SelectedMTU != 1300 ||
		report.MTU.Verified || report.MTU.Mode != "manual" {
		t.Fatalf("manual MTU was incorrectly verified: %+v, %v", report.MTU, err)
	}
	code, out, _ = runWireGuardDiagnose(t, root, b, runner, link.ID)
	if code != 0 || !strings.Contains(out, "WireGuard interface") ||
		!strings.Contains(out, "RX 1234 bytes") || !strings.Contains(out, "last observed handshake") {
		t.Fatalf("incomplete human WireGuard summary: %d %q", code, out)
	}
}

func TestWireGuardDiagnoseFailsClosedBeforeProbeOnIdentityOrCapabilityDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*readWireGuardDiagnosticBackend, *readGREProbeRunner)
	}{
		{"capability unavailable", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) { b.capability.Available = false }},
		{"backend failure secret redacted", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) {
			b.err = errors.New("private_key=DO_NOT_EXPOSE")
		}},
		{"wrong interface", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) { b.state.Interface = "not-ours" }},
		{"missing ifindex", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) { b.state.IfIndex = 0 }},
		{"wrong local key", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) {
			b.state.LocalPublicKey = b.state.PeerPublicKey
		}},
		{"wrong peer key", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) {
			b.state.PeerPublicKey = b.state.LocalPublicKey
		}},
		{"wrong listen port", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) { b.state.ListenPort++ }},
		{"invalid handshake timestamp", func(b *readWireGuardDiagnosticBackend, _ *readGREProbeRunner) { b.state.LatestHandshakeUnix = -1 }},
		{"interface recycled before probe", func(_ *readWireGuardDiagnosticBackend, p *readGREProbeRunner) { p.observedIndex = 81 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, link, b, runner := fixtureWireGuardDiagnose(t)
			tc.change(b, runner)
			code, out, stderr := runWireGuardDiagnose(t, root, b, runner, link.ID, "--json")
			if code == 0 || stderr != "" || strings.Contains(out, "private_key") || runner.probes != 0 {
				t.Fatalf("WireGuard fail-closed diagnostic violated: code=%d out=%q stderr=%q probes=%d", code, out, stderr, runner.probes)
			}
			var response linkReadErrorResponse
			if err := json.Unmarshal([]byte(out), &response); err != nil || response.SchemaVersion != 1 || response.Error == nil {
				t.Fatalf("WireGuard failure lost structured error: %q %v", out, err)
			}
		})
	}
}

func TestWireGuardDiagnoseDoesNotInventManualMTUCeiling(t *testing.T) {
	root, link, b, runner := fixtureWireGuardDiagnose(t)
	code, out, _ := runWireGuardDiagnose(t, root, b, runner, link.ID, "--mtu", "1361", "--json")
	if code == 0 || runner.probes != 0 || strings.Contains(out, "private_key") {
		t.Fatalf("invalid underlay MTU accepted: code=%d result=%q probes=%d", code, out, runner.probes)
	}
}

func TestWireGuardDiagnoseUnobservedHandshakeNotClaimed(t *testing.T) {
	root, link, b, runner := fixtureWireGuardDiagnose(t)
	b.state.LatestHandshakeUnix = 0
	code, out, _ := runWireGuardDiagnose(t, root, b, runner, link.ID)
	if code != 0 || !strings.Contains(out, "no handshake observed at pre-probe inspection") {
		t.Fatalf("unobserved WireGuard handshake was overstated: %d %q", code, out)
	}
}
