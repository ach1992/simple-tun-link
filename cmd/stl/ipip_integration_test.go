package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type readIPIPDiagnosticBackend struct {
	backend.Backend
	state      ipipbackend.DiagnosticState
	capability linux.CapabilityStatus
	err        error
}

func (*readIPIPDiagnosticBackend) Kind() domain.Backend { return domain.BackendIPIP }

func (b *readIPIPDiagnosticBackend) Capability(context.Context, domain.Link) (linux.CapabilityStatus, error) {
	if b.err != nil {
		return linux.CapabilityStatus{}, b.err
	}
	return b.capability, nil
}

func (b *readIPIPDiagnosticBackend) DiagnosticState(context.Context, domain.Link) (ipipbackend.DiagnosticState, error) {
	if b.err != nil {
		return ipipbackend.DiagnosticState{}, b.err
	}
	return b.state, nil
}

func runIPIPRead(root string, inspector backend.Backend, runner linux.Runner, args ...string) (int, string, string) {
	var output, errorsOut bytes.Buffer
	code := runWithRuntime(args, &output, &errorsOut, &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{inspector}, probeRunner: runner,
	})
	return code, output.String(), errorsOut.String()
}

func TestIPIPCLIStatusAndDiagnoseAllEncapsulations(t *testing.T) {
	for _, tc := range []struct {
		encap   domain.Encapsulation
		ceiling int
	}{
		{domain.EncapNative, 1400},
		{domain.EncapFOU, 1392},
		{domain.EncapGUE, 1388},
	} {
		t.Run(string(tc.encap), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			link := fixtureReadLink("lnk_88888888888888888888888888888888", "10.80.80.0/31", "10.80.80.1/31", domain.BackendIPIP)
			link.Encapsulation = tc.encap
			storeReadLinks(t, root, link)
			name, err := ipipbackend.InterfaceName(link.ID)
			if err != nil {
				t.Fatal(err)
			}
			inspector := &readIPIPDiagnosticBackend{
				capability: linux.CapabilityStatus{Available: true},
				state: ipipbackend.DiagnosticState{
					Interface: name, IfIndex: 77, Encapsulation: tc.encap, RXPackets: 11, TXPackets: 13,
				},
			}
			prober := &readGREProbeRunner{link: link, name: name, observedIndex: 77}

			code, out, stderr := runIPIPRead(root, inspector, prober, "link", "status", string(link.ID), "--json")
			if code != 0 || stderr != "" || strings.Contains(out, "private_key") {
				t.Fatalf("IPIP status unavailable or unsafe: %d %q %q", code, out, stderr)
			}
			var status linkStatusResponse
			if err := json.Unmarshal([]byte(out), &status); err != nil {
				t.Fatal(err)
			}
			if status.SchemaVersion != 1 || !status.InterfaceVerified || status.Connectivity != "not_measured" ||
				status.GREState != nil || status.IPIPState == nil || status.IPIPState.TXPackets != 13 ||
				status.IPIPState.Encapsulation != tc.encap {
				t.Fatalf("bad IPIP status projection: %+v", status)
			}
			code, out, stderr = runIPIPRead(root, inspector, prober, "link", "diagnose", string(link.ID), "--json")
			if code != 0 || stderr != "" || strings.Contains(out, "private_key") {
				t.Fatalf("IPIP diagnostics unavailable or unsafe: %d %q %q", code, out, stderr)
			}
			var report diagnostics.IPIPReport
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatal(err)
			}
			if report.SchemaVersion != 1 || report.Backend != domain.BackendIPIP ||
				report.State.IfIndex != 77 || report.State.Encapsulation != tc.encap ||
				report.MTU.SelectedMTU != tc.ceiling || !report.MTU.Verified ||
				!report.Quality.Reachable || report.Quality.PacketsReceived != 5 {
				t.Fatalf("bad IPIP diagnostic report: %+v", report)
			}
			if prober.probes != 6 {
				t.Fatalf("unexpected bounded Link-specific probe count: %d", prober.probes)
			}
			for _, command := range prober.commands {
				if strings.Contains(command, "iptables") || strings.Contains(command, "link set") ||
					strings.Contains(command, "route add") {
					t.Fatalf("diagnose attempted network mutation: %s", command)
				}
			}
		})
	}
}

func TestIPIPCLIInspectionFailureCannotBecomeHealth(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_99999999999999999999999999999999", "10.80.90.0/31", "10.80.90.1/31", domain.BackendIPIP)
	storeReadLinks(t, root, link)
	name, _ := ipipbackend.InterfaceName(link.ID)
	inspector := &readIPIPDiagnosticBackend{
		capability: linux.CapabilityStatus{Available: true},
		state:      ipipbackend.DiagnosticState{Interface: name, IfIndex: 0, Encapsulation: domain.EncapNative},
	}
	prober := &readGREProbeRunner{link: link, name: name, observedIndex: 77}
	for _, command := range []string{"status", "diagnose"} {
		code, out, stderr := runIPIPRead(root, inspector, prober, "link", command, string(link.ID), "--json")
		if code != 1 || stderr != "" || strings.Contains(out, "private_key") {
			t.Fatalf("%s incorrectly accepted inconsistent IPIP identity: %d %q %q", command, code, out, stderr)
		}
	}
	if prober.probes != 0 {
		t.Fatalf("active packets sent before ownership/identity check: %d", prober.probes)
	}
	inspector.capability.Available = false
	code, _, _ := runIPIPRead(root, inspector, prober, "link", "diagnose", string(link.ID), "--json")
	if code != 4 || prober.probes != 0 {
		t.Fatalf("missing IPIP capability did not fail closed: code=%d probes=%d", code, prober.probes)
	}
	inspector.capability.Available = true
	inspector.err = errors.New("private_key=DO_NOT_EXPOSE")
	code, out, _ := runIPIPRead(root, inspector, prober, "link", "diagnose", string(link.ID), "--json")
	if code != 1 || strings.Contains(out, "DO_NOT_EXPOSE") {
		t.Fatalf("IPIP error leaked sensitive backend output: %d %q", code, out)
	}
}
