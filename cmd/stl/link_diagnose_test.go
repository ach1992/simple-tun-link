package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type readGREDiagnosticBackend struct {
	backend.Backend
	state                grebackend.DiagnosticState
	capability           linux.CapabilityStatus
	err                  error
	capCalls, stateCalls int
}

func (*readGREDiagnosticBackend) Kind() domain.Backend { return domain.BackendGRE }
func (b *readGREDiagnosticBackend) Capability(context.Context, domain.Link) (linux.CapabilityStatus, error) {
	b.capCalls++
	if b.err != nil {
		return linux.CapabilityStatus{}, b.err
	}
	return b.capability, nil
}
func (b *readGREDiagnosticBackend) DiagnosticState(context.Context, domain.Link) (grebackend.DiagnosticState, error) {
	b.stateCalls++
	if b.err != nil {
		return grebackend.DiagnosticState{}, b.err
	}
	return b.state, nil
}

type readGREProbeRunner struct {
	link          domain.Link
	name          string
	probes        int
	commands      []string
	observedIndex int
}

func (r *readGREProbeRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	str := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, str)
	switch str {
	case "ip -4 -json route get 192.0.2.2":
		return linux.CommandResult{Stdout: []byte(`[{"dst":"192.0.2.2","dev":"eth0","prefsrc":"192.0.2.1","mtu":1420}]`)}, nil
	case "ip -json link show dev eth0":
		return linux.CommandResult{Stdout: []byte(`[{"ifindex":3,"ifname":"eth0","mtu":1500,"flags":["UP"]}]`)}, nil
	case "ip -4 -json address show dev " + r.name:
		row := fmt.Sprintf(`[{"ifindex":%d,"ifname":%q,"mtu":1400,"flags":["UP"],"addr_info":[{"family":"inet","local":%q,"prefixlen":31}]}]`,
			r.observedIndex, r.name, r.link.Addresses.Local.Addr().String())
		return linux.CommandResult{Stdout: []byte(row)}, nil
	default:
		if name != "env" {
			return linux.CommandResult{}, errors.New("unexpected OS command")
		}
		r.probes++
		if !strings.HasSuffix(str, " "+r.link.Addresses.Peer.Addr().String()) ||
			!strings.Contains(str, " -I "+r.name+" -I "+r.link.Addresses.Local.Addr().String()+" ") {
			return linux.CommandResult{}, fmt.Errorf("probe was not Link-scoped")
		}
		peer := r.link.Addresses.Peer.Addr().String()
		return linux.CommandResult{Stdout: []byte(
			"64 bytes from " + peer + ": icmp_seq=1 ttl=64 time=0.050 ms\n" +
				"1 packets transmitted, 1 received, 0% packet loss\n")}, nil
	}
}

func fixtureDiagnose(t *testing.T) (string, domain.Link, *readGREDiagnosticBackend, *readGREProbeRunner) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_77777777777777777777777777777777", "10.80.80.0/31", "10.80.80.1/31", domain.BackendGRE)
	storeReadLinks(t, root, link)
	name, err := grebackend.InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	inspector := &readGREDiagnosticBackend{capability: linux.CapabilityStatus{Available: true}, state: grebackend.DiagnosticState{
		Interface: name, IfIndex: 77, Encapsulation: domain.EncapNative, RXPackets: 17, TXPackets: 22,
	}}
	return root, link, inspector, &readGREProbeRunner{link: link, name: name, observedIndex: 77}
}

func execDiagnose(t *testing.T, root string, impl *readGREDiagnosticBackend, probe linux.Runner, args ...string) (int, string, string) {
	t.Helper()
	var bs []backend.Backend
	if impl != nil {
		bs = []backend.Backend{impl}
	}
	var stdout, stderr strings.Builder
	code := runWithRuntime(args, &stdout, &stderr, &runtimeOptions{stateRoot: root, backends: bs, probeRunner: probe})
	return code, stdout.String(), stderr.String()
}

func TestCLIDiagnoseGREProvidesVersionedMeasuredLinkReport(t *testing.T) {
	root, link, inspector, probe := fixtureDiagnose(t)
	code, stdout, stderr := execDiagnose(t, root, inspector, probe, "link", "diagnose", string(link.ID), "--json")
	if code != 0 || stderr != "" || strings.Contains(stdout, "private_key") {
		t.Fatalf("active diagnose failed or leaked: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var payload diagnostics.GREReport
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != 1 || payload.LinkID != link.ID || payload.State.RXPackets != 17 ||
		!payload.MTU.Verified || payload.MTU.SelectedMTU != 1396 ||
		!payload.Quality.Reachable || payload.Quality.PacketsReceived != 5 {
		t.Fatalf("incorrect measured GRE diagnostic response: %+v", payload)
	}
	if inspector.capCalls != 1 || inspector.stateCalls != 1 || probe.probes != 6 {
		t.Fatalf("unexpected inspection budget: capability=%d state=%d probes=%d", inspector.capCalls, inspector.stateCalls, probe.probes)
	}
	for _, call := range probe.commands {
		if strings.Contains(call, "iptables") || strings.Contains(call, "link set") || strings.Contains(call, "route add") || strings.Contains(call, "private_key") {
			t.Fatalf("diagnostics invoked a mutating or sensitive command: %q", call)
		}
	}
}

func TestCLIDiagnoseManualMTUAndHumanSummary(t *testing.T) {
	root, link, inspector, probe := fixtureDiagnose(t)
	code, stdout, stderr := execDiagnose(t, root, inspector, probe, "link", "diagnose", string(link.ID), "--mtu", "1300", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("manual failed: code=%d out=%q err=%q", code, stdout, stderr)
	}
	var report diagnostics.GREReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.MTU.Mode != "manual" || report.MTU.SelectedMTU != 1300 || report.MTU.Verified ||
		probe.probes != 5 {
		t.Fatalf("manual MTU was falsely auto-verified: %+v probes=%d", report.MTU, probe.probes)
	}
	code, stdout, stderr = execDiagnose(t, root, inspector, probe, "link", "diagnose", string(link.ID))
	if code != 0 || stderr != "" || !strings.Contains(stdout, "probe-confirmed") || !strings.Contains(stdout, "RX 17 packets") {
		t.Fatalf("missing human diagnostic result: code=%d out=%q err=%q", code, stdout, stderr)
	}
}

func TestCLIDiagnoseInvalidAndUnsupportedNeverProbe(t *testing.T) {
	root, link, inspector, probe := fixtureDiagnose(t)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"link", "diagnose", "bad", "--json"}, 2},
		{[]string{"link", "diagnose", "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--json"}, 2},
		{[]string{"link", "diagnose", string(link.ID), "--mtu", "67", "--json"}, 2},
		{[]string{"link", "diagnose", string(link.ID), "--mtu", "65536", "--json"}, 2},
		{[]string{"link", "diagnose", string(link.ID), "--mtu", "1k", "--json"}, 2},
		{[]string{"link", "diagnose", string(link.ID), "--mtu", "1300", "--mtu", "1400", "--json"}, 2},
		{[]string{"link", "diagnose", string(link.ID), "--json", "--json"}, 2},
		{[]string{"link", "diagnose", string(link.ID), "--bad", "--json"}, 2},
	} {
		code, stdout, stderr := execDiagnose(t, root, inspector, probe, tc.args...)
		if code != tc.code || stderr != "" {
			t.Fatalf("invalid request accepted: %v => %d %q %q", tc.args, code, stdout, stderr)
		}
		var out linkReadErrorResponse
		if err := json.Unmarshal([]byte(stdout), &out); err != nil || out.SchemaVersion != 1 || out.Error == nil || out.Error.Code != stlerr.CodeInvalid {
			t.Fatalf("invalid request not structured JSON: %v out=%q", tc.args, stdout)
		}
	}
	if inspector.capCalls != 0 || probe.probes != 0 {
		t.Fatalf("invalid requests touched backend: %d %d", inspector.capCalls, probe.probes)
	}
}

func TestCLIDiagnoseRejectsUnavailableAndMismatchedObservedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.Link, *readGREDiagnosticBackend, *readGREProbeRunner)
		want   int
	}{
		{"capability missing", func(_ *domain.Link, b *readGREDiagnosticBackend, _ *readGREProbeRunner) {
			b.capability = linux.CapabilityStatus{Reason: "not supported"}
		}, 4},
		{"ifindex changed", func(_ *domain.Link, _ *readGREDiagnosticBackend, r *readGREProbeRunner) { r.observedIndex = 88 }, 1},
		{"state unavailable", func(_ *domain.Link, b *readGREDiagnosticBackend, _ *readGREProbeRunner) {
			b.err = errors.New("private_key=NEVER_LOG")
		}, 1},
		{"unsupported backend", func(l *domain.Link, _ *readGREDiagnosticBackend, _ *readGREProbeRunner) {
			l.Backend = domain.BackendIPIP
		}, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, link, b, r := fixtureDiagnose(t)
			tc.mutate(&link, b, r)
			if link.Backend != domain.BackendGRE {
				root = filepath.Join(t.TempDir(), "unsupported")
				storeReadLinks(t, root, link)
			}
			code, stdout, stderr := execDiagnose(t, root, b, r, "link", "diagnose", string(link.ID), "--json")
			if code != tc.want || stderr != "" || strings.Contains(stdout, "private_key") {
				t.Fatalf("bad fail-closed behavior: %d %q %q", code, stdout, stderr)
			}
			var out linkReadErrorResponse
			if err := json.Unmarshal([]byte(stdout), &out); err != nil || out.SchemaVersion != 1 || out.Error == nil {
				t.Fatalf("unstructured failed diagnostics: %q %v", stdout, err)
			}
			if r.probes != 0 {
				t.Fatalf("unsafe diagnostic probe after error: %d", r.probes)
			}
		})
	}
}

func TestCLIDiagnoseDoesNotGuessMTU(t *testing.T) {
	root, link, inspector, probe := fixtureDiagnose(t)
	for _, n := range []int{1400, 1476} {
		// The observed route MTU 1420 and GRE overhead 24 cap the
		// inner Link MTU at 1396; larger manual overrides must fail.
		code, out, _ := execDiagnose(t, root, inspector, probe, "link", "diagnose", string(link.ID), "--mtu", strconv.Itoa(n), "--json")
		if code == 0 || strings.Contains(out, "private_key") {
			t.Fatalf("invalid oversize MTU was accepted: %d %q", n, out)
		}
	}
}
