//go:build linux

package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type fakeGREInspector struct {
	cap        linux.CapabilityStatus
	state      grebackend.DiagnosticState
	capErr     error
	stateErr   error
	capCalls   int
	stateCalls int
}

func (f *fakeGREInspector) Capability(context.Context, domain.Link) (linux.CapabilityStatus, error) {
	f.capCalls++
	return f.cap, f.capErr
}
func (f *fakeGREInspector) DiagnosticState(context.Context, domain.Link) (grebackend.DiagnosticState, error) {
	f.stateCalls++
	return f.state, f.stateErr
}

type fakeGREProbeRunner struct {
	name         string
	addressIndex int
	calls        []string
	probeCount   int
}

func (r *fakeGREProbeRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch {
	case name == "ip" && strings.Join(args, " ") == "-4 -json route get 192.0.2.20":
		return linux.CommandResult{Stdout: []byte(`[{"dst":"192.0.2.20","dev":"eth0","prefsrc":"192.0.2.10","mtu":1420}]`)}, nil
	case name == "ip" && strings.Join(args, " ") == "-json link show dev eth0":
		return linux.CommandResult{Stdout: []byte(`[{"ifindex":3,"ifname":"eth0","mtu":1500,"flags":["UP"]}]`)}, nil
	case name == "ip" && strings.Join(args, " ") == "-4 -json address show dev "+r.name:
		row := fmt.Sprintf(`[{"ifindex":%d,"ifname":%q,"mtu":1400,"flags":["UP"],"addr_info":[{"family":"inet","local":"10.80.20.0","prefixlen":31}]}]`, r.addressIndex, r.name)
		return linux.CommandResult{Stdout: []byte(row)}, nil
	case name == "env":
		r.probeCount++
		return linux.CommandResult{Stdout: []byte(
			"64 bytes from 10.80.20.1: icmp_seq=1 ttl=64 time=0.050 ms\n" +
				"1 packets transmitted, 1 received, 0% packet loss\n")}, nil
	default:
		return linux.CommandResult{}, fmt.Errorf("unexpected read-only diagnostics invocation")
	}
}

func greFixture() (domain.Link, *fakeGREInspector, *fakeGREProbeRunner) {
	link := diagnosticLink()
	link.DisplayName = "private_key=NEVER_PRINT"
	name, _ := grebackend.InterfaceName(link.ID)
	inspector := &fakeGREInspector{
		cap:   linux.CapabilityStatus{Available: true},
		state: grebackend.DiagnosticState{Interface: name, IfIndex: 77, Encapsulation: link.Encapsulation, RXPackets: 7, TXPackets: 11},
	}
	return link, inspector, &fakeGREProbeRunner{name: name, addressIndex: 77}
}

func TestObserveGREComposesIdentityCheckedCountersAndMeasuredLinkMTU(t *testing.T) {
	link, inspector, runner := greFixture()
	report, err := ObserveGRE(context.Background(), link, inspector, runner, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.LinkID != link.ID || report.Backend != domain.BackendGRE ||
		report.State.IfIndex != 77 || report.State.RXPackets != 7 || report.State.TXPackets != 11 ||
		report.MTU.SelectedMTU != 1396 || !report.MTU.Verified || report.Quality.PacketsReceived != 5 {
		t.Fatalf("measured GRE report is invalid: %+v", report)
	}
	if inspector.capCalls != 1 || inspector.stateCalls != 1 || runner.probeCount != 6 {
		t.Fatalf("incorrect bounded observation: cap=%d counters=%d probe=%d", inspector.capCalls, inspector.stateCalls, runner.probeCount)
	}
	b, err := json.Marshal(report)
	if err != nil || strings.Contains(string(b), "private_key") || strings.Contains(string(b), "NEVER_PRINT") ||
		!strings.Contains(string(b), `"schema_version":1`) || !strings.Contains(string(b), `"rx_packets":7`) ||
		!strings.Contains(string(b), `"mtu":`) {
		t.Fatalf("secret leak or wrong structured schema: %s %v", b, err)
	}
	if strings.Contains(report.Summary(), "private_key") || !strings.Contains(report.Summary(), "RX 7 packets") {
		t.Fatalf("report summary unsafe or inaccurate: %s", report.Summary())
	}
	for _, cmd := range runner.calls {
		if strings.Contains(cmd, "link set") || strings.Contains(cmd, "address add") || strings.Contains(cmd, "fou add") ||
			strings.Contains(cmd, "iptables") || strings.Contains(cmd, "private_key") {
			t.Fatalf("diagnostics triggered mutation or emitted credential: %q", cmd)
		}
	}
}

func TestObserveGREManualMTUAndFOUOverheadAreBackendOwned(t *testing.T) {
	link, inspector, runner := greFixture()
	link.Encapsulation = domain.EncapFOU
	link.GRE.UDPPort = 4500
	inspector.state.Encapsulation = domain.EncapFOU
	report, err := ObserveGRE(context.Background(), link, inspector, runner, 1300)
	if err != nil {
		t.Fatal(err)
	}
	// Route MTU 1420, outer IPv4+GRE+UDP =32, ceiling=1388.
	if report.MTU.CeilingMTU != 1388 || report.MTU.SelectedMTU != 1300 ||
		report.MTU.Mode != "manual" || report.MTU.Verified || runner.probeCount != 5 {
		t.Fatalf("backend overhead/manual MTU was guessed or applied: %+v probes=%d", report.MTU, runner.probeCount)
	}
}

func TestObserveGREFailsClosedBeforeSendingProbes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.Link, *fakeGREInspector, *fakeGREProbeRunner)
		code   stlerr.Code
	}{
		{"wrong backend", func(l *domain.Link, _ *fakeGREInspector, _ *fakeGREProbeRunner) { l.Backend = domain.BackendIPIP }, stlerr.CodeUnsupported},
		{"backend unavailable", func(_ *domain.Link, i *fakeGREInspector, _ *fakeGREProbeRunner) {
			i.cap = linux.CapabilityStatus{Reason: "not supported"}
		}, stlerr.CodeUnsupported},
		{"different ifindex", func(_ *domain.Link, i *fakeGREInspector, _ *fakeGREProbeRunner) { i.state.IfIndex = 88 }, stlerr.CodeInspect},
		{"foreign interface", func(_ *domain.Link, i *fakeGREInspector, _ *fakeGREProbeRunner) { i.state.Interface = "foreign0" }, stlerr.CodeInspect},
		{"wrong encapsulation", func(_ *domain.Link, i *fakeGREInspector, _ *fakeGREProbeRunner) {
			i.state.Encapsulation = domain.EncapGUE
		}, stlerr.CodeInspect},
		{"failed inspection", func(_ *domain.Link, i *fakeGREInspector, _ *fakeGREProbeRunner) {
			i.stateErr = errors.New("private_key=NEVER_PRINT")
		}, stlerr.CodeInspect},
		{"failed capability inspection", func(_ *domain.Link, i *fakeGREInspector, _ *fakeGREProbeRunner) {
			i.capErr = errors.New("private_key=NEVER_PRINT")
		}, stlerr.CodeInspect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link, inspector, runner := greFixture()
			tc.mutate(&link, inspector, runner)
			_, err := ObserveGRE(context.Background(), link, inspector, runner, 0)
			if err == nil || stlerr.CodeOf(err) != tc.code || runner.probeCount != 0 {
				t.Fatalf("unsafe error handling: err=%v probes=%d", err, runner.probeCount)
			}
			if strings.Contains(stlerr.Public(err).Error(), "private_key") {
				t.Fatalf("unsafe public error: %s", stlerr.Public(err))
			}
		})
	}
}

func TestObserveGREPinKernelIfindexAcrossCounterAndAddressSnapshots(t *testing.T) {
	link, inspector, runner := greFixture()
	runner.addressIndex = 88
	_, err := ObserveGRE(context.Background(), link, inspector, runner, 0)
	if err == nil || stlerr.CodeOf(err) != stlerr.CodeInspect || runner.probeCount != 0 {
		t.Fatalf("different kernel interface was observed: err=%v sent=%d", err, runner.probeCount)
	}
}

func TestObserveGRECancelSkipsAllOSOperations(t *testing.T) {
	link, inspector, runner := greFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ObserveGRE(ctx, link, inspector, runner, 0)
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 || inspector.capCalls != 0 {
		t.Fatalf("cancel must stop operations: err=%v calls=%v", err, runner.calls)
	}
}

func TestObserveGREUsesBackendLinkDestinationNotUnderlay(t *testing.T) {
	link, inspector, runner := greFixture()
	_, err := ObserveGRE(context.Background(), link, inspector, runner, 0)
	if err != nil {
		t.Fatal(err)
	}
	expectedPeer := netip.MustParseAddr("10.80.20.1").String()
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "env ") && (!strings.HasSuffix(call, " "+expectedPeer) ||
			strings.Contains(call, " 192.0.2.20")) {
			t.Fatalf("active diagnostics probed underlay or unrelated address: %q", call)
		}
	}
}
