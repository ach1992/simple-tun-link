package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type healthRunner struct {
	links    map[string]domain.Link // keyed by verified interface name
	probes   map[string]int
	commands []string
}

func (r *healthRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	call := name + " " + strings.Join(args, " ")
	r.commands = append(r.commands, call)
	switch call {
	case "ip -4 -json route get 192.0.2.2":
		return linux.CommandResult{Stdout: []byte(`[{"dst":"192.0.2.2","dev":"eth0","prefsrc":"192.0.2.1","mtu":1420}]`)}, nil
	case "ip -json link show dev eth0":
		return linux.CommandResult{Stdout: []byte(`[{"ifindex":3,"ifname":"eth0","mtu":1500,"flags":["UP"]}]`)}, nil
	}
	if name == "ip" && len(args) == 6 && args[0] == "-4" && args[1] == "-json" &&
		args[2] == "address" && args[3] == "show" && args[4] == "dev" {
		if link, ok := r.links[args[5]]; ok {
			data := fmt.Sprintf(`[{"ifindex":77,"ifname":%q,"mtu":1400,"flags":["UP"],"addr_info":[{"family":"inet","local":%q,"prefixlen":31}]}]`,
				args[5], link.Addresses.Local.Addr().String())
			return linux.CommandResult{Stdout: []byte(data)}, nil
		}
	}
	if name == "env" {
		for iface, link := range r.links {
			if strings.Contains(call, " -I "+iface+" -I "+link.Addresses.Local.Addr().String()+" ") &&
				strings.HasSuffix(call, " "+link.Addresses.Peer.Addr().String()) {
				r.probes[iface]++
				peer := link.Addresses.Peer.Addr().String()
				return linux.CommandResult{Stdout: []byte("64 bytes from " + peer + ": icmp_seq=1 ttl=64 time=0.050 ms\n1 packets transmitted, 1 received, 0% packet loss\n")}, nil
			}
		}
	}
	return linux.CommandResult{}, errors.New("PSK=UNTRUSTED_RAW_RUNNER_ERROR")
}

func fixtureHealthCenter(t *testing.T) (string, []backend.Backend, *healthRunner, []domain.Link) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "health-state")
	gre := fixtureReadLink("lnk_11111111111111111111111111111111", "10.80.10.0/31", "10.80.10.1/31", domain.BackendGRE)
	ipip := fixtureReadLink("lnk_22222222222222222222222222222222", "10.80.20.0/31", "10.80.20.1/31", domain.BackendIPIP)
	wg := fixtureReadLink("lnk_33333333333333333333333333333333", "10.80.30.0/31", "10.80.30.1/31", domain.BackendWireGuard)
	wg.Encapsulation = domain.EncapUDP
	completeWireGuardFixture(t, &wg, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x64}, 32)))
	ipsec := fixtureReadLink("lnk_44444444444444444444444444444444", "10.80.40.0/31", "10.80.40.1/31", domain.BackendIPsec)
	ipsec.Encapsulation = domain.EncapESP
	storeReadLinks(t, root, ipsec, wg, ipip, gre)
	greName, _ := grebackend.InterfaceName(gre.ID)
	ipipName, _ := ipipbackend.InterfaceName(ipip.ID)
	wgName, _ := wgbackend.InterfaceName(wg.ID)
	implementations := []backend.Backend{
		&readGREDiagnosticBackend{capability: linux.CapabilityStatus{Available: true}, state: grebackend.DiagnosticState{
			Interface: greName, IfIndex: 77, Encapsulation: gre.Encapsulation, RXPackets: 21, TXPackets: 22}},
		&readIPIPDiagnosticBackend{capability: linux.CapabilityStatus{Available: true}, state: ipipbackend.DiagnosticState{
			Interface: ipipName, IfIndex: 77, Encapsulation: ipip.Encapsulation, RXPackets: 31, TXPackets: 32}},
		&readWireGuardDiagnosticBackend{capability: linux.CapabilityStatus{Available: true}, state: wgbackend.DiagnosticState{
			Interface: wgName, IfIndex: 77, LocalPublicKey: wg.WireGuard.LocalPublicKey,
			PeerPublicKey: wg.WireGuard.PeerPublicKey, ListenPort: wg.WireGuard.ListenPort,
			LatestHandshakeUnix: 1700000000, RXBytes: 41, TXBytes: 42}},
	}
	probe := &healthRunner{links: map[string]domain.Link{greName: gre, ipipName: ipip, wgName: wg}, probes: make(map[string]int)}
	return root, implementations, probe, []domain.Link{gre, ipip, wg, ipsec}
}

func runHealth(t *testing.T, root string, impl []backend.Backend, runner linux.Runner, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := runWithRuntime(append([]string{"link", "diagnose", "--all"}, args...), &stdout, &stderr, &runtimeOptions{
		stateRoot: root, backends: impl, probeRunner: runner,
	})
	return code, stdout.String(), stderr.String()
}

func TestHealthCenterMixedGREIPIPWireGuardIPsecDeterministicSafeReport(t *testing.T) {
	root, implementations, probe, links := fixtureHealthCenter(t)
	code, out, stderr := runHealth(t, root, implementations, probe, "--json")
	if code != 4 || stderr != "" {
		t.Fatalf("blocked IPsec was not reported with typed exit: code=%d out=%q err=%q", code, out, stderr)
	}
	if strings.Contains(out, "DO_NOT_EXPOSE") || strings.Contains(out, "private_key") ||
		strings.Contains(out, "PSK=") || strings.Contains(out, "display_name") {
		t.Fatal("secret-looking desired state or command data leaked")
	}
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Operation != "link_diagnose_all" ||
		report.Outcome != "complete" || report.Total != 4 || len(report.Checks) != 4 ||
		report.Observed != 3 || report.Blocked != 1 || report.Unknown != 0 {
		t.Fatalf("wrong cross-backend summary: %+v", report)
	}
	for i, check := range report.Checks {
		if check.Link.ID != links[i].ID || check.Link.Backend != links[i].Backend || check.NextStep == "" {
			t.Fatalf("unstable ordered Link identity: %+v", check)
		}
		if i == 3 {
			if check.Status != "blocked" || check.ReasonCode != "ipsec_runtime_not_registered" || check.Observed != nil {
				t.Fatalf("IPsec activation falsely implied: %+v", check)
			}
		} else if check.Status != "observed" || check.ReasonCode != "link_peer_replied" ||
			check.Observed == nil || check.Observed.Quality.PacketsReceived != 5 || check.Observed.MTU.SelectedMTU < 1280 {
			t.Fatalf("backend did not independently verify peer replies: %+v", check)
		}
	}
	if report.Checks[0].Observed.CounterUnit != "packets" ||
		report.Checks[1].Observed.CounterUnit != "packets" ||
		report.Checks[2].Observed.CounterUnit != "bytes" ||
		report.Checks[2].Observed.LatestHandshakeUnix == nil {
		t.Fatal("backend-safe counter/handshake projection is not useful")
	}
	for _, count := range probe.probes {
		if count != 6 {
			t.Fatalf("unbounded or missing Link-scoped probes: %d", count)
		}
	}
	for _, command := range probe.commands {
		for _, mutation := range []string{"link add", "link set", "iptables", "route add", "swanctl", "systemctl", "wg set", "modprobe"} {
			if strings.Contains(command, mutation) {
				t.Fatalf("read-only health center invoked mutation: %q", command)
			}
		}
	}
	// The human response draws from the same measured batch and never says
	// the entire host is healthy while IPsec remains unavailable.
	code, human, errOut := runHealth(t, root, implementations, probe)
	if code != 4 || errOut != "" || !strings.Contains(human, "blocked/ipsec_runtime_not_registered") ||
		!strings.Contains(human, "peer replied: 3") || strings.Contains(human, "DO_NOT_EXPOSE") {
		t.Fatalf("unsafe, misleading or missing human operator summary: %d %q %q", code, human, errOut)
	}
}

func TestHealthCenterPartialFailureCannotMaskHealthySibling(t *testing.T) {
	root, implementations, probe, links := fixtureHealthCenter(t)
	gre := implementations[0].(*readGREDiagnosticBackend)
	gre.err = errors.New("private_key=NEVER_PRINT")
	ipip := implementations[1].(*readIPIPDiagnosticBackend)
	ipip.capability.Available = false
	code, out, stderr := runHealth(t, root, implementations, probe, "--json")
	if code != 1 || stderr != "" || strings.Contains(out, "NEVER_PRINT") {
		t.Fatalf("partial diagnosis silently succeeded or leaked raw errors: %d %q %q", code, out, stderr)
	}
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Total != 4 || report.Observed != 1 || report.Blocked != 2 || report.Unknown != 1 ||
		report.Checks[0].ReasonCode != "diagnostic_observation_unverified" ||
		report.Checks[1].ReasonCode != "diagnostic_capability_unavailable" ||
		report.Checks[2].Link.ID != links[2].ID || report.Checks[2].Status != "observed" ||
		report.Checks[3].ReasonCode != "ipsec_runtime_not_registered" {
		t.Fatalf("unrelated Link got swallowed or promoted: %+v", report)
	}
	wgName, _ := wgbackend.InterfaceName(links[2].ID)
	if probe.probes[wgName] != 6 {
		t.Fatal("one failing backend prevented a healthy sibling from being tested")
	}
}

func TestHealthCenterEmptyAndFailureInputNoMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	code, out, stderr := runHealth(t, root, nil, nil, "--json")
	if code != 0 || stderr != "" || !strings.Contains(out, `"checks":[]`) ||
		!strings.Contains(out, `"total":0`) {
		t.Fatalf("empty does not represent no configured Links: %d %q %q", code, out, stderr)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("health center created state directory")
	}
	for _, args := range [][]string{
		{"--json", "--json"},
		{"--mtu", "1300", "--json"},
		{"--timeout", "0s", "--json"},
		{"--timeout", "not-duration", "--json"},
		{"--timeout", "--json"},
		{"--timeout", "1s", "--timeout", "2s", "--json"},
		{"--bogus", "--json"},
	} {
		code, out, stderr := runHealth(t, root, nil, nil, args...)
		if code != 2 || stderr != "" {
			t.Fatalf("invalid batch args accepted: %v %d %q %q", args, code, out, stderr)
		}
		var got linkReadErrorResponse
		if err := json.Unmarshal([]byte(out), &got); err != nil ||
			got.Error == nil || got.Error.ReasonCode != "invalid_request" || got.Error.NextStep == "" {
			t.Fatalf("invalid batch request lost safe guidance: %v %q", args, out)
		}
	}
}

func TestHealthCenterExpiredBudgetPreservesAllLinkStatusesWithoutProbing(t *testing.T) {
	root, implementations, probe, _ := fixtureHealthCenter(t)
	code, out, stderr := runHealth(t, root, implementations, probe, "--timeout", "1ns", "--json")
	if code != 1 || stderr != "" {
		t.Fatalf("timeout silently passed or failed without report: %d %q %q", code, out, stderr)
	}
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Outcome != "interrupted" || report.Total != 4 || report.Unknown == 0 ||
		len(report.Checks) != 4 {
		t.Fatalf("timeout lost Link inventory: %+v", report)
	}
	if report.Checks[0].ReasonCode != "diagnostic_interrupted" {
		t.Fatalf("first unobserved Link not marked uncertain: %+v", report.Checks[0])
	}
	if len(probe.commands) != 0 {
		t.Fatal("expired deadline began kernel/network probes")
	}
}

func TestHealthCenterNoReplyIsNotAHealthyLink(t *testing.T) {
	link := fixtureReadLink("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "10.80.70.0/31", "10.80.70.1/31", domain.BackendGRE)
	m := linkDiagnostic{quality: diagnostics.QualityResult{Status: diagnostics.QualityMeasured},
		counterUnit: "packets"}
	check := healthFromMeasurement(link, m)
	if check.Status != "unknown" || check.ReasonCode != "link_probe_no_reply" || check.Observed == nil {
		t.Fatalf("missing peer reply promoted into health: %+v", check)
	}
	m.quality.Status = diagnostics.QualityPartial
	check = healthFromMeasurement(link, m)
	if check.ReasonCode != "link_probe_incomplete" || check.Status != "unknown" {
		t.Fatalf("incomplete observation promoted: %+v", check)
	}
	if got := healthDiagnosticFailure(link, stlerr.New(stlerr.CodeConflict, "diagnose", "", "", "")); got.Status != "blocked" {
		t.Fatalf("conflicting resource not explicitly blocked: %+v", got)
	}
}

// Two separately keyed/same-underlay GRE Links must not collapse into one
// diagnostic row or borrow a sibling's interface/traffic observations.
type multiGREHealthBackend struct {
	backend.Backend
	states map[domain.LinkID]grebackend.DiagnosticState
}

func (*multiGREHealthBackend) Kind() domain.Backend { return domain.BackendGRE }
func (*multiGREHealthBackend) Capability(context.Context, domain.Link) (linux.CapabilityStatus, error) {
	return linux.CapabilityStatus{Available: true}, nil
}
func (b *multiGREHealthBackend) DiagnosticState(_ context.Context, link domain.Link) (grebackend.DiagnosticState, error) {
	state, ok := b.states[link.ID]
	if !ok {
		return grebackend.DiagnosticState{}, errors.New("identity not owned")
	}
	return state, nil
}

func TestHealthCenterTwoSamePeerGRELinksIndependent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	first := fixtureReadLink("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "10.80.11.0/31", "10.80.11.1/31", domain.BackendGRE)
	first.GRE.KeyEnabled = true
	first.GRE.Key = 14001
	second := fixtureReadLink("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "10.80.12.0/31", "10.80.12.1/31", domain.BackendGRE)
	second.GRE.KeyEnabled = true
	second.GRE.Key = 14002
	storeReadLinks(t, root, second, first)
	firstName, _ := grebackend.InterfaceName(first.ID)
	secondName, _ := grebackend.InterfaceName(second.ID)
	impl := &multiGREHealthBackend{states: map[domain.LinkID]grebackend.DiagnosticState{
		first.ID:  {Interface: firstName, IfIndex: 77, Encapsulation: domain.EncapNative, RXPackets: 11, TXPackets: 12},
		second.ID: {Interface: secondName, IfIndex: 77, Encapsulation: domain.EncapNative, RXPackets: 31, TXPackets: 32},
	}}
	probe := &healthRunner{links: map[string]domain.Link{firstName: first, secondName: second},
		probes: make(map[string]int)}
	code, output, errOut := runHealth(t, root, []backend.Backend{impl}, probe, "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("simultaneous same-peer GRE diagnostics failed: %d %q %q", code, output, errOut)
	}
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(output), &report); err != nil || report.Total != 2 ||
		report.Observed != 2 || report.Blocked != 0 || report.Unknown != 0 ||
		report.Checks[0].Link.ID != first.ID || report.Checks[1].Link.ID != second.ID ||
		report.Checks[0].Observed == nil || report.Checks[1].Observed == nil ||
		report.Checks[0].Observed.RX != 11 || report.Checks[1].Observed.RX != 31 ||
		probe.probes[firstName] != 6 || probe.probes[secondName] != 6 {
		t.Fatalf("same-peer Links were conflated, skipped or misattributed: %+v probes=%v err=%v",
			report, probe.probes, err)
	}
}
