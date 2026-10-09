//go:build linux

package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type scriptedLinuxRunner struct {
	calls             []string
	routeSource       string
	routeMTU          int
	localPrefix       netip.Prefix
	linkUp            bool
	addressIndex      int
	pingResult        linux.CommandResult
	pingErr           error
	pingMax           int
	pingTotalRequests int
}

func newScriptedLinuxRunner() *scriptedLinuxRunner {
	return &scriptedLinuxRunner{routeSource: "192.0.2.10", routeMTU: 1410,
		localPrefix: netip.MustParsePrefix("10.80.20.0/31"), linkUp: true, addressIndex: 77}
}

func (r *scriptedLinuxRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	cmd := strings.Join(args, " ")
	switch {
	case name == "ip" && cmd == "-4 -json route get 192.0.2.20":
		raw := fmt.Sprintf(`[{"dst":"192.0.2.20","dev":"eth0","prefsrc":%q,"mtu":%d}]`, r.routeSource, r.routeMTU)
		return linux.CommandResult{Stdout: []byte(raw)}, nil
	case name == "ip" && cmd == "-json link show dev eth0":
		return linux.CommandResult{Stdout: []byte(`[{"ifindex":3,"ifname":"eth0","mtu":1500,"flags":["UP"]}]`)}, nil
	case name == "ip" && cmd == "-4 -json address show dev stltest0":
		flags := "UP"
		if !r.linkUp {
			flags = "DOWN"
		}
		raw := fmt.Sprintf(`[{"ifindex":%d,"ifname":"stltest0","mtu":1400,"flags":[%q],"addr_info":[{"family":"inet","local":%q,"prefixlen":%d}]}]`,
			r.addressIndex, flags, r.localPrefix.Addr().String(), r.localPrefix.Bits())
		return linux.CommandResult{Stdout: []byte(raw)}, nil
	case name == "env":
		r.pingTotalRequests++
		if r.pingMax != 0 {
			idx := slices.Index(args, "-s")
			if idx < 0 || idx+1 >= len(args) {
				return linux.CommandResult{}, errors.New("missing ping payload")
			}
			dataBytes, _ := strconv.Atoi(args[idx+1])
			if dataBytes+28 > r.pingMax {
				return linux.CommandResult{Stderr: []byte("ping: local error: message too long, mtu=1400")}, &linux.CommandError{Command: "env", ExitCode: 1}
			}
			return linux.CommandResult{Stdout: []byte("PING 10.80.20.1 (10.80.20.1)\n64 bytes from 10.80.20.1: icmp_seq=1 ttl=64 time=0.045 ms\n\n--- 10.80.20.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n")}, nil
		}
		return r.pingResult, r.pingErr
	default:
		return linux.CommandResult{}, fmt.Errorf("unexpected read-only command %q", name+" "+cmd)
	}
}

func testLinuxOptions(r linux.Runner) LinuxProbeOptions {
	return LinuxProbeOptions{Runner: r, Interface: "stltest0", BackendOverhead: 24}
}

func TestLinuxPreflightUsesRealUnderlayPathAndExactLocalLinkAddress(t *testing.T) {
	runner := newScriptedLinuxRunner()
	link := diagnosticLink()
	constraints, err := PreflightLinux(context.Background(), link, testLinuxOptions(runner))
	if err != nil || constraints.UnderlayMTU != 1410 || constraints.BackendOverhead != 24 {
		t.Fatalf("route-aware constraints wrong: %+v err=%v", constraints, err)
	}
	want := []string{
		"ip -4 -json route get 192.0.2.20",
		"ip -json link show dev eth0",
		"ip -4 -json address show dev stltest0",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("unscoped or unexpected observations: %v", runner.calls)
	}
}

func TestLinuxPreflightRefusesMismatchedSourceAddressOrUnavailableInterface(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*scriptedLinuxRunner, *LinuxProbeOptions)
	}{
		{"wrong underlay source", func(r *scriptedLinuxRunner, _ *LinuxProbeOptions) { r.routeSource = "192.0.2.90" }},
		{"missing link source", func(r *scriptedLinuxRunner, _ *LinuxProbeOptions) {
			r.localPrefix = netip.MustParsePrefix("10.9.9.9/32")
		}},
		{"interface down", func(r *scriptedLinuxRunner, _ *LinuxProbeOptions) { r.linkUp = false }},
		{"interface ifindex invalid", func(r *scriptedLinuxRunner, _ *LinuxProbeOptions) { r.addressIndex = 0 }},
		{"missing overhead", func(_ *scriptedLinuxRunner, o *LinuxProbeOptions) { o.BackendOverhead = 0 }},
		{"invalid iface", func(_ *scriptedLinuxRunner, o *LinuxProbeOptions) { o.Interface = "-f" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newScriptedLinuxRunner()
			o := testLinuxOptions(r)
			tc.mutate(r, &o)
			if _, err := PreflightLinux(context.Background(), diagnosticLink(), o); err == nil {
				t.Fatal("unsafe Linux diagnostic preflight accepted")
			}
			if r.pingTotalRequests != 0 {
				t.Fatal("preflight must not transmit any packets")
			}
		})
	}
}

func TestLinuxPingOutcomeClassificationRejectsUnprovenReplies(t *testing.T) {
	peer := netip.MustParseAddr("10.80.20.1")
	reply := "64 bytes from 10.80.20.1: icmp_seq=1 ttl=64 time=0.045 ms\n1 packets transmitted, 1 received, 0% packet loss\n"
	empty := &linux.CommandError{Command: "env", ExitCode: 1}
	cases := []struct {
		name   string
		result linux.CommandResult
		err    error
		want   ProbeOutcome
		fails  bool
	}{
		{"confirmed reply", linux.CommandResult{Stdout: []byte(reply)}, nil, ProbeReply, false},
		{"actual unanswered", linux.CommandResult{Stdout: []byte("1 packets transmitted, 0 received, 100% packet loss")}, empty, ProbeTimeout, false},
		{"network error is not silent packet loss", linux.CommandResult{Stdout: []byte("1 packets transmitted, 0 received, +1 errors, 100% packet loss")}, empty, ProbeUnsupported, false},
		{"local fragmentation", linux.CommandResult{Stderr: []byte("ping: local error: message too long")}, empty, ProbeTooLarge, false},
		{"remote fragmentation", linux.CommandResult{Stdout: []byte("From 192.0.2.1 icmp_seq=1 Frag needed and DF set")}, empty, ProbeTooLarge, false},
		{"missing tool", linux.CommandResult{}, fmt.Errorf("spawn: %w", exec.ErrNotFound), ProbeUnsupported, false},
		{"unsupported ping option", linux.CommandResult{}, &linux.CommandError{Command: "env", ExitCode: 2}, ProbeUnsupported, false},
		{"false summary", linux.CommandResult{Stdout: []byte("1 packets transmitted, 1 received, 0% packet loss")}, nil, "", true},
		{"wrong peer", linux.CommandResult{Stdout: []byte(strings.Replace(reply, "bytes from 10.80.20.1", "bytes from 10.80.20.99", 1))}, nil, "", true},
		{"inconsistent success", linux.CommandResult{Stdout: []byte("1 packets transmitted, 0 received, 100% packet loss")}, nil, "", true},
		{"empty transport failure", linux.CommandResult{}, empty, "", true},
		{"private command error", linux.CommandResult{}, errors.New("DO_NOT_LEAK_PRIVATE_TOKEN"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePingSample(tc.result, tc.err, peer)
			if (err != nil) != tc.fails || (!tc.fails && got.Outcome != tc.want) {
				t.Fatalf("probe=%+v err=%v want=%s fails=%v", got, err, tc.want, tc.fails)
			}
			if err != nil && strings.Contains(err.Error(), "DO_NOT_LEAK") {
				t.Fatal("sensitive runner error leaked")
			}
		})
	}
}

func TestLinuxProbeArgsAreLinkBoundAndNeverTargetUnderlay(t *testing.T) {
	runner := newScriptedLinuxRunner()
	runner.pingResult = linux.CommandResult{Stdout: []byte(
		"64 bytes from 10.80.20.1: icmp_seq=1 ttl=64 time=0.123 ms\n1 packets transmitted, 1 received, 0% packet loss\n")}
	link := diagnosticLink()
	prober, err := NewLinuxDFProber(link, testLinuxOptions(runner))
	if err != nil {
		t.Fatal(err)
	}
	got, err := prober.Probe(context.Background(), link, 84)
	if err != nil || got.Outcome != ProbeReply || got.RTT != 123*time.Microsecond {
		t.Fatalf("actual DF echo not parsed: %+v err=%v", got, err)
	}
	want := "env LC_ALL=C ping -4 -n -c 1 -W 1 -M do -s 56 -I stltest0 -I 10.80.20.0 10.80.20.1"
	if !slices.Contains(runner.calls, want) {
		t.Fatalf("ping not strictly scoped: %v", runner.calls)
	}
	other := link
	other.ID = domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := prober.Probe(context.Background(), other, 84); err == nil {
		t.Fatal("cross-Link probe was accepted")
	}
	other = link
	other.Addresses.Peer = netip.MustParsePrefix("10.8.8.8/32")
	if _, err := prober.Probe(context.Background(), other, 84); err == nil {
		t.Fatal("changed Link address was accepted")
	}
	if _, err := prober.Probe(context.Background(), link, MinIPv4MTU-1); err == nil {
		t.Fatal("invalid size was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prober.Probe(ctx, link, 84); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not respected: %v", err)
	}
	if runner.pingTotalRequests != 1 {
		t.Fatalf("unexpected extra probes: %d", runner.pingTotalRequests)
	}
}

func TestObserveLinuxComposesReadOnlyPreflightMTUAndQuality(t *testing.T) {
	r := newScriptedLinuxRunner()
	r.pingMax = 1360
	o := testLinuxOptions(r)
	link := diagnosticLink()
	report, err := ObserveLinux(context.Background(), link, o)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != SchemaVersion || report.LinkID != link.ID ||
		report.MTU.CeilingMTU != 1386 || !report.MTU.Verified ||
		report.MTU.SelectedMTU != 1360 || report.Quality.Status != QualityMeasured ||
		!report.Quality.Reachable || report.Quality.PacketsReceived != DefaultQualitySamples {
		t.Fatalf("incorrect composed Linux diagnostics: %+v", report)
	}
	if r.pingTotalRequests > MaxMTUProbeAttempts+DefaultQualitySamples {
		t.Fatalf("unbounded probe requests: %d", r.pingTotalRequests)
	}
	for _, cmd := range r.calls {
		if strings.Contains(cmd, "192.0.2.20") && strings.HasPrefix(cmd, "env ") {
			t.Fatal("underlay address used as measurement target")
		}
	}
}

func TestLinuxDFProberLoopbackSmoke(t *testing.T) {
	if os.Getenv("STL_LIVE_LOOPBACK_PING") != "1" {
		t.Skip("opt-in read-only loopback probe; no privileged namespace required")
	}
	// Only the localhost interface is used; no remote network traffic.
	link := diagnosticLink()
	link.Addresses.Local = netip.MustParsePrefix("127.0.0.1/8")
	link.Addresses.Peer = netip.MustParsePrefix("127.0.0.2/8")
	p, err := NewLinuxDFProber(link, LinuxProbeOptions{Runner: linux.ExecRunner{}, Interface: "lo"})
	if err != nil {
		t.Fatal(err)
	}
	sample, err := p.Probe(context.Background(), link, 84)
	if err != nil || sample.Outcome != ProbeReply {
		t.Fatalf("local iputils DF echo was not confirmed: %+v err=%v", sample, err)
	}
}
