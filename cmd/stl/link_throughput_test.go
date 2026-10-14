package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

const goodIperfJSON = `{
	"start":{"connected":[{"host":"peer-private-hostname"}]},
	"end":{
		"sum_sent":{"seconds":3.01,"bytes":3750000,"bits_per_second":10000000},
		"sum_received":{"seconds":3.01,"bytes":3712500,"bits_per_second":9900000}
	}
}`

type throughputPreflightRunner struct {
	*readGREProbeRunner
	badRoute bool
}

func (r *throughputPreflightRunner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && strings.Join(args, " ") == "-4 -json route get "+r.link.Addresses.Peer.Addr().String() {
		source := r.link.Addresses.Local.Addr().String()
		device := r.name
		if r.badRoute {
			device = "eth0"
		}
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf(
			`[{"dst":%q,"dev":%q,"prefsrc":%q}]`, r.link.Addresses.Peer.Addr().String(), device, source))}, nil
	}
	return r.readGREProbeRunner.Run(ctx, name, args...)
}

type throughputFakeTool struct {
	calls         int // throughput client attempts only
	versionCalls  int
	args          []string
	errorText     string
	output        string
	versionOutput string
	versionErr    error
	onCall        func()
}

func (f *throughputFakeTool) Run(context.Context, string, ...string) (linux.CommandResult, error) {
	panic("unbounded tool invocation not allowed")
}

func (f *throughputFakeTool) RunBounded(_ context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name != "iperf3" {
		return linux.CommandResult{}, errors.New("unexpected executable")
	}
	if len(args) == 1 && args[0] == "--version" {
		f.versionCalls++
		if limits.Stdout != 2048 || limits.Stderr != 1024 {
			return linux.CommandResult{}, errors.New("unbounded version read")
		}
		if f.versionErr != nil {
			return linux.CommandResult{}, f.versionErr
		}
		return linux.CommandResult{Stdout: []byte(f.versionOutput)}, nil
	}
	f.calls++
	f.args = append([]string{name}, args...)
	if f.onCall != nil {
		f.onCall()
	}
	if limits.Stdout != 64<<10 || limits.Stderr != 2048 {
		return linux.CommandResult{}, errors.New("not bounded")
	}
	if f.errorText != "" {
		return linux.CommandResult{}, errors.New(f.errorText)
	}
	return linux.CommandResult{Stdout: []byte(f.output)}, nil
}

func fixtureThroughput(t *testing.T) (string, domain.Link, *runtimeOptions, *throughputFakeTool, *throughputPreflightRunner) {
	t.Helper()
	root, link, inspector, read := fixtureDiagnose(t)
	route := &throughputPreflightRunner{readGREProbeRunner: read}
	tool := &throughputFakeTool{output: goodIperfJSON, versionOutput: "iperf 3.16 (cJSON 1.7.15)\n"}
	opts := &runtimeOptions{
		stateRoot:        root,
		backends:         []backend.Backend{inspector},
		probeRunner:      route,
		throughputRunner: tool,
	}
	return root, link, opts, tool, route
}

func callThroughput(args []string, opts *runtimeOptions) (int, string, string) {
	var out, errOut strings.Builder
	code := runWithRuntime(args, &out, &errOut, opts)
	return code, out.String(), errOut.String()
}

func TestThroughputExplicitOptInProvesOwnedInterfaceRouteAndNumericResult(t *testing.T) {
	_, link, opts, tool, route := fixtureThroughput(t)
	id := string(link.ID)
	status, output, errText := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--seconds", "3", "--json"}, opts)
	if status != 0 || errText != "" {
		t.Fatalf("scoped throughput failed: code=%d output=%s err=%s", status, output, errText)
	}
	var res linkThroughputResult
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatal(err)
	}
	if res.SchemaVersion != 1 || res.Operation != "link_throughput" || res.LinkID != link.ID ||
		res.Backend != domain.BackendGRE || res.Protocol != "tcp" || res.Direction != "local_to_peer" ||
		res.SentMbps != 10 || res.ReceivedMbps != 9.9 || res.Seconds != 3 ||
		res.SentBytes != 3750000 || res.ReceivedBytes != 3712500 ||
		strings.Contains(output, "private-hostname") {
		t.Fatalf("unsafe/incorrect numeric projection: %+v raw=%s", res, output)
	}
	expected := "iperf3 --client " + link.Addresses.Peer.Addr().String() +
		" --bind " + link.Addresses.Local.Addr().String() +
		" --bind-dev " + route.name +
		" --port 5201 --time 3 --connect-timeout 2000 --json"
	if tool.versionCalls != 1 || tool.calls != 1 || strings.Join(tool.args, " ") != expected {
		t.Fatalf("unbounded/unscoped iperf3 call: version=%d calls=%d argv=%s",
			tool.versionCalls, tool.calls, tool.args)
	}
	if route.probes != 6 {
		t.Fatalf("link reachability not verified before throughput: %d probes", route.probes)
	}
	for _, call := range route.commands {
		if strings.Contains(call, "link set") || strings.Contains(call, "route add") ||
			strings.Contains(call, "systemctl") || strings.Contains(call, "iptables") {
			t.Fatalf("preflight mutated kernel: %q", call)
		}
	}
}

func TestThroughputInvalidConfirmationOrDurationNeverTouchesRuntime(t *testing.T) {
	_, link, opts, tool, route := fixtureThroughput(t)
	id := string(link.ID)
	for _, args := range [][]string{
		{"link", "throughput", id},
		{"link", "throughput", id, "--confirm", "lnk_ffffffffffffffffffffffffffffffff"},
		{"link", "throughput", id, "--confirm", id, "--seconds", "0", "--json"},
		{"link", "throughput", id, "--confirm", id, "--seconds", "11", "--json"},
		{"link", "throughput", id, "--confirm", id, "--json", "--seconds", "1"},
		{"link", "throughput", id, "--confirm", id, "--unknown", "--json"},
		{"link", "throughput", "bad-id", "--confirm", "bad-id", "--json"},
	} {
		code, _, _ := callThroughput(args, opts)
		if code != 2 || tool.calls != 0 || route.probes != 0 {
			t.Fatalf("invalid explicit opt-in touched runtime: args=%v code=%d tool=%d probes=%d", args, code, tool.calls, route.probes)
		}
	}
}

func TestThroughputNoTrafficOnRouteDriftOrMissingLink(t *testing.T) {
	_, link, opts, tool, route := fixtureThroughput(t)
	id := string(link.ID)
	route.badRoute = true
	code, stdout, errText := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
	if code == 0 || tool.calls != 0 || !strings.Contains(stdout, "throughput_route_unverified") {
		t.Fatalf("route drift sent traffic or was hidden: code=%d out=%s err=%s", code, stdout, errText)
	}
	code, stdout, _ = callThroughput([]string{"link", "throughput", "lnk_ffffffffffffffffffffffffffffffff",
		"--confirm", "lnk_ffffffffffffffffffffffffffffffff", "--json"}, opts)
	if code != 2 || tool.calls != 0 || !strings.Contains(stdout, "throughput_link_not_found") {
		t.Fatalf("unknown link ran traffic: code=%d out=%s", code, stdout)
	}
}

func TestThroughputRedactsToolErrorsAndFailsClosedOnMalformedMetrics(t *testing.T) {
	_, link, opts, tool, _ := fixtureThroughput(t)
	id := string(link.ID)
	tool.errorText = "private_key=<SECRET> hostname=secret-peer"
	code, out, errText := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
	if code == 0 || !strings.Contains(out, "throughput_server_unavailable") ||
		strings.Contains(out+errText, "private_key") || strings.Contains(out+errText, "secret-peer") {
		t.Fatalf("iperf3 error not redacted: code=%d out=%s err=%s", code, out, errText)
	}
	tool.errorText = ""
	for _, raw := range []string{
		`{"error":"private_key=secret"}`,
		`{"end":{"sum_sent":{"seconds":3,"bytes":2,"bits_per_second":123}}}`,
		`{"end":{"sum_sent":{"seconds":3,"bytes":2,"bits_per_second":123},"sum_received":{"seconds":3,"bytes":2}}}`,
		`{"end":{"sum_sent":{"seconds":0,"bytes":2,"bits_per_second":123},"sum_received":{"seconds":3,"bytes":2,"bits_per_second":456}}}`,
		`[{"not":"iperf"}]`,
		`not-json`,
		strings.Repeat("x", 65<<10),
	} {
		if result, err := parseThroughputOutput([]byte(raw), link.ID, link.Backend, 3); err == nil {
			t.Fatalf("unverified numeric output treated as measurement: %+v", result)
		}
	}
	tool.output = `{"end":{"sum_sent":{"seconds":1.9,"bytes":0,"bits_per_second":0},"sum_received":{"seconds":1.9,"bytes":0,"bits_per_second":0}}}`
	code, out, errText = callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
	if code != 0 || !strings.Contains(out, `"sent_mbps":0`) || errText != "" {
		t.Fatalf("measured zero wrongly hidden: code=%d out=%s err=%s", code, out, errText)
	}
}

func TestThroughputHoldsExactEngineLinkLockForEntireTrafficWindow(t *testing.T) {
	root, link, opts, tool, _ := fixtureThroughput(t)
	tool.onCall = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		unlock, err := state.NewLockManager(root).Acquire(ctx,
			[]domain.ResourceClaim{{Kind: "stl-link", Key: string(link.ID)}})
		if unlock != nil {
			defer unlock()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Engine Link lock not held during traffic: %v", err)
		}
	}
	id := string(link.ID)
	code, _, errText := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
	if code != 0 || errText != "" || tool.calls != 1 {
		t.Fatalf("locked throughput failed: code=%d err=%s calls=%d", code, errText, tool.calls)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := state.NewLockManager(root).Acquire(ctx,
		[]domain.ResourceClaim{{Kind: "stl-link", Key: string(link.ID)}})
	if err != nil {
		t.Fatalf("Link lock was not released after traffic: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("cannot release acquired Link lock: %v", err)
	}
}

func TestThroughputNormalDiagnoseNeverStartsTraffic(t *testing.T) {
	_, link, opts, tool, _ := fixtureThroughput(t)
	code, _, errText := callThroughput([]string{"link", "diagnose", string(link.ID), "--json"}, opts)
	if code != 0 || errText != "" || tool.calls != 0 {
		t.Fatalf("ordinary read-only diagnostics unexpectedly invoked throughput: code=%d stderr=%s calls=%d", code, errText, tool.calls)
	}
}

func TestThroughputIperf3VersionParserRejectsUnsafeBeforeClient(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		accept       bool
	}{
		{"too old 3.9", "iperf 3.9 (cJSON 1.7.13)\n", false},
		{"affected 3.10", "iperf 3.10 (cJSON 1.7.13)\n", false},
		{"affected patch 3.10.1", "iperf 3.10.1 (cJSON 1.7.13)\n", false},
		{"patched 3.11", "iperf 3.11 (cJSON 1.7.13)\n", true},
		{"3.11.1", "iperf 3.11.1 (cJSON 1.7.13)\n", true},
		{"recent 3.16", "iperf 3.16 (cJSON 1.7.15)\n", true},
		{"recent 3.21", "iperf 3.21 (cJSON 1.7.15)\n", true},
		{"wrong major", "iperf 4.1 (cJSON 1.7.15)\n", false},
		{"unrecognized banner", "Welcome iperf 3.16\n", false},
		{"unrecognized executable", "not iperf3\n", false},
		{"embedded later line", "unsupported\niperf 3.16\n", false},
		{"pre release", "iperf 3.11-rc1\n", false},
		{"injected zero", "iperf 3.11\x00", false},
		{"missing", "", false},
		{"oversized", strings.Repeat("x", 2049), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if knownSafeIperf3TCPDeviceBinding([]byte(tc.output)) != tc.accept {
				t.Fatalf("version classified incorrectly: %q", tc.output)
			}
		})
	}
}

func TestThroughputRejectsAffectedIperf3VersionsBeforeAnyClientPacket(t *testing.T) {
	for _, version := range []string{
		"iperf 3.9 (cJSON 1.7.13)\n", "iperf 3.10 (cJSON 1.7.13)\n",
		"iperf 3.10.1 (cJSON 1.7.13)\n", "unknown tool version",
		"Welcome\niperf 3.16\n",
	} {
		t.Run(strings.TrimSpace(version), func(t *testing.T) {
			_, link, opts, tool, _ := fixtureThroughput(t)
			tool.versionOutput = version
			id := string(link.ID)
			code, out, errText := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
			if code != 4 || tool.versionCalls != 1 || tool.calls != 0 ||
				!strings.Contains(out, "throughput_tool_incompatible") ||
				strings.Contains(out+errText, version) {
				t.Fatalf("unsafe version reached client or leaked: code=%d version=%d calls=%d out=%s err=%s",
					code, tool.versionCalls, tool.calls, out, errText)
			}
		})
	}
}

func TestThroughputVersionFailureRedactedAndNoUnboundFallback(t *testing.T) {
	_, link, opts, tool, _ := fixtureThroughput(t)
	id := string(link.ID)
	tool.versionErr = errors.New("secret peer_key=hidden raw version error")
	code, out, errText := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
	if code != 4 || tool.calls != 0 || tool.versionCalls != 1 ||
		!strings.Contains(out, "throughput_tool_incompatible") ||
		strings.Contains(out+errText, "secret") || strings.Contains(out+errText, "peer_key") {
		t.Fatalf("version error leaked/retried: %d %s %s", code, out, errText)
	}
	tool.versionErr = nil
	tool.versionOutput = "iperf 3.16 (cJSON 1.7.15)\n"
	tool.errorText = "secret data connection failure"
	code, out, errText = callThroughput([]string{"link", "throughput", id, "--confirm", id, "--json"}, opts)
	if code == 0 || tool.calls != 1 || tool.versionCalls != 2 ||
		!strings.Contains(out, "throughput_server_unavailable") ||
		strings.Contains(out+errText, "secret") {
		t.Fatalf("client failure was retried or leaked: %d %s %s", code, out, errText)
	}
}
