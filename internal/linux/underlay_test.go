package linux

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type offlineUnderlayRoutes struct {
	calls  int
	source netip.Addr
}

func (r *offlineUnderlayRoutes) Resolve(_ context.Context, peer netip.Addr) (Route, error) {
	r.calls++
	if r.source.IsValid() {
		return Route{Peer: peer, Source: r.source, Device: "wrong0"}, nil
	}
	return Route{}, errors.New("network unreachable")
}
func TestLocalAddressInventoryAndPeerOfflineFallback(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	host := &fakeRunner{result: CommandResult{Stdout: []byte(`[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"}]},{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet6","local":"2001:db8::1"}]}]`)}}
	for _, route := range []*offlineUnderlayRoutes{{}, {source: netip.MustParseAddr("198.51.100.4")}} {
		got, err := ResolveConfiguredUnderlay(context.Background(), route, host, local, peer)
		if err != nil || got.Source != local || got.Device != "ens3" || got.Peer != peer || got.Gateway.IsValid() || route.calls != 1 {
			t.Fatalf("offline local creation failed: got=%+v err=%v calls=%d", got, err, route.calls)
		}
		if host.name != "ip" || len(host.args) != 3 || host.args[0] != "-json" || host.args[1] != "address" || host.args[2] != "show" {
			t.Fatal("fallback performed something other than local address inventory", host.args)
		}
	}
}
func TestLocalIPv4FallbackRejectsUnassignedAndAmbiguousSource(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	for _, tc := range []struct{ name, json string }{
		{"unassigned", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.11"}]}]`},
		{"ambiguous", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`},
		{"malformed", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"UNTRUSTED"}]}]`},
		{"foreign interface", `[{"ifname":"bad space","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeRunner{result: CommandResult{Stdout: []byte(tc.json)}}
			if _, err := ResolveConfiguredUnderlay(context.Background(), &offlineUnderlayRoutes{}, host, local, peer); err == nil {
				t.Fatal("admitted unverified local address")
			}
		})
	}
}

func TestLocalInventoryRequiredEvenForMatchingRouteHint(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	matching := &offlineUnderlayRoutes{source: local}
	for _, tc := range []struct {
		name, rows string
		wantDevice string
		mustReject bool
	}{
		{"matching-route-but-unassigned", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.99"}]}]`, "", true},
		{"matching-route-but-wrong-device", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`, "ens3", false},
		{"matching-route-but-ambiguous", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`, "", true},
		{"matching-route-but-duplicate", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet","local":"192.0.2.10"}]}]`, "", true},
		{"matching-route-but-unknown-family", `[{"ifname":"ens3","addr_info":[{"local":"192.0.2.10"}]}]`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{result: CommandResult{Stdout: []byte(tc.rows)}}
			got, err := ResolveConfiguredUnderlay(context.Background(), matching, r, local, peer)
			if tc.mustReject {
				if err == nil {
					t.Fatalf("route suggestion bypassed assigned IPv4 proof: %+v", got)
				}
			} else if err != nil || got.Device != tc.wantDevice || got.Gateway.IsValid() || got.MTU != 0 {
				t.Fatalf("wrong route device not safely replaced by local inventory: %+v %v", got, err)
			}
		})
	}
}

func TestLocalAddressInventoryRejectsOversizedOrMissingContext(t *testing.T) {
	runner := &fakeRunner{result: CommandResult{Stdout: []byte("[" + strings.Repeat(" ", 256<<10) + "]")}}
	if _, err := ListLocalIPv4Endpoints(context.Background(), runner); err == nil {
		t.Fatal("unbounded host address inventory was accepted")
	}
	if _, err := ListLocalIPv4Endpoints(nil, runner); err == nil {
		t.Fatal("missing context accepted")
	}
}

// BoundedRunner is mandatory: a plain Runner must not be consulted,
// even if its fake output looks like a valid local IPv4 inventory.
type unboundedInventoryRunner struct{ calls int }

func (r *unboundedInventoryRunner) Run(_ context.Context, _ string, _ ...string) (CommandResult, error) {
	r.calls++
	return CommandResult{Stdout: []byte(`[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`)}, nil
}

type capturedInventoryRunner struct {
	unboundedInventoryRunner
	gotLimits CaptureLimits
	gotName   string
	gotArgs   []string
	result    CommandResult
	err       error
}

func (r *capturedInventoryRunner) RunBounded(ctx context.Context, limits CaptureLimits, name string, args ...string) (CommandResult, error) {
	r.gotLimits = limits
	r.gotName = name
	r.gotArgs = append([]string(nil), args...)
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	if r.err != nil {
		return CommandResult{}, r.err
	}
	if len(r.result.Stdout) > limits.Stdout || len(r.result.Stderr) > limits.Stderr {
		return CommandResult{}, ErrOutputLimit
	}
	return r.result, nil
}
func TestLocalInventoryRequiresCaptureBoundaryAndExactArgs(t *testing.T) {
	unbounded := &unboundedInventoryRunner{}
	if _, err := ListLocalIPv4Endpoints(context.Background(), unbounded); err == nil || unbounded.calls != 0 {
		t.Fatalf("unbounded runner was invoked instead of refused: err=%v calls=%d", err, unbounded.calls)
	}
	r := &capturedInventoryRunner{result: CommandResult{Stdout: []byte(`[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`)}}
	endpoints, err := ListLocalIPv4Endpoints(context.Background(), r)
	if err != nil || len(endpoints) != 1 || endpoints[0].Interface != "ens3" || r.calls != 0 ||
		r.gotName != "ip" || !reflect.DeepEqual(r.gotArgs, []string{"-json", "address", "show"}) ||
		r.gotLimits != (CaptureLimits{Stdout: 256 << 10, Stderr: 1024}) {
		t.Fatalf("wrong bounded local inventory admission: %+v err=%v runner=%+v", endpoints, err, r)
	}
}

func TestRealLocalInventoryCaptureStopsOversizedStdoutAndStderr(t *testing.T) {
	// Execute the actual existing os/exec bounded reader via an isolated fake
	// ip binary; testing len(stdout) after a plain Run would not pass here.
	temp := t.TempDir()
	t.Setenv("PATH", temp+string(os.PathListSeparator)+os.Getenv("PATH"))
	script := filepath.Join(temp, "ip")
	for _, tc := range []struct{ name, body string }{
		{"stdout", "/usr/bin/head -c 1048576 /dev/zero"},
		{"stderr", "/usr/bin/head -c 1048576 /dev/zero >&2"},
		{"valid", `printf '%s' '[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(script, []byte("#!/bin/sh\n"+tc.body+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			endpoints, err := ListLocalIPv4Endpoints(context.Background(), ExecRunner{Timeout: 3 * time.Second})
			if tc.name == "valid" {
				if err != nil || len(endpoints) != 1 || endpoints[0].Address.String() != "192.0.2.10" {
					t.Fatalf("bounded valid inventory rejected: %v %+v", err, endpoints)
				}
			} else if !errors.Is(err, ErrOutputLimit) || len(endpoints) != 0 {
				t.Fatalf("%s overflow escaped capture-time bound: err=%v endpoints=%+v", tc.name, err, endpoints)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatalf("%s inventory overflow did not terminate promptly", tc.name)
			}
		})
	}
}
func TestLocalInventoryPreservesCancellationAndTimeoutClassification(t *testing.T) {
	r := &capturedInventoryRunner{err: context.DeadlineExceeded}
	if _, err := ListLocalIPv4Endpoints(context.Background(), r); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout classification lost: %v", err)
	}
	r.err = context.Canceled
	if _, err := ListLocalIPv4Endpoints(context.Background(), r); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation classification lost: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ListLocalIPv4Endpoints(ctx, r); !errors.Is(err, context.Canceled) {
		t.Fatalf("already-canceled context not propagated: %v", err)
	}
	if r.calls != 0 {
		t.Fatal("unbounded Run called after a cancellation")
	}
}
