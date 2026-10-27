package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func parallelHealthMeasured() linkDiagnostic {
	return linkDiagnostic{quality: diagnostics.QualityResult{
		Status: diagnostics.QualityMeasured, Reachable: true,
		PacketsSent: 1, PacketsReceived: 1,
	}}
}

// Before this option a slow first Link would consume the entire shared
// deadline and prevent a healthy later Link from being inspected. Concurrent
// observations must preserve that second Link's ACTUAL time-local evidence,
// while refusing the late success of the first Link and retaining ID order.
func TestHealthCenterParallelSlowFirstLinkDoesNotStarveHealthySibling(t *testing.T) {
	snapshot := healthRemediationInventory()
	slow := snapshot.Links[0].Desired.ID
	var started atomic.Int32
	deps := healthCenterServices{
		load: func(context.Context) (state.Snapshot, error) { return snapshot, nil },
		observe: func(ctx context.Context, link domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
			started.Add(1)
			if link.ID == slow {
				<-ctx.Done()
				// An uncooperative observer reports apparent success AFTER
				// the batch deadline: it must NEVER become observed.
				return parallelHealthMeasured(), nil
			}
			return parallelHealthMeasured(), nil
		},
	}
	code, out, stderr := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--parallel", "2", "--timeout", "150ms", "--json"},
		&runtimeOptions{stateRoot: t.TempDir()}, deps,
	)
	var batch healthCenterResponse
	if err := json.Unmarshal([]byte(out), &batch); err != nil || code != 1 || stderr != "" ||
		started.Load() != 2 || batch.Total != 2 || batch.Observed != 1 ||
		batch.Unknown != 1 || batch.Blocked != 0 || batch.Outcome != "interrupted" ||
		len(batch.Checks) != 2 || batch.Checks[0].Link.ID != slow ||
		batch.Checks[0].Status != "unknown" ||
		batch.Checks[0].ReasonCode != "diagnostic_interrupted" ||
		batch.Checks[0].Observed != nil ||
		batch.Checks[1].Link.ID != snapshot.Links[1].Desired.ID ||
		batch.Checks[1].Status != "observed" ||
		batch.Checks[1].ReasonCode != "link_peer_replied" {
		t.Fatalf("parallel deadline hid sibling or promoted late success: code=%d report=%+v started=%d stderr=%q err=%v",
			code, batch, started.Load(), stderr, err)
	}
}

// Six saved Links are ALL supported: four is only the process/subprocess
// concurrency ceiling. Results remain ordered even though the first four
// can complete in a different order from their Link IDs.
func TestHealthCenterParallelIsBoundedAndAllLinksRemainIndependent(t *testing.T) {
	snapshot := state.EmptySnapshot()
	for i := 1; i <= 6; i++ {
		link := fixtureReadLink(fmt.Sprintf("lnk_%032x", i),
			fmt.Sprintf("10.96.%d.0/31", i), fmt.Sprintf("10.96.%d.1/31", i), domain.BackendGRE)
		snapshot.Upsert(state.LinkRecord{Desired: link})
	}
	started := make(chan domain.LinkID, 6)
	release := make(chan struct{})
	var active, peak atomic.Int32
	deps := healthCenterServices{
		load: func(context.Context) (state.Snapshot, error) { return snapshot, nil },
		observe: func(ctx context.Context, link domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
			n := active.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			defer active.Add(-1)
			started <- link.ID
			select {
			case <-release:
				return parallelHealthMeasured(), nil
			case <-ctx.Done():
				return linkDiagnostic{}, ctx.Err()
			}
		},
	}
	result := make(chan struct{})
	var code int
	var body, stderr string
	root := t.TempDir()
	go func() {
		defer close(result)
		code, body, stderr = executeHealthRemediationTest(
			[]string{"diagnose", "--all", "--parallel", "4", "--timeout", "5s", "--json"},
			&runtimeOptions{stateRoot: root}, deps,
		)
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("worker pool did not start four independent observers")
		}
	}
	select {
	case extra := <-started:
		t.Fatalf("parallel health exceeded its worker cap; extra Link: %s", extra)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	released = true
	select {
	case <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("worker pool did not finish after observers returned")
	}
	var batch healthCenterResponse
	if err := json.Unmarshal([]byte(body), &batch); err != nil || code != 0 || stderr != "" ||
		batch.Outcome != "complete" || batch.Total != 6 || batch.Observed != 6 ||
		batch.Unknown != 0 || batch.Blocked != 0 || len(batch.Checks) != 6 ||
		peak.Load() != maxHealthParallel {
		t.Fatalf("parallel cap/inventory mismatch: code=%d active=%d peak=%d batch=%+v stderr=%q err=%v",
			code, active.Load(), peak.Load(), batch, stderr, err)
	}
	for i, check := range batch.Checks {
		if check.Link.ID != domain.LinkID(fmt.Sprintf("lnk_%032x", i+1)) ||
			check.ReasonCode != "link_peer_replied" || check.Status != "observed" {
			t.Fatalf("completion order corrupted exact Link mapping: i=%d %+v", i, check)
		}
	}
}

// The opt-in must be explicit and unambiguous. No malformed input is
// allowed to launch an unexpected number of host probe subprocesses.
func TestHealthCenterParallelArgumentValidationAndSerialCompatibility(t *testing.T) {
	for _, args := range [][]string{
		{"diagnose", "--all", "--parallel", "0"},
		{"diagnose", "--all", "--parallel", "5"},
		{"diagnose", "--all", "--parallel", "-1"},
		{"diagnose", "--all", "--parallel", "01"},
		{"diagnose", "--all", "--parallel", "foo"},
		{"diagnose", "--all", "--parallel"},
		{"diagnose", "--all", "--parallel", "2", "--parallel", "3"},
	} {
		_, _, _, valid := parseHealthCenterArgs(args)
		if valid {
			t.Fatalf("invalid parallel worker count accepted: %q", args)
		}
	}
	_, _, defaultParallel, valid := parseHealthCenterArgs([]string{"diagnose", "--all", "--json"})
	if !valid || defaultParallel != 1 {
		t.Fatalf("legacy serial contract changed: parallel=%d valid=%t", defaultParallel, valid)
	}
	snapshot := healthRemediationInventory()
	deps := healthCenterServices{
		load: func(context.Context) (state.Snapshot, error) { return snapshot, nil },
		observe: func(context.Context, domain.Link, runtimeOptions) (linkDiagnostic, error) {
			return parallelHealthMeasured(), nil
		},
	}
	first, previousOutput, previousError := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--json"}, &runtimeOptions{stateRoot: t.TempDir()}, deps)
	second, out, stderr := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--parallel", "1", "--json"},
		&runtimeOptions{stateRoot: t.TempDir()}, deps)
	if first != second || previousError != "" || stderr != "" ||
		previousOutput != out || !strings.Contains(out, "link_peer_replied") {
		t.Fatalf("explicit serial mode changed health outcome: first=%d second=%d stderr=%q", first, second, stderr)
	}
}

// Exhausting the total budget must not start an unlimited number of
// observers or omit queued/unstarted Link IDs. A late "healthy" value after
// cancellation cannot be elevated to observed.
func TestHealthCenterParallelDeadlineKeepsEveryUnstartedLinkUnknown(t *testing.T) {
	snapshot := state.EmptySnapshot()
	for i := 1; i <= 6; i++ {
		link := fixtureReadLink(fmt.Sprintf("lnk_%032x", i),
			fmt.Sprintf("10.95.%d.0/31", i), fmt.Sprintf("10.95.%d.1/31", i), domain.BackendGRE)
		snapshot.Upsert(state.LinkRecord{Desired: link})
	}
	var started atomic.Int32
	deps := healthCenterServices{
		load: func(context.Context) (state.Snapshot, error) { return snapshot, nil },
		observe: func(ctx context.Context, _ domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
			started.Add(1)
			<-ctx.Done()
			return parallelHealthMeasured(), nil
		},
	}
	code, out, stderr := executeHealthRemediationTest(
		[]string{"diagnose", "--all", "--parallel", "2", "--timeout", "120ms", "--json"},
		&runtimeOptions{stateRoot: t.TempDir()}, deps,
	)
	var batch healthCenterResponse
	if err := json.Unmarshal([]byte(out), &batch); err != nil || code != 1 || stderr != "" ||
		started.Load() != 2 || batch.Outcome != "interrupted" || batch.Total != 6 ||
		batch.Unknown != 6 || batch.Observed != 0 || batch.Blocked != 0 ||
		len(batch.Checks) != 6 {
		t.Fatalf("parallel timeout lost unstarted links: code=%d started=%d report=%+v stderr=%q err=%v",
			code, started.Load(), batch, stderr, err)
	}
	for i, check := range batch.Checks {
		if check.Link.ID != domain.LinkID(fmt.Sprintf("lnk_%032x", i+1)) ||
			check.Status != "unknown" || check.ReasonCode != "diagnostic_interrupted" ||
			check.Observed != nil {
			t.Fatalf("timed-out worker fabricated health or dropped Link: %+v", check)
		}
	}
}

// The real diagnostic dispatch uses the same bounded shared runner across
// independently owned GRE, IPIP and WireGuard Links. This test exercises the
// entire CLI->backend observation->probe projection, not only the scheduling
// seam. The wrapper protects the original non-thread-safe fake call log.
type lockedHealthRunner struct {
	mu     sync.Mutex
	source *healthRunner
}

func (r *lockedHealthRunner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.source.Run(ctx, name, args...)
}
func TestHealthCenterParallelRealDispatchAndBackendSafeProjection(t *testing.T) {
	root, implementations, fake, links := fixtureHealthCenter(t)
	code, out, stderr := runHealth(t, root, implementations, &lockedHealthRunner{source: fake},
		"--parallel", "4", "--timeout", "5s", "--json")
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(out), &report); err != nil || code != 4 || stderr != "" ||
		report.Outcome != "complete" || report.Total != 4 || report.Observed != 3 ||
		report.Blocked != 1 || report.Unknown != 0 || len(report.Checks) != 4 {
		t.Fatalf("real dispatch broke backend projection: code=%d result=%+v stderr=%q err=%v",
			code, report, stderr, err)
	}
	for i, check := range report.Checks {
		if check.Link.ID != links[i].ID {
			t.Fatalf("parallel real dispatch lost stable Link order: %+v", check)
		}
		if i < 3 && (check.Status != "observed" || check.Observed == nil ||
			check.Observed.Quality.PacketsReceived != 5) {
			t.Fatalf("real parallel diagnostic was not verified: %+v", check)
		}
	}
	if report.Checks[3].ReasonCode != "ipsec_runtime_not_registered" ||
		report.Checks[3].Observed != nil {
		t.Fatal("parallel worker tried activating unregistered IPsec")
	}
	for _, count := range fake.probes {
		if count != 6 {
			t.Fatalf("parallel mode changed bounded Link quality+MTU probe count: %d", count)
		}
	}
	for _, cmd := range fake.commands {
		for _, mutation := range []string{"link add", "link set", "iptables", "route add", "swanctl", "systemctl", "wg set", "modprobe"} {
			if strings.Contains(cmd, mutation) {
				t.Fatalf("parallel diagnostic ran host-changing command: %q", cmd)
			}
		}
	}
}

// PR #156's shared health center must remain semantically correct after
// PR #154 adds the managed-WSS Backend and its own read-only diagnostics.
// An unimplemented active carrier probe is blocked, never "observed"
// because native WireGuard counters happened to be nonzero. It cannot
// consume one of the bounded worker's probe subprocesses.
func TestHealthCenterWSSUsesCarrierAwareObserverNotNativeGuess(t *testing.T) {
	wss := fixtureReadLink("lnk_00000000000000000000000000000001",
		"10.96.10.0/31", "10.96.10.1/31", domain.BackendGRE)
	wss.Backend = domain.BackendWireGuardWSS
	gre := fixtureReadLink("lnk_00000000000000000000000000000002",
		"10.96.20.0/31", "10.96.20.1/31", domain.BackendGRE)
	var nativeCalls, wssCalls atomic.Int32
	checks := healthObserveAll(context.Background(), []domain.Link{wss, gre},
		runtimeOptions{}, true, 2,
		func(_ context.Context, link domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
			switch link.ID {
			case gre.ID:
				nativeCalls.Add(1)
			case wss.ID:
				wssCalls.Add(1)
			default:
				t.Fatal("unexpected Link observation")
			}
			return parallelHealthMeasured(), nil
		})
	if len(checks) != 2 || checks[0].Status != "observed" ||
		checks[0].ReasonCode != "link_peer_replied" || checks[0].Observed == nil ||
		checks[1].Status != "observed" || checks[1].ReasonCode != "link_peer_replied" ||
		nativeCalls.Load() != 1 || wssCalls.Load() != 1 {
		t.Fatalf("carrier-aware five-ping observer was not used for WSS: checks=%+v native=%d wss=%d",
			checks, nativeCalls.Load(), wssCalls.Load())
	}
}
