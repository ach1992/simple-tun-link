package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Model the maximum supported slow preflight with a virtual clock, avoiding
// multi-minute CI sleeps. Even if the entire per-Link diagnosis, version
// check, benchmark and non-probe reserve are consumed, the parent cannot
// expire before the benchmark's own bounded subprocess window ends.
func TestThroughputBudgetCoversSlowPreflightAndFullBenchmark(t *testing.T) {
	for _, seconds := range []int{1, defaultThroughputSeconds, maxThroughputSeconds} {
		start := time.Unix(0, 0)
		parentDeadline := start.Add(throughputOperationBudget(seconds))
		// The non-probe reserve also covers locks and the two state reads.
		diagnosedAt := start.Add(throughputPreparationReserve + diagnoseOperationTimeout)
		versionCheckedAt := diagnosedAt.Add(throughputVersionBudget)
		benchmarkDoneAt := versionCheckedAt.Add(time.Duration(seconds)*time.Second + throughputBenchmarkOverhead)
		if benchmarkDoneAt.Add(throughputCompletionReserve).After(parentDeadline) ||
			parentDeadline.Sub(versionCheckedAt) < time.Duration(seconds)*time.Second+
				throughputBenchmarkOverhead+throughputCompletionReserve {
			t.Fatalf("slow diagnostic preflight steals benchmark allowance: seconds=%d parent=%s needs=%s",
				seconds, throughputOperationBudget(seconds), benchmarkDoneAt.Sub(start))
		}
		// Detect a regression to the previous 40s+duration cap.
		if throughputOperationBudget(seconds) <= 40*time.Second+time.Duration(seconds)*time.Second {
			t.Fatalf("parent timeout still has the R2 4-second deficit: seconds=%d", seconds)
		}
	}
}

type slowedThroughputProbeRunner struct {
	*throughputPreflightRunner
	childBudgets []time.Duration
}

func (r *slowedThroughputProbeRunner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "env" {
		if deadline, ok := ctx.Deadline(); ok {
			r.childBudgets = append(r.childBudgets, time.Until(deadline))
		}
		select {
		case <-time.After(4 * time.Millisecond):
		case <-ctx.Done():
			return linux.CommandResult{}, ctx.Err()
		}
	}
	return r.throughputPreflightRunner.Run(ctx, name, args...)
}

type throughputDeadlineSpyTool struct {
	*throughputFakeTool
	versionBudget, benchmarkBudget time.Duration
}

func (s *throughputDeadlineSpyTool) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if len(args) == 1 && args[0] == "--version" {
			s.versionBudget = time.Until(deadline)
		} else {
			s.benchmarkBudget = time.Until(deadline)
		}
	}
	return s.throughputFakeTool.RunBounded(ctx, limits, name, args...)
}

func TestThroughputSlowActualPreflightPreservesBenchmarkChildBudget(t *testing.T) {
	_, link, opts, rawTool, route := fixtureThroughput(t)
	slow := &slowedThroughputProbeRunner{throughputPreflightRunner: route}
	tool := &throughputDeadlineSpyTool{throughputFakeTool: rawTool}
	opts.probeRunner = slow
	opts.throughputRunner = tool

	id := string(link.ID)
	code, body, errOut := callThroughput([]string{"link", "throughput", id, "--confirm", id, "--seconds", "3", "--json"}, opts)
	if code != 0 || errOut != "" || rawTool.calls != 1 || rawTool.versionCalls != 1 ||
		!strings.Contains(body, "\"operation\":\"link_throughput\"") {
		t.Fatalf("valid slow-preflight throughput did not finish: code=%d body=%q err=%q", code, body, errOut)
	}
	// One MTU attempt + five actual Linux quality probes, with the same
	// child execution budgets as the standalone read-only diagnostic.
	if len(slow.childBudgets) != 6 || slow.childBudgets[0] < 850*time.Millisecond {
		t.Fatalf("diagnostic preflight not fully exercised: %v", slow.childBudgets)
	}
	for _, b := range slow.childBudgets[1:] {
		if b < 1800*time.Millisecond {
			t.Fatalf("quality did not retain the two-second process allowance: %v", slow.childBudgets)
		}
	}
	if tool.versionBudget < throughputVersionBudget-200*time.Millisecond ||
		tool.benchmarkBudget < time.Duration(3)*time.Second+throughputBenchmarkOverhead-200*time.Millisecond {
		t.Fatalf("valid preflight reduced phase budgets: version=%s benchmark=%s", tool.versionBudget, tool.benchmarkBudget)
	}
	var measured linkThroughputResult
	if err := json.Unmarshal([]byte(body), &measured); err != nil || measured.ReceivedMbps != 9.9 {
		t.Fatalf("valid scoped iperf3 output not measured: %+v error=%v", measured, err)
	}
}

// Explicitly fire a parent DeadlineExceeded only when the requested phase
// has been reached. Unlike a fragile 50ms global timer, contention before
// this stage cannot invalidate what the test intends to prove.
type controlledThroughputDeadline struct {
	context.Context
	once sync.Once
	done chan struct{}
}

func newControlledThroughputDeadline() *controlledThroughputDeadline {
	return &controlledThroughputDeadline{Context: context.Background(), done: make(chan struct{})}
}

func (p *controlledThroughputDeadline) Done() <-chan struct{} { return p.done }
func (p *controlledThroughputDeadline) Err() error {
	select {
	case <-p.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}
func (p *controlledThroughputDeadline) expire() { p.once.Do(func() { close(p.done) }) }

type throughputExpiresDuringPreflight struct {
	*throughputPreflightRunner
	parent *controlledThroughputDeadline
}

func (r *throughputExpiresDuringPreflight) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "env" {
		r.parent.expire()
		<-ctx.Done()
		return linux.CommandResult{}, ctx.Err()
	}
	return r.throughputPreflightRunner.Run(ctx, name, args...)
}

func TestThroughputParentExpiresDuringPreflightWithoutStartingTraffic(t *testing.T) {
	_, link, opts, tool, route := fixtureThroughput(t)
	parent := newControlledThroughputDeadline()
	opts.probeRunner = &throughputExpiresDuringPreflight{throughputPreflightRunner: route, parent: parent}

	var out, errOut strings.Builder
	id := string(link.ID)
	code := linkThroughputWithContext(parent, []string{"throughput", id, "--confirm", id, "--json"}, &out, &errOut, opts)
	if code == 0 || !strings.Contains(out.String(), "throughput_identity_unverified") ||
		tool.calls != 0 || tool.versionCalls != 0 || strings.Contains(out.String(), "sent_mbps") {
		t.Fatalf("expired preflight initiated traffic or fabricated output: code=%d out=%q err=%q calls=%d/%d",
			code, out.String(), errOut.String(), tool.versionCalls, tool.calls)
	}
}

type throughputExpiresDuringBenchmark struct {
	*throughputFakeTool
	parent *controlledThroughputDeadline
}

func (f *throughputExpiresDuringBenchmark) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	result, err := f.throughputFakeTool.RunBounded(ctx, limits, name, args...)
	if len(args) > 1 {
		// Simulate a late but superficially valid iperf3 JSON response from
		// a subprocess whose parent operation has actually expired.
		f.parent.expire()
		<-ctx.Done()
	}
	return result, err
}

func TestThroughputParentExpiryCannotPublishLateBenchmarkMetrics(t *testing.T) {
	_, link, opts, rawTool, _ := fixtureThroughput(t)
	parent := newControlledThroughputDeadline()
	opts.throughputRunner = &throughputExpiresDuringBenchmark{throughputFakeTool: rawTool, parent: parent}
	var out, errOut strings.Builder
	id := string(link.ID)
	code := linkThroughputWithContext(parent, []string{"throughput", id, "--confirm", id, "--json"}, &out, &errOut, opts)
	if code == 0 || rawTool.versionCalls != 1 || rawTool.calls != 1 ||
		!strings.Contains(out.String(), "throughput_interrupted") ||
		strings.Contains(out.String(), "sent_mbps") || strings.Contains(out.String(), "received_mbps") {
		t.Fatalf("expired operation presented incomplete benchmark as measured: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

// A successfully parsed version banner is not authorization to start the
// network client if the operation expired during the version subprocess.
type throughputExpiresDuringVersion struct {
	*throughputFakeTool
	parent *controlledThroughputDeadline
}

func (f *throughputExpiresDuringVersion) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	result, err := f.throughputFakeTool.RunBounded(ctx, limits, name, args...)
	if len(args) == 1 && args[0] == "--version" {
		f.parent.expire()
		<-ctx.Done()
	}
	return result, err
}

func TestThroughputParentExpiryDuringVersionNeverStartsClient(t *testing.T) {
	_, link, opts, rawTool, _ := fixtureThroughput(t)
	parent := newControlledThroughputDeadline()
	opts.throughputRunner = &throughputExpiresDuringVersion{throughputFakeTool: rawTool, parent: parent}
	var out, errOut strings.Builder
	id := string(link.ID)
	code := linkThroughputWithContext(parent, []string{"throughput", id, "--confirm", id, "--json"}, &out, &errOut, opts)
	if code == 0 || rawTool.versionCalls != 1 || rawTool.calls != 0 ||
		!strings.Contains(out.String(), "throughput_interrupted") ||
		strings.Contains(out.String(), "sent_mbps") {
		t.Fatalf("expired tool version check started benchmark: code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}
