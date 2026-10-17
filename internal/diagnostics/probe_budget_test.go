package diagnostics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// The default 18-attempt worst-case MTU binary search (upper limit 65515,
// threshold 1280) is followed by five normal-sized quality probes. Each fake
// probe is deliberately slow enough to exercise the composed phases without
// making CI wait for real network/process deadlines.
type qualityBudgetProber struct {
	mtuBudget     []time.Duration
	qualityBudget []time.Duration
}

func (p *qualityBudgetProber) Probe(ctx context.Context, _ domain.Link, size int) (ProbeSample, error) {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		return ProbeSample{}, errors.New("probe child had no bounded deadline")
	}
	remaining := time.Until(deadline)
	if size != normalProbePacketSize {
		p.mtuBudget = append(p.mtuBudget, remaining)
		time.Sleep(3 * time.Millisecond)
		if size > DefaultFallbackMTU {
			return ProbeSample{Outcome: ProbeTooLarge}, nil
		}
		return ProbeSample{Outcome: ProbeReply, RTT: time.Millisecond}, nil
	}
	p.qualityBudget = append(p.qualityBudget, remaining)
	time.Sleep(3 * time.Millisecond)
	switch len(p.qualityBudget) {
	case 2, 4:
		return ProbeSample{Outcome: ProbeTimeout}, nil
	default:
		return ProbeSample{Outcome: ProbeReply, RTT: 50 * time.Millisecond}, nil
	}
}

func TestSeparateProbeBudgetsCompleteDefaultMixedFiveSamples(t *testing.T) {
	// The parent budget includes the worst-case MTU and quality allowances,
	// and a separate allowance for preflight. No network interfaces are used.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultDiagnosticProbeBudget+7*time.Second)
	defer cancel()
	prober := &qualityBudgetProber{}
	result, err := Observe(ctx, diagnosticLink(), MTUConstraints{UnderlayMTU: 65535, BackendOverhead: 20}, prober)
	if err != nil {
		t.Fatal(err)
	}
	if DefaultDiagnosticProbeBudget != 28*time.Second {
		t.Fatalf("default MTU + five-sample budget exceeds the expected bound: %s", DefaultDiagnosticProbeBudget)
	}
	if len(prober.mtuBudget) != MaxMTUProbeAttempts ||
		result.MTU.Attempts != MaxMTUProbeAttempts || !result.MTU.Verified ||
		result.MTU.SelectedMTU != DefaultFallbackMTU {
		t.Fatalf("worst-case MTU budget was not exercised: budget=%v result=%+v", prober.mtuBudget, result.MTU)
	}
	for _, budget := range prober.mtuBudget {
		if budget < mtuProbeAttemptTimeout-250*time.Millisecond || budget > mtuProbeAttemptTimeout {
			t.Fatalf("MTU probe did not use the original one-second child budget: %s", budget)
		}
	}
	if len(prober.qualityBudget) != DefaultQualitySamples {
		t.Fatalf("quality did not run all five samples: %v", prober.qualityBudget)
	}
	for _, budget := range prober.qualityBudget {
		if budget < qualityProbeAttemptTimeout-250*time.Millisecond || budget > qualityProbeAttemptTimeout {
			t.Fatalf("quality probe did not receive the two-second child budget: %s", budget)
		}
	}
	q := result.Quality
	if q.Status != QualityMeasured || q.Reason != QualityReasonNone ||
		q.ProbeCalls != 5 || q.PacketsSent != 5 || q.PacketsReceived != 3 ||
		q.PacketLossPct == nil || *q.PacketLossPct != 40 || !q.Reachable {
		t.Fatalf("valid missed probes must count as loss without interrupting five-sample accounting: %+v", q)
	}
}

// A real parent deadline supersedes either child budget. Cancellation must
// not be reclassified as a completed no-reply packet or a healthy report.
type parentExpiryProber struct {
	calls int
}

func (p *parentExpiryProber) Probe(ctx context.Context, _ domain.Link, size int) (ProbeSample, error) {
	p.calls++
	if size != normalProbePacketSize {
		return ProbeSample{Outcome: ProbeReply, RTT: time.Millisecond}, nil
	}
	<-ctx.Done()
	return ProbeSample{}, ctx.Err()
}

func TestParentDeadlineInterruptsQualityWithoutInventingPacketLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p := &parentExpiryProber{}
	report, err := Observe(ctx, diagnosticLink(), MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 24}, p)
	if !errors.Is(err, context.DeadlineExceeded) || report != (Report{}) || p.calls != 2 {
		t.Fatalf("parent cancellation fabricated a quality result or continued probes: report=%+v calls=%d err=%v", report, p.calls, err)
	}
}
