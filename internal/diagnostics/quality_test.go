package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestQualityMeasurementLatencyLossAndConsecutiveJitter(t *testing.T) {
	responses := []ProbeSample{
		{Outcome: ProbeReply, RTT: 10 * time.Millisecond},
		{Outcome: ProbeReply, RTT: 20 * time.Millisecond},
		{Outcome: ProbeTimeout},
		{Outcome: ProbeReply, RTT: 30 * time.Millisecond},
		{Outcome: ProbeReply, RTT: 50 * time.Millisecond},
	}
	p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) {
		if size != normalProbePacketSize {
			t.Fatalf("quality sent MTU-sized packet instead of small packet: %d", size)
		}
		return responses[n-1], nil
	}}
	got, err := MeasureQuality(context.Background(), diagnosticLink(), 1420, 5, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != QualityMeasured || got.ProbeCalls != 5 || got.PacketsSent != 5 || got.PacketsReceived != 4 ||
		got.PacketLossPct == nil || *got.PacketLossPct != 20 || !got.Reachable {
		t.Fatalf("sample accounting wrong: %+v", got)
	}
	if got.MinRTTMs == nil || *got.MinRTTMs != 10 || got.MaxRTTMs == nil || *got.MaxRTTMs != 50 ||
		got.AvgRTTMs == nil || *got.AvgRTTMs != 27.5 || got.JitterMs == nil || *got.JitterMs != 15 {
		t.Fatalf("RTT/jitter calculation wrong: %+v", got)
	}
	for _, id := range p.linkIDs {
		if id != testLinkID {
			t.Fatalf("wrong link probed: %v", p.linkIDs)
		}
	}
}

func TestQualityAllLossNotMistakenForHealthy(t *testing.T) {
	p := &thresholdProber{always: ProbeTimeout}
	got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, 0, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != QualityMeasured || got.PacketsSent != DefaultQualitySamples ||
		got.PacketsReceived != 0 || got.Reachable || got.PacketLossPct == nil ||
		*got.PacketLossPct != 100 || got.AvgRTTMs != nil || got.JitterMs != nil {
		t.Fatalf("all-loss quality incorrectly healthy: %+v", got)
	}
}

func TestQualityUnavailableUsesNullLossAndRTT(t *testing.T) {
	got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != QualityUnavailable || got.PacketsSent != 0 || got.PacketLossPct != nil ||
		got.AvgRTTMs != nil || got.Reason != QualityReasonNoProbe {
		t.Fatalf("no adapter wrongly measured: %+v", got)
	}
	body, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(body), "\"packet_loss_pct\":null") {
		t.Fatalf("unavailable packet loss must be null: %s %v", body, err)
	}
}

func TestQualityPartialToolErrorDoesNotCountAsLostPacket(t *testing.T) {
	p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) {
		if n == 1 {
			return ProbeSample{Outcome: ProbeReply, RTT: time.Millisecond}, nil
		}
		return ProbeSample{}, errors.New("private_key=must-not-leak")
	}}
	got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, 5, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != QualityPartial || got.PacketsSent != 1 || got.PacketsReceived != 1 ||
		got.ProbeCalls != 2 || got.PacketLossPct == nil || *got.PacketLossPct != 0 ||
		got.Reason != QualityReasonProbeError {
		t.Fatalf("tool error misclassified as packet loss: %+v", got)
	}
	body, err := json.Marshal(got)
	if err != nil || strings.Contains(string(body), "private_key") {
		t.Fatalf("tool error leaked: %s %v", body, err)
	}
}

func TestQualityFragmentationIsNotAPacketLoss(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior_reply_%t", first), func(t *testing.T) {
			p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) {
				if n == 1 && first {
					return ProbeSample{Outcome: ProbeReply, RTT: 3 * time.Millisecond}, nil
				}
				return ProbeSample{Outcome: ProbeTooLarge}, nil
			}}
			got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, 5, p)
			if err != nil {
				t.Fatal(err)
			}
			wantSent := 0
			wantStatus := QualityUnavailable
			if first {
				wantSent = 1
				wantStatus = QualityPartial
			}
			if got.Status != wantStatus || got.PacketsSent != wantSent || got.Reason != QualityReasonTooLarge ||
				got.ProbeCalls != wantSent+1 {
				t.Fatalf("local fragmentation counted as transmitted loss: %+v", got)
			}
		})
	}
}

func TestQualityZeroRTTIsValidButUnknownJitterRemainsNull(t *testing.T) {
	p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) {
		if size != MinIPv4MTU {
			t.Fatalf("quality exceeded low selected MTU: %d", size)
		}
		return ProbeSample{Outcome: ProbeReply, RTT: 0}, nil
	}}
	got, err := MeasureQuality(context.Background(), diagnosticLink(), MinIPv4MTU, 1, p)
	if err != nil || got.AvgRTTMs == nil || *got.AvgRTTMs != 0 ||
		got.JitterMs != nil || got.PacketLossPct == nil || *got.PacketLossPct != 0 {
		t.Fatalf("zero RTT or jitter null incorrect: %+v %v", got, err)
	}
}

func TestQualityUnsupportedAndInvalidSamplesRemainUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sample ProbeSample
		reason QualityReason
	}{
		{"unsupported", ProbeSample{Outcome: ProbeUnsupported}, QualityReasonUnsupported},
		{"unknown status", ProbeSample{Outcome: "undefined"}, QualityReasonProbeError},
		{"negative RTT", ProbeSample{Outcome: ProbeReply, RTT: -time.Second}, QualityReasonProbeError},
		{"RTT beyond deadline", ProbeSample{Outcome: ProbeReply, RTT: 9 * time.Second}, QualityReasonProbeError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) { return tc.sample, nil }}
			got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, 3, p)
			if err != nil || got.Status != QualityUnavailable || got.Reason != tc.reason ||
				got.PacketsSent != 0 || got.PacketLossPct != nil {
				t.Fatalf("untrusted sample treated as measured: %+v %v", got, err)
			}
		})
	}
}

func TestQualityValidationsBoundedCallsAndCancellation(t *testing.T) {
	for _, tc := range []struct{ mtu, count int }{{67, 5}, {65536, 5}, {1400, -1}, {1400, MaxQualitySamples + 1}} {
		p := &thresholdProber{maxPacket: 1500}
		_, err := MeasureQuality(context.Background(), diagnosticLink(), tc.mtu, tc.count, p)
		if err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid || len(p.calls) != 0 {
			t.Fatalf("invalid quality request accepted: %+v %v", tc, err)
		}
	}
	p := &thresholdProber{maxPacket: 1500}
	got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, MaxQualitySamples, p)
	if err != nil || got.ProbeCalls != MaxQualitySamples {
		t.Fatalf("quality exceeded probe cap: %+v %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.calls = nil
	_, err = MeasureQuality(ctx, diagnosticLink(), 1400, 5, p)
	if !errors.Is(err, context.Canceled) || len(p.calls) != 0 {
		t.Fatalf("canceled quality still ran: %v %v", err, p.calls)
	}
}

func TestQualityToolDeadlineIsNotRealPacketLoss(t *testing.T) {
	p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) { return ProbeSample{}, context.DeadlineExceeded }}
	got, err := MeasureQuality(context.Background(), diagnosticLink(), 1400, 3, p)
	if err != nil || got.PacketsSent != 0 || got.PacketLossPct != nil ||
		got.Status != QualityUnavailable || got.Reason != QualityReasonProbeError {
		t.Fatalf("tool deadline was counted as packet loss: %+v %v", got, err)
	}
}

func TestObserveVersionedSecretSafeAndReadOnly(t *testing.T) {
	link := diagnosticLink()
	link.DisplayName = "private_key=NEVER_INCLUDE_THIS"
	original := link
	p := &thresholdProber{maxPacket: 1400}
	report, err := Observe(context.Background(), link, MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 24}, p)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != SchemaVersion || report.LinkID != link.ID ||
		report.MTU.Choice != MTUVerified || report.MTU.SelectedMTU != 1400 ||
		report.Quality.Status != QualityMeasured || !report.Quality.Reachable {
		t.Fatalf("inaccurate diagnostic report: %+v", report)
	}
	if original != link {
		t.Fatal("diagnostics mutated the Link")
	}
	for _, id := range p.linkIDs {
		if id != link.ID {
			t.Fatalf("sibling Link probed: %s", id)
		}
	}
	body, err := json.Marshal(report)
	if err != nil || !strings.Contains(string(body), "\"schema_version\":1") ||
		!strings.Contains(string(body), "\"link_id\":\"lnk_") ||
		strings.Contains(string(body), "private_key") {
		t.Fatalf("machine output not versioned/secret-safe: %s %v", body, err)
	}
	summary := report.Summary()
	if !strings.Contains(summary, "probe-confirmed") || !strings.Contains(summary, string(link.ID)) ||
		strings.Contains(summary, "private_key") {
		t.Fatalf("human output not safe: %s", summary)
	}
}

func TestObserveUnavailableDoesNotFakeHealthOrMTU(t *testing.T) {
	report, err := Observe(context.Background(), diagnosticLink(), MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 48}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.MTU.Choice != MTUFallback || report.MTU.Verified ||
		report.Quality.Status != QualityUnavailable || report.Quality.PacketLossPct != nil {
		t.Fatalf("probe-free diagnostics lied: %+v", report)
	}
	summary := report.Summary()
	if !strings.Contains(summary, "conservative estimate") || !strings.Contains(summary, "quality unavailable") {
		t.Fatalf("human summary falsely measured: %s", summary)
	}
}

func TestSummaryMatchesManualAndPartialMachineModel(t *testing.T) {
	loss := 50.0
	q := QualityResult{Status: QualityPartial, PacketsSent: 2, PacketsReceived: 1, Reason: QualityReasonProbeError, PacketLossPct: &loss}
	report := Report{SchemaVersion: SchemaVersion, LinkID: testLinkID, MTU: MTUResult{Choice: MTUManual, Mode: "manual", SelectedMTU: 1300, CeilingMTU: 1476}, Quality: q}
	summary := report.Summary()
	if !strings.Contains(summary, "manual") || !strings.Contains(summary, "quality incomplete") ||
		!strings.Contains(summary, fmt.Sprint(q.Reason)) {
		t.Fatalf("human and JSON disagree: %q", summary)
	}
	body, err := json.Marshal(report)
	if err != nil || strings.Contains(string(body), "secret") || !strings.Contains(string(body), "\"packet_loss_pct\":50") {
		t.Fatalf("machine report wrong: %s %v", body, err)
	}
}

func TestQualityRejectsInvalidLinkWithoutProbe(t *testing.T) {
	link := diagnosticLink()
	link.ID = domain.LinkID("bad")
	p := &thresholdProber{maxPacket: 1400}
	_, err := MeasureQuality(context.Background(), link, 1400, 5, p)
	if err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid || len(p.calls) != 0 {
		t.Fatalf("invalid Link reached adapter: %v %v", err, p.calls)
	}
}
