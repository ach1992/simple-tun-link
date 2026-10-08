package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const testLinkID = domain.LinkID("lnk_00112233445566778899aabbccddeeff")

func diagnosticLink() domain.Link {
	return domain.Link{
		ID: testLinkID, DisplayName: "not-a-credential",
		Backend: domain.BackendGRE, Encapsulation: domain.EncapNative,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("192.0.2.20"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.80.20.0/31"),
			Peer:  netip.MustParsePrefix("10.80.20.1/31"),
		},
	}
}

type thresholdProber struct {
	maxPacket int
	calls     []int
	linkIDs   []domain.LinkID
	err       error
	always    ProbeOutcome
	onSize    func(int, int) (ProbeSample, error)
}

func (p *thresholdProber) Probe(ctx context.Context, link domain.Link, size int) (ProbeSample, error) {
	p.calls = append(p.calls, size)
	p.linkIDs = append(p.linkIDs, link.ID)
	if err := ctx.Err(); err != nil {
		return ProbeSample{}, err
	}
	if p.onSize != nil {
		return p.onSize(size, len(p.calls))
	}
	if p.err != nil {
		return ProbeSample{}, p.err
	}
	if p.always != "" {
		return ProbeSample{Outcome: p.always}, nil
	}
	if size > p.maxPacket {
		return ProbeSample{Outcome: ProbeTooLarge}, nil
	}
	return ProbeSample{Outcome: ProbeReply, RTT: 12 * time.Millisecond}, nil
}

func TestAutoMTUConfirmedUpperBound(t *testing.T) {
	for _, tc := range []struct {
		name               string
		underlay, overhead int
	}{
		{"GRE native candidate", 1500, 24},
		{"encapsulation adapter supplies greater overhead", 1500, 80},
		{"IPv4 absolute maximum", 100000, 20},
		{"minimum allowed IPv4", 88, 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := MTUConstraints{UnderlayMTU: tc.underlay, BackendOverhead: tc.overhead}
			limit := min(tc.underlay-tc.overhead, MaxIPv4MTU)
			probe := &thresholdProber{maxPacket: limit}
			got, err := SelectMTU(context.Background(), diagnosticLink(), c, probe)
			if err != nil {
				t.Fatal(err)
			}
			if got.SelectedMTU != limit || got.CeilingMTU != limit ||
				got.Choice != MTUVerified || !got.Verified || got.Attempts != 1 ||
				got.Mode != "auto" {
				t.Fatalf("confirmed maximum was not selected: %+v", got)
			}
			if !reflect.DeepEqual(probe.calls, []int{limit}) {
				t.Fatalf("unexpected probe call sequence: %v", probe.calls)
			}
		})
	}
}

func TestAutoMTUDiscoversSupportedMaximumWithoutHardcodedEncapsulation(t *testing.T) {
	for _, test := range []struct {
		name                string
		overhead, reachable int
	}{
		{"native GRE", 24, 1420},
		{"FOU-like overhead", 32, 1399},
		{"WireGuard-like overhead", 80, 1388},
		{"constrained path below fallback", 20, 900},
		{"near IPv4 protocol ceiling", 20, 50000},
	} {
		t.Run(test.name, func(t *testing.T) {
			underlay := 1500
			if test.reachable > 1500 {
				underlay = 65000
			}
			probe := &thresholdProber{maxPacket: test.reachable}
			c := MTUConstraints{UnderlayMTU: underlay, BackendOverhead: test.overhead}
			got, err := SelectMTU(context.Background(), diagnosticLink(), c, probe)
			if err != nil {
				t.Fatal(err)
			}
			if got.Choice != MTUVerified || !got.Verified || got.SelectedMTU != test.reachable {
				t.Fatalf("binary search did not find confirmed threshold: %+v", got)
			}
			if got.Attempts != len(probe.calls) || got.Attempts > MaxMTUProbeAttempts {
				t.Fatalf("probe budget violated: %+v %v", got, probe.calls)
			}
			for _, size := range probe.calls {
				if size < MinIPv4MTU || size > got.CeilingMTU {
					t.Fatalf("invalid PMTU probe packet size %d", size)
				}
			}
		})
	}
}

func TestAutoMTUFallbackMustBeExplicitlyUnverified(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prober DFProber
		want   MTUReason
		calls  int
	}{
		{"no adapter", nil, MTUReasonNoProbe, 0},
		{"unsupported", &thresholdProber{always: ProbeUnsupported}, MTUReasonUnsupported, 1},
		{"all timeouts", &thresholdProber{always: ProbeTimeout}, MTUReasonUnreachable, 2},
		{"failed tool", &thresholdProber{err: errors.New("do not leak private key")}, MTUReasonProbeError, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := SelectMTU(context.Background(), diagnosticLink(),
				MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 24}, tc.prober)
			if err != nil {
				t.Fatal(err)
			}
			if result.SelectedMTU != DefaultFallbackMTU || result.Verified ||
				result.Choice != MTUFallback || result.Reason != tc.want ||
				result.Attempts != tc.calls {
				t.Fatalf("missing honest fallback status: %+v", result)
			}
			data, err := json.Marshal(result)
			if err != nil || strings.Contains(string(data), "private key") {
				t.Fatalf("underlying tool error leaked in JSON: %s %v", data, err)
			}
		})
	}
}

func TestNeverSuggestMTUExplicitlyRejectedByFragmentationSignal(t *testing.T) {
	p := &thresholdProber{maxPacket: 420}
	got, err := SelectMTU(context.Background(), diagnosticLink(),
		MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 20}, p)
	if err != nil || got.SelectedMTU != 420 || !got.Verified {
		t.Fatalf("did not reduce past a definitive too-large bound: %+v %v", got, err)
	}
	p = &thresholdProber{always: ProbeTooLarge}
	_, err = SelectMTU(context.Background(), diagnosticLink(),
		MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 20}, p)
	if err == nil || stlerr.CodeOf(err) != stlerr.CodeVerify {
		t.Fatalf("known minimum-MTU rejection falsely produced usable MTU: %v", err)
	}
}

func TestManualOverrideIsUnclampedAndDoesNotProbe(t *testing.T) {
	p := &thresholdProber{maxPacket: 100}
	got, err := SelectMTU(context.Background(), diagnosticLink(),
		MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 52, ManualOverride: 1440}, p)
	if err != nil || got.Mode != "manual" || got.SelectedMTU != 1440 ||
		got.CeilingMTU != 1448 || got.Verified || got.Attempts != 0 || got.Choice != MTUManual {
		t.Fatalf("manual MTU lost intent or claimed validation: %+v %v", got, err)
	}
	if len(p.calls) != 0 {
		t.Fatalf("manual MTU unexpectedly invoked probes: %v", p.calls)
	}
}

func TestInvalidMTUConstraintsAreRejectedBeforeProbe(t *testing.T) {
	tests := []MTUConstraints{
		{},
		{UnderlayMTU: 67},
		{UnderlayMTU: 1500, BackendOverhead: -1},
		{UnderlayMTU: 1500, BackendOverhead: 0},
		{UnderlayMTU: 1500, BackendOverhead: 1500},
		{UnderlayMTU: 1500, BackendOverhead: 1490},
		{UnderlayMTU: 1500, BackendOverhead: 20, ManualOverride: -1},
		{UnderlayMTU: 1500, BackendOverhead: 20, ManualOverride: 1481},
		{UnderlayMTU: 1500, BackendOverhead: 20, ManualOverride: 67},
	}
	for i, c := range tests {
		p := &thresholdProber{maxPacket: 1500}
		_, err := SelectMTU(context.Background(), diagnosticLink(), c, p)
		if err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid || len(p.calls) != 0 {
			t.Fatalf("invalid constraints #%d reached probe or succeeded: %v calls=%v", i, err, p.calls)
		}
	}
	p := &thresholdProber{}
	link := diagnosticLink()
	link.ID = "not-a-Link-ID"
	if _, err := SelectMTU(context.Background(), link, MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 20}, p); err == nil {
		t.Fatal("unvalidated Link identity accepted")
	}
}

func TestContextCancellationHaltsBeforeAnyNetworkProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &thresholdProber{maxPacket: 1500}
	_, err := SelectMTU(ctx, diagnosticLink(), MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 20}, p)
	if !errors.Is(err, context.Canceled) || len(p.calls) != 0 {
		t.Fatalf("canceled request did not stop: %v %v", err, p.calls)
	}
}

func TestProbeErrorsNeverLeakSecretStrings(t *testing.T) {
	p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) {
		switch {
		case n == 1:
			return ProbeSample{Outcome: ProbeTooLarge}, nil
		case n == 2:
			return ProbeSample{Outcome: ProbeReply, RTT: time.Millisecond}, nil
		default:
			return ProbeSample{}, errors.New("secret-token=never-log-this")
		}
	}}
	got, err := SelectMTU(context.Background(), diagnosticLink(),
		MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 24}, p)
	if err != nil || got.Choice != MTUVerified || got.SelectedMTU != 1280 || got.Reason != MTUReasonProbeError {
		t.Fatalf("lost confirmed fallback on later probe tool error: %+v %v", got, err)
	}
	jsonBody, err := json.Marshal(got)
	if err != nil || strings.Contains(string(jsonBody), "secret-token") {
		t.Fatalf("tool error leaked in result: %s %v", jsonBody, err)
	}
}

func TestProbeBudgetAndNoSiblingLinkMutation(t *testing.T) {
	link := diagnosticLink()
	copyLink := link
	p := &thresholdProber{maxPacket: 50500}
	got, err := SelectMTU(context.Background(), link,
		MTUConstraints{UnderlayMTU: 65535, BackendOverhead: 20}, p)
	if err != nil || !got.Verified || got.Attempts > MaxMTUProbeAttempts {
		t.Fatalf("bounded auto probe failed: %+v %v", got, err)
	}
	if link != copyLink {
		t.Fatal("MTU selection mutated requested Link")
	}
	for _, seen := range p.linkIDs {
		if seen != link.ID {
			t.Fatalf("probe touched different/sibling Link: %s", seen)
		}
	}
}

func TestUnderlayConstrainedBelowFallbackCanFindLowerVerifiedMTU(t *testing.T) {
	p := &thresholdProber{maxPacket: 480}
	got, err := SelectMTU(context.Background(), diagnosticLink(),
		MTUConstraints{UnderlayMTU: 900, BackendOverhead: 30}, p)
	if err != nil || !got.Verified || got.SelectedMTU != 480 || got.Attempts > MaxMTUProbeAttempts {
		t.Fatalf("underlay-constrained smaller MTU was not discovered: %+v %v", got, err)
	}
}

func TestMtuProbeHandlesMalformedRepliesAndNilContext(t *testing.T) {
	_, err := SelectMTU(nil, diagnosticLink(), MTUConstraints{UnderlayMTU: 1500}, nil)
	if err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("nil context accepted: %v", err)
	}
	for _, sample := range []ProbeSample{
		{Outcome: "nonsense"},
		{Outcome: ProbeReply, RTT: -time.Millisecond},
	} {
		p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) { return sample, nil }}
		got, err := SelectMTU(context.Background(), diagnosticLink(),
			MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 20}, p)
		if err != nil || got.Choice != MTUFallback || got.Reason != MTUReasonProbeError {
			t.Fatalf("bad probe sample promoted to measured result: %+v %v", got, err)
		}
	}
}

func TestMtuProbeCancelledAfterBackendAttemptDoesNotReturnFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &thresholdProber{onSize: func(size, n int) (ProbeSample, error) {
		cancel()
		return ProbeSample{Outcome: ProbeReply, RTT: time.Millisecond}, nil
	}}
	_, err := SelectMTU(ctx, diagnosticLink(), MTUConstraints{UnderlayMTU: 1500, BackendOverhead: 20}, p)
	if !errors.Is(err, context.Canceled) || len(p.calls) != 1 {
		t.Fatalf("canceled probing returned misleading MTU: %v calls=%v", err, p.calls)
	}
}

func FuzzMTUDecisionBounds(f *testing.F) {
	f.Add(int32(1500), int32(24), int32(1420))
	f.Add(int32(1280), int32(24), int32(800))
	f.Add(int32(88), int32(20), int32(68))
	f.Add(int32(65535), int32(20), int32(50000))
	f.Add(int32(-1), int32(1500), int32(50))
	f.Fuzz(func(t *testing.T, rawUnderlay, rawOverhead, rawReachable int32) {
		underlay, overhead, reachable := int(rawUnderlay), int(rawOverhead), int(rawReachable)
		p := &thresholdProber{maxPacket: reachable}
		choice, err := SelectMTU(context.Background(), diagnosticLink(),
			MTUConstraints{UnderlayMTU: underlay, BackendOverhead: overhead}, p)
		if err != nil {
			code := stlerr.CodeOf(err)
			if code != stlerr.CodeInvalid && code != stlerr.CodeVerify {
				t.Fatalf("unexpected PMTU error: %v", err)
			}
			return
		}
		if choice.CeilingMTU < MinIPv4MTU || choice.CeilingMTU > MaxIPv4MTU ||
			choice.SelectedMTU < MinIPv4MTU || choice.SelectedMTU > choice.CeilingMTU ||
			choice.Attempts > MaxMTUProbeAttempts || choice.Attempts != len(p.calls) {
			t.Fatalf("PMTU result violates bounds: %+v calls=%v", choice, p.calls)
		}
		if choice.Choice == MTUVerified {
			if !choice.Verified || choice.SelectedMTU > reachable {
				t.Fatalf("probe confirmed unreachable packet: %+v max=%d", choice, reachable)
			}
			confirmed := false
			for _, size := range p.calls {
				if size == choice.SelectedMTU {
					confirmed = true
				}
			}
			if !confirmed {
				t.Fatalf("MTU was called confirmed without a matching probe: %+v", choice)
			}
		} else if choice.Verified || choice.Choice != MTUFallback {
			t.Fatalf("unverified fallback falsely measured: %+v", choice)
		}
	})
}
