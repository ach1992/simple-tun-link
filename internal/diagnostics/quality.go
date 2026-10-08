package diagnostics

import (
	"context"
	"errors"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const (
	DefaultQualitySamples = 5
	MaxQualitySamples     = 10
	normalProbePacketSize = 84 // IPv4 20 + ICMP 8 + default ICMP echo data 56.
)

type QualityStatus string

const (
	QualityMeasured    QualityStatus = "measured"
	QualityUnavailable QualityStatus = "unavailable"
	QualityPartial     QualityStatus = "partial"
)

type QualityReason string

const (
	QualityReasonNone        QualityReason = ""
	QualityReasonNoProbe     QualityReason = "probe_adapter_unavailable"
	QualityReasonUnsupported QualityReason = "probe_unsupported"
	QualityReasonProbeError  QualityReason = "probe_error"
	QualityReasonTooLarge    QualityReason = "small_packet_too_large"
)

// QualityResult is intentionally secret-free and distinguishes "no valid RTT"
// from a legitimate zero-millisecond measurement by using nullable metrics.
//
// JitterMs is the mean absolute difference between consecutive SUCCESSFUL
// RTTs, resetting after a failed probe. It is a short diagnostic variation
// estimate, not RFC 3550 RTP jitter.
type QualityResult struct {
	Status          QualityStatus `json:"status"`
	ProbeCalls      int           `json:"probe_calls"`
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	PacketLossPct   *float64      `json:"packet_loss_pct"`
	Reachable       bool          `json:"reachable"`
	MinRTTMs        *float64      `json:"min_rtt_ms"`
	AvgRTTMs        *float64      `json:"avg_rtt_ms"`
	MaxRTTMs        *float64      `json:"max_rtt_ms"`
	JitterMs        *float64      `json:"jitter_ms"`
	Reason          QualityReason `json:"reason,omitempty"`
}

// MeasureQuality takes a small number of observational per-Link probes using
// a normal-sized inner IPv4 packet (up to the known selected Link MTU).
// Unsupported/error outcomes do not masquerade as 100% packet loss;
// ordinary ProbeTimeout means an actual attempted probe without a reply.
func MeasureQuality(ctx context.Context, link domain.Link, selectedMTU, count int, prober DFProber) (QualityResult, error) {
	if ctx == nil {
		return QualityResult{}, stlerr.New(stlerr.CodeInvalid, "diagnostics_quality", "", "", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return QualityResult{}, err
	}
	if err := link.Validate(); err != nil {
		return QualityResult{}, stlerr.Wrap(stlerr.CodeInvalid, "diagnostics_quality", "", "", "invalid Link", err)
	}
	if selectedMTU < MinIPv4MTU || selectedMTU > MaxIPv4MTU {
		return QualityResult{}, stlerr.New(stlerr.CodeInvalid, "diagnostics_quality", string(link.ID), string(link.Backend), "invalid Link MTU for quality probing")
	}
	if count == 0 {
		count = DefaultQualitySamples
	}
	if count < 1 || count > MaxQualitySamples {
		return QualityResult{}, stlerr.New(stlerr.CodeInvalid, "diagnostics_quality", string(link.ID), string(link.Backend), "quality sample count exceeds diagnostic limit")
	}
	out := QualityResult{Status: QualityUnavailable}
	if prober == nil {
		out.Reason = QualityReasonNoProbe
		return out, nil
	}
	packetSize := min(normalProbePacketSize, selectedMTU)
	var sumRTT time.Duration
	var minRTT, maxRTT time.Duration
	var previous time.Duration
	var hasPrevious bool
	var jitterSum time.Duration
	var jitterPairs int

	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return QualityResult{}, err
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeAttemptTimeout)
		sample, callErr := prober.Probe(probeCtx, link, packetSize)
		exceeded := errors.Is(probeCtx.Err(), context.DeadlineExceeded)
		cancel()
		out.ProbeCalls++
		if err := ctx.Err(); err != nil {
			return QualityResult{}, err
		}
		if callErr != nil || exceeded {
			// A tool/context failure is NOT evidence that an ICMP echo was
			// transmitted and lost. Only an explicit adapter ProbeTimeout
			// outcome is counted as packet loss.
			if out.PacketsSent != 0 {
				out.Status = QualityPartial
			}
			out.Reason = QualityReasonProbeError
			break
		}
		if sample.Outcome == ProbeUnsupported || (sample.Outcome != ProbeReply &&
			sample.Outcome != ProbeTimeout && sample.Outcome != ProbeTooLarge) ||
			(sample.Outcome == ProbeReply && (sample.RTT < 0 || sample.RTT > probeAttemptTimeout)) {
			if out.PacketsSent != 0 {
				out.Status = QualityPartial
			}
			if sample.Outcome == ProbeUnsupported {
				out.Reason = QualityReasonUnsupported
			} else {
				out.Reason = QualityReasonProbeError
			}
			break
		}
		if sample.Outcome == ProbeTooLarge {
			// A local fragmentation rejection is a diagnostic failure,
			// not a transmitted packet, and cannot become packet loss.
			if out.PacketsSent != 0 {
				out.Status = QualityPartial
			}
			out.Reason = QualityReasonTooLarge
			break
		}
		out.PacketsSent++
		switch sample.Outcome {
		case ProbeReply:
			out.PacketsReceived++
			if out.PacketsReceived == 1 || sample.RTT < minRTT {
				minRTT = sample.RTT
			}
			if sample.RTT > maxRTT {
				maxRTT = sample.RTT
			}
			sumRTT += sample.RTT
			if hasPrevious {
				delta := sample.RTT - previous
				if delta < 0 {
					delta = -delta
				}
				jitterSum += delta
				jitterPairs++
			}
			previous, hasPrevious = sample.RTT, true
		case ProbeTimeout:
			hasPrevious = false
		}
	}
	if out.PacketsSent > 0 {
		if out.Status != QualityPartial {
			out.Status = QualityMeasured
		}
		loss := float64(out.PacketsSent-out.PacketsReceived) * 100 / float64(out.PacketsSent)
		out.PacketLossPct = &loss
	}
	if out.PacketsReceived > 0 {
		out.Reachable = true
		minMS := durationMilliseconds(minRTT)
		maxMS := durationMilliseconds(maxRTT)
		avgMS := durationMilliseconds(sumRTT) / float64(out.PacketsReceived)
		out.MinRTTMs, out.MaxRTTMs, out.AvgRTTMs = &minMS, &maxMS, &avgMS
	}
	if jitterPairs != 0 {
		jitterMS := durationMilliseconds(jitterSum) / float64(jitterPairs)
		out.JitterMs = &jitterMS
	}
	return out, nil
}

func durationMilliseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
