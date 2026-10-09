// Package diagnostics owns the backend-neutral observational MTU/PMTU
// decision and short link-quality model for Issue #9. It never modifies a
// Link, device, route, firewall, backend or systemd service.
package diagnostics

import (
	"context"
	"errors"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const (
	SchemaVersion       = 1
	MinIPv4MTU          = 68
	MaxIPv4MTU          = 65535
	DefaultFallbackMTU  = 1280
	MaxMTUProbeAttempts = 18
	probeAttemptTimeout = time.Second
)

// ProbeOutcome distinguishes an observed reply, an actual fragmentation/
// packet-too-large rejection, a timeout, and an unavailable probe facility.
// A timeout is NOT evidence of a size-specific PMTU ceiling.
type ProbeOutcome string

const (
	ProbeReply       ProbeOutcome = "reply"
	ProbeTooLarge    ProbeOutcome = "too_large"
	ProbeTimeout     ProbeOutcome = "timeout"
	ProbeUnsupported ProbeOutcome = "unsupported"
)

type ProbeSample struct {
	Outcome ProbeOutcome
	RTT     time.Duration
}

// DFProber tests the remote LINK ADDRESS, not the public underlay address.
// packetBytes is the total INNER IPv4 datagram length, including IPv4 and
// ICMP headers. An iputils ping adapter must subtract 28 bytes for -s
// (20 IPv4 + 8 ICMP). ProbeReply requires an actual observed ICMP reply;
// ProbeTooLarge requires a definitive size/fragmentation rejection.
//
// Adapters must honor context deadlines and must never change network state.
// Real Linux probe adapters are implemented only with backend integration.
type DFProber interface {
	Probe(context.Context, domain.Link, int) (ProbeSample, error)
}

// BackendOverhead is supplied by the selected backend and includes outer IP
// and encapsulation bytes, and must be positive (unknown/zero overhead
// must fail closed). It must not be guessed by this common algorithm:
// GRE, FOU, GUE, WireGuard and IPsec can have different overhead.
type MTUConstraints struct {
	UnderlayMTU     int
	BackendOverhead int
	ManualOverride  int // 0=Auto, any other value requests Manual.
}

type MTUChoice string

const (
	MTUManual   MTUChoice = "manual"
	MTUVerified MTUChoice = "probe_confirmed"
	MTUFallback MTUChoice = "conservative_fallback"
)

type MTUReason string

const (
	MTUReasonNone        MTUReason = ""
	MTUReasonNoProbe     MTUReason = "probe_adapter_unavailable"
	MTUReasonUnsupported MTUReason = "probe_unsupported"
	MTUReasonUnreachable MTUReason = "no_confirmed_reachability"
	MTUReasonProbeError  MTUReason = "probe_error"
	MTUReasonProbeLimit  MTUReason = "probe_limit_reached"
)

// MTUResult separates confidence from the proposed MTU. A fallback is NOT
// a verified path MTU. Callers must not advertise or apply it as measured.
type MTUResult struct {
	Mode        string    `json:"mode"`
	Choice      MTUChoice `json:"choice"`
	SelectedMTU int       `json:"selected_mtu"`
	CeilingMTU  int       `json:"ceiling_mtu"`
	Attempts    int       `json:"probe_attempts"`
	Verified    bool      `json:"verified"`
	Reason      MTUReason `json:"reason,omitempty"`
}

func mtuCeiling(c MTUConstraints) (int, error) {
	if c.UnderlayMTU < MinIPv4MTU || c.BackendOverhead <= 0 || c.BackendOverhead > c.UnderlayMTU {
		return 0, stlerr.New(stlerr.CodeInvalid, "diagnostics_mtu", "", "", "invalid underlay MTU or encapsulation overhead")
	}
	ceiling := c.UnderlayMTU - c.BackendOverhead
	if ceiling > MaxIPv4MTU {
		ceiling = MaxIPv4MTU
	}
	if ceiling < MinIPv4MTU {
		return 0, stlerr.New(stlerr.CodeInvalid, "diagnostics_mtu", "", "", "encapsulation leaves no viable IPv4 Link MTU")
	}
	return ceiling, nil
}

// SelectMTU chooses the highest probe-confirmed candidate it has observed,
// or an explicitly unverified conservative fallback. It probes at most
// MaxMTUProbeAttempts times, uses a child timeout for each attempt, and
// never conflates packet loss with a confirmed TooLarge result.
func SelectMTU(ctx context.Context, link domain.Link, c MTUConstraints, prober DFProber) (MTUResult, error) {
	if ctx == nil {
		return MTUResult{}, stlerr.New(stlerr.CodeInvalid, "diagnostics_mtu", "", "", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return MTUResult{}, err
	}
	if err := link.Validate(); err != nil {
		return MTUResult{}, stlerr.Wrap(stlerr.CodeInvalid, "diagnostics_mtu", "", "", "invalid Link", err)
	}
	ceiling, err := mtuCeiling(c)
	if err != nil {
		return MTUResult{}, err
	}
	r := MTUResult{Mode: "auto", Choice: MTUFallback, CeilingMTU: ceiling}
	fallback := min(DefaultFallbackMTU, ceiling)
	r.SelectedMTU = fallback
	if c.ManualOverride != 0 {
		if c.ManualOverride < MinIPv4MTU || c.ManualOverride > ceiling {
			return MTUResult{}, stlerr.New(stlerr.CodeInvalid, "diagnostics_mtu", string(link.ID), string(link.Backend), "manual MTU is outside the underlay/encapsulation range")
		}
		r.Mode, r.Choice, r.SelectedMTU = "manual", MTUManual, c.ManualOverride
		return r, nil
	}
	if prober == nil {
		r.Reason = MTUReasonNoProbe
		return r, nil
	}

	// Keep the strongest confirmed lower bound and smallest proven TooLarge.
	good, smallestTooLarge := 0, ceiling+1
	probe := func(size int) (ProbeOutcome, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if r.Attempts >= MaxMTUProbeAttempts {
			return ProbeTimeout, nil
		}
		callCtx, cancel := context.WithTimeout(ctx, probeAttemptTimeout)
		sample, callErr := prober.Probe(callCtx, link, size)
		exceeded := errors.Is(callCtx.Err(), context.DeadlineExceeded)
		cancel()
		r.Attempts++
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if callErr != nil {
			if exceeded || errors.Is(callErr, context.DeadlineExceeded) {
				return ProbeTimeout, nil
			}
			r.Reason = MTUReasonProbeError
			return ProbeUnsupported, nil
		}
		if exceeded {
			return ProbeTimeout, nil
		}
		switch sample.Outcome {
		case ProbeReply:
			if sample.RTT < 0 {
				r.Reason = MTUReasonProbeError
				return ProbeUnsupported, nil
			}
			return ProbeReply, nil
		case ProbeTooLarge, ProbeTimeout:
			return sample.Outcome, nil
		case ProbeUnsupported:
			r.Reason = MTUReasonUnsupported
			return ProbeUnsupported, nil
		default:
			r.Reason = MTUReasonProbeError
			return ProbeUnsupported, nil
		}
	}

	// Fast path: an actual DF reply at the allowed ceiling.
	top, err := probe(ceiling)
	if err != nil {
		return MTUResult{}, err
	}
	if top == ProbeReply {
		r.Choice, r.SelectedMTU, r.Verified = MTUVerified, ceiling, true
		return r, nil
	}
	if top == ProbeUnsupported {
		return r, nil
	}
	if top == ProbeTooLarge {
		smallestTooLarge = ceiling
	}
	if ceiling == MinIPv4MTU {
		if top == ProbeTooLarge {
			return MTUResult{}, stlerr.New(stlerr.CodeVerify, "diagnostics_mtu", string(link.ID), string(link.Backend), "path rejected the minimum IPv4 MTU")
		}
		r.Reason = MTUReasonUnreachable
		return r, nil
	}

	low, high := MinIPv4MTU, ceiling-1
	if fallback != ceiling {
		base, err := probe(fallback)
		if err != nil {
			return MTUResult{}, err
		}
		switch base {
		case ProbeReply:
			good, low = fallback, fallback+1
		case ProbeTooLarge:
			smallestTooLarge = min(smallestTooLarge, fallback)
			high = fallback - 1
		case ProbeTimeout:
			r.Reason = MTUReasonUnreachable
			return r, nil
		case ProbeUnsupported:
			return r, nil
		}
	} else if top == ProbeTimeout {
		r.Reason = MTUReasonUnreachable
		return r, nil
	}

	for low <= high && r.Attempts < MaxMTUProbeAttempts {
		mid := low + (high-low+1)/2
		outcome, err := probe(mid)
		if err != nil {
			return MTUResult{}, err
		}
		switch outcome {
		case ProbeReply:
			good, low = max(good, mid), mid+1
		case ProbeTooLarge:
			smallestTooLarge = min(smallestTooLarge, mid)
			high = mid - 1
		case ProbeTimeout:
			high = mid - 1 // Unknown quality; do not claim it was too-large.
		case ProbeUnsupported:
			high = low - 1 // Preserve existing reachable lower bound.
		}
	}
	if good > 0 {
		r.Choice, r.Verified, r.SelectedMTU = MTUVerified, true, good
		if low <= high && r.Attempts >= MaxMTUProbeAttempts {
			r.Reason = MTUReasonProbeLimit
		}
		return r, nil
	}
	if smallestTooLarge <= MinIPv4MTU {
		return MTUResult{}, stlerr.New(stlerr.CodeVerify, "diagnostics_mtu", string(link.ID), string(link.Backend), "path rejected the minimum IPv4 MTU")
	}
	// Never deliberately suggest a size proven to be too large.
	r.SelectedMTU = min(fallback, smallestTooLarge-1)
	if r.SelectedMTU < MinIPv4MTU {
		return MTUResult{}, stlerr.New(stlerr.CodeVerify, "diagnostics_mtu", string(link.ID), string(link.Backend), "no viable Link MTU available")
	}
	if r.Reason == MTUReasonNone {
		if r.Attempts >= MaxMTUProbeAttempts {
			r.Reason = MTUReasonProbeLimit
		} else {
			r.Reason = MTUReasonUnreachable
		}
	}
	return r, nil
}
