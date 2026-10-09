package diagnostics

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Report is the v1 diagnostic JSON envelope. There are deliberately no
// credential fields, raw tool logs, process arguments, interface configuration,
// mutable host-state actions or backend-specific secret/counter payloads.
// Concrete backend state/counter adapters will extend this in their own Issues.
type Report struct {
	SchemaVersion int           `json:"schema_version"`
	LinkID        domain.LinkID `json:"link_id"`
	MTU           MTUResult     `json:"mtu"`
	Quality       QualityResult `json:"quality"`
}

// Observe performs only read-only probe calls for exactly the supplied Link.
// No repair/apply capability is in the interface; any later repair action must
// remain explicit through the canonical Engine, not implicit in health checks.
func Observe(ctx context.Context, link domain.Link, constraints MTUConstraints, prober DFProber) (Report, error) {
	mtu, err := SelectMTU(ctx, link, constraints, prober)
	if err != nil {
		return Report{}, err
	}
	quality, err := MeasureQuality(ctx, link, mtu.SelectedMTU, DefaultQualitySamples, prober)
	if err != nil {
		return Report{}, err
	}
	return Report{SchemaVersion: SchemaVersion, LinkID: link.ID, MTU: mtu, Quality: quality}, nil
}

// Summary is a minimal secret-safe operator-facing text derived from the
// exact same versioned result model, not a second probing implementation.
func (r Report) Summary() string {
	selection := "manual; probe confidence not established"
	switch r.MTU.Choice {
	case MTUVerified:
		selection = "probe-confirmed"
	case MTUFallback:
		selection = "conservative estimate; PMTU not confirmed"
	}
	status := "quality unavailable"
	if r.Quality.Status == QualityMeasured && r.Quality.PacketLossPct != nil {
		status = fmt.Sprintf("quality sampled: %d/%d replies, %.1f%% loss",
			r.Quality.PacketsReceived, r.Quality.PacketsSent, *r.Quality.PacketLossPct)
	} else if r.Quality.Status == QualityPartial {
		status = fmt.Sprintf("quality incomplete: %d/%d replies, %s",
			r.Quality.PacketsReceived, r.Quality.PacketsSent, r.Quality.Reason)
	}
	if r.MTU.Reason != MTUReasonNone {
		selection += "; reason=" + string(r.MTU.Reason)
	}
	if r.Quality.Status == QualityUnavailable && r.Quality.Reason != QualityReasonNone {
		status += "; reason=" + string(r.Quality.Reason)
	}
	return fmt.Sprintf("Link %s: suggested inner IPv4 MTU %d (%s; ceiling %d); %s",
		r.LinkID, r.MTU.SelectedMTU, selection, r.MTU.CeilingMTU, status)
}
