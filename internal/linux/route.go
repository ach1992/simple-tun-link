package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Route describes the kernel-selected path toward one concrete peer. Source is
// the address STL should treat as the local underlay candidate for that peer.
type Route struct {
	Peer    netip.Addr
	Source  netip.Addr
	Device  string
	Gateway netip.Addr
	MTU     int // Optional route-specific PMTU; zero means unspecified.
}

type RouteResolver struct {
	Runner   Runner
	IPBinary string
}

type ipRoute struct {
	Destination string       `json:"dst"`
	Gateway     string       `json:"gateway"`
	Device      string       `json:"dev"`
	Preferred   string       `json:"prefsrc"`
	Source      string       `json:"src"`
	MTU         int          `json:"mtu"`
	Metrics     routeMetrics `json:"metrics"`
}

// iproute2 returns metrics as either an object or a singleton array.
// Both shapes are local kernel route metadata, not proof of remote reachability.
type routeMetrics struct{ MTU int }

func (m *routeMetrics) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return fmt.Errorf("empty route metrics")
	}
	if raw[0] == '[' {
		var rows []routeMetrics
		if err := json.Unmarshal(raw, &rows); err != nil {
			return fmt.Errorf("invalid route metrics array: %w", err)
		}
		if len(rows) != 1 {
			return fmt.Errorf("route metrics must have exactly one entry")
		}
		*m = rows[0]
		return nil
	}
	var row struct {
		MTU int `json:"mtu"`
	}
	if raw[0] != '{' {
		return fmt.Errorf("invalid route metrics shape")
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return fmt.Errorf("invalid route metrics object: %w", err)
	}
	m.MTU = row.MTU
	return nil
}

// Resolve asks the kernel for the route to the actual peer instead of guessing
// from the default interface or consulting an external public-IP service.
func (r RouteResolver) Resolve(ctx context.Context, peer netip.Addr) (Route, error) {
	if r.Runner == nil {
		return Route{}, fmt.Errorf("route resolver runner is required")
	}
	if !peer.IsValid() || peer.IsUnspecified() {
		return Route{}, fmt.Errorf("valid peer address is required")
	}

	binary := r.IPBinary
	if binary == "" {
		binary = "ip"
	}
	family := "-4"
	if peer.Is6() {
		family = "-6"
	}
	result, err := r.Runner.Run(ctx, binary, family, "-json", "route", "get", peer.String())
	if err != nil {
		return Route{}, fmt.Errorf("route lookup failed: %w", err)
	}

	var rows []ipRoute
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return Route{}, fmt.Errorf("parse route lookup JSON: %w", err)
	}
	if len(rows) != 1 {
		return Route{}, fmt.Errorf("route lookup returned %d entries, want exactly 1", len(rows))
	}
	row := rows[0]
	if strings.TrimSpace(row.Device) == "" || strings.ContainsAny(row.Device, "\r\n\x00") {
		return Route{}, fmt.Errorf("route lookup did not return a valid device")
	}

	sourceText := strings.TrimSpace(row.Preferred)
	if sourceText == "" {
		sourceText = strings.TrimSpace(row.Source)
	}
	if sourceText == "" {
		return Route{}, fmt.Errorf("route lookup did not return a source address")
	}
	source, err := netip.ParseAddr(sourceText)
	if err != nil {
		return Route{}, fmt.Errorf("parse route source address: %w", err)
	}
	if source.BitLen() != peer.BitLen() {
		return Route{}, fmt.Errorf("route source address family does not match peer")
	}

	var gateway netip.Addr
	if gatewayText := strings.TrimSpace(row.Gateway); gatewayText != "" {
		gateway, err = netip.ParseAddr(gatewayText)
		if err != nil {
			return Route{}, fmt.Errorf("parse route gateway address: %w", err)
		}
		if gateway.BitLen() != peer.BitLen() {
			return Route{}, fmt.Errorf("route gateway address family does not match peer")
		}
	}

	if row.MTU < 0 || row.Metrics.MTU < 0 {
		return Route{}, fmt.Errorf("route lookup reported an invalid MTU")
	}
	mtu := row.MTU
	if row.Metrics.MTU > 0 && (mtu == 0 || row.Metrics.MTU < mtu) {
		mtu = row.Metrics.MTU
	}
	return Route{
		MTU:     mtu,
		Peer:    peer,
		Source:  source,
		Device:  row.Device,
		Gateway: gateway,
	}, nil
}
