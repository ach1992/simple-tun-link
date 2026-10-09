package ipip

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// DiagnosticState is the backend-specific, secret-free state/counter view used
// by common diagnostics. It is observational and cannot mutate or repair a Link.
type DiagnosticState struct {
	Interface     string               `json:"interface"`
	IfIndex       int                  `json:"ifindex"`
	Encapsulation domain.Encapsulation `json:"encapsulation"`
	RXPackets     uint64               `json:"rx_packets"`
	RXBytes       uint64               `json:"rx_bytes"`
	RXErrors      uint64               `json:"rx_errors"`
	TXPackets     uint64               `json:"tx_packets"`
	TXBytes       uint64               `json:"tx_bytes"`
	TXErrors      uint64               `json:"tx_errors"`
}

func (b *Backend) Capability(ctx context.Context, link domain.Link) (linux.CapabilityStatus, error) {
	if err := validateLink(link); err != nil {
		return linux.CapabilityStatus{}, err
	}
	if _, err := b.runner.Run(ctx, b.ipBinary, "-details", "-json", "link", "show", "type", "ipip"); err != nil {
		if ctx.Err() != nil {
			return linux.CapabilityStatus{}, ctx.Err()
		}
		return linux.CapabilityStatus{Reason: "IPIP link type is unavailable"}, nil
	}
	if link.Encapsulation == domain.EncapFOU || link.Encapsulation == domain.EncapGUE {
		if _, err := b.runner.Run(ctx, b.ipBinary, "-json", "fou", "show"); err != nil {
			if ctx.Err() != nil {
				return linux.CapabilityStatus{}, ctx.Err()
			}
			return linux.CapabilityStatus{Reason: "IPIP FOU/GUE support is unavailable"}, nil
		}
	}
	return linux.CapabilityStatus{Available: true}, nil
}

func (b *Backend) DiagnosticState(ctx context.Context, link domain.Link) (DiagnosticState, error) {
	observed, err := b.Inspect(ctx, link)
	if err != nil {
		return DiagnosticState{}, err
	}
	state := observed.(observation).Target
	name, err := InterfaceName(link.ID)
	if err != nil {
		return DiagnosticState{}, err
	}
	if !state.matches(link, name) {
		return DiagnosticState{}, fmt.Errorf("IPIP Link is not in the requested operational state")
	}
	result, err := b.runner.Run(ctx, b.ipBinary, "-s", "-json", "link", "show", "dev", name)
	if err != nil {
		return DiagnosticState{}, fmt.Errorf("read IPIP counters: %w", err)
	}
	counters, err := parseCounters(result.Stdout, name, state.IfIndex)
	if err != nil {
		return DiagnosticState{}, err
	}
	counters.Encapsulation = link.Encapsulation
	return counters, nil
}

type counterJSON struct {
	IfIndex int    `json:"ifindex"`
	IfName  string `json:"ifname"`
	Stats64 struct {
		RX struct {
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
			Errors  uint64 `json:"errors"`
		} `json:"rx"`
		TX struct {
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
			Errors  uint64 `json:"errors"`
		} `json:"tx"`
	} `json:"stats64"`
}

func parseCounters(raw []byte, name string, ifindex int) (DiagnosticState, error) {
	var rows []counterJSON
	if err := json.Unmarshal(raw, &rows); err != nil {
		return DiagnosticState{}, fmt.Errorf("parse IPIP counters: %w", err)
	}
	if len(rows) != 1 || rows[0].IfName != name || rows[0].IfIndex != ifindex {
		return DiagnosticState{}, fmt.Errorf("IPIP counter identity changed during observation")
	}
	row := rows[0]
	return DiagnosticState{
		Interface: name, IfIndex: ifindex,
		RXPackets: row.Stats64.RX.Packets, RXBytes: row.Stats64.RX.Bytes, RXErrors: row.Stats64.RX.Errors,
		TXPackets: row.Stats64.TX.Packets, TXBytes: row.Stats64.TX.Bytes, TXErrors: row.Stats64.TX.Errors,
	}, nil
}
