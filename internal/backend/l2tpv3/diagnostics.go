package l2tpv3

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

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

func (b *Backend) Capability(ctx context.Context, l domain.Link) (linux.CapabilityStatus, error) {
	if err := validLink(l); err != nil {
		return linux.CapabilityStatus{}, err
	}
	if _, err := b.runner.Run(ctx, b.ip, "-json", "l2tp", "show", "tunnel"); err != nil {
		if ctx.Err() != nil {
			return linux.CapabilityStatus{}, ctx.Err()
		}
		if b.moduleProbe(ctx, "l2tp_ip") || b.moduleProbe(ctx, "l2tp_eth") {
			return linux.CapabilityStatus{Reason: "L2TPv3 kernel modules are loadable but not active", ReasonCode: "kernel_module_not_loaded"}, nil
		}
		return linux.CapabilityStatus{Reason: "L2TPv3 Direct-IP kernel/netlink query unavailable", ReasonCode: "l2tpv3_probe_unconfirmed"}, nil
	}
	if _, err := b.runner.Run(ctx, b.ip, "-json", "l2tp", "show", "session"); err != nil {
		return linux.CapabilityStatus{Reason: "L2TPv3 session kernel query unavailable", ReasonCode: "l2tpv3_session_probe_unconfirmed"}, nil
	}
	return linux.CapabilityStatus{Available: true}, nil
}
func (b *Backend) DiagnosticState(ctx context.Context, l domain.Link) (DiagnosticState, error) {
	raw, err := b.Inspect(ctx, l)
	if err != nil {
		return DiagnosticState{}, err
	}
	o := raw.(observation)
	if !o.matches(l) {
		return DiagnosticState{}, fmt.Errorf("L2TPv3 exact owned kernel state or peer neighbor not verified")
	}
	res, err := b.runner.Run(ctx, b.ip, "-statistics", "-json", "link", "show", "dev", o.id.name)
	if err != nil {
		return DiagnosticState{}, fmt.Errorf("L2TPv3 interface counter query failed: %w", err)
	}
	var rows []struct {
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
	if err := json.Unmarshal(res.Stdout, &rows); err != nil || len(rows) != 1 || rows[0].IfIndex != o.iface.IfIndex || rows[0].IfName != o.id.name {
		return DiagnosticState{}, fmt.Errorf("L2TPv3 interface counter identity is inconsistent")
	}
	row := rows[0]
	return DiagnosticState{
		Interface: o.id.name, IfIndex: o.iface.IfIndex, Encapsulation: l.Encapsulation,
		RXPackets: row.Stats64.RX.Packets, RXBytes: row.Stats64.RX.Bytes, RXErrors: row.Stats64.RX.Errors,
		TXPackets: row.Stats64.TX.Packets, TXBytes: row.Stats64.TX.Bytes, TXErrors: row.Stats64.TX.Errors,
	}, nil
}
