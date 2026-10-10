package wireguard

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// DiagnosticState contains only public WireGuard identity, handshake age input,
// and byte counters. Neither private keys nor preshared keys are inspected.
type DiagnosticState struct {
	Interface           string `json:"interface"`
	IfIndex             int    `json:"ifindex"`
	LocalPublicKey      string `json:"local_public_key"`
	PeerPublicKey       string `json:"peer_public_key"`
	ListenPort          uint16 `json:"listen_port"`
	LatestHandshakeUnix int64  `json:"latest_handshake_unix"`
	RXBytes             uint64 `json:"rx_bytes"`
	TXBytes             uint64 `json:"tx_bytes"`
}

// DiagnosticState is read-only. An observed interface must match its exact
// Link ownership/public configuration before exposing any counter readings.
func (b *Backend) DiagnosticState(ctx context.Context, link domain.Link) (DiagnosticState, error) {
	if err := validateLink(link); err != nil {
		return DiagnosticState{}, err
	}
	observed, err := b.Inspect(ctx, link)
	if err != nil {
		return DiagnosticState{}, err
	}
	name, _ := InterfaceName(link.ID)
	target := observed.(observation).Target
	if !target.matches(link, name) {
		return DiagnosticState{}, fmt.Errorf("WireGuard interface identity/configuration is not verified")
	}
	read := func(field string) (string, error) {
		result, err := b.runner.Run(ctx, b.wgBinary, "show", name, field)
		if err != nil {
			return "", fmt.Errorf("cannot read WireGuard public %s status", field)
		}
		return strings.TrimSpace(string(result.Stdout)), nil
	}
	handshake, err := read("latest-handshakes")
	if err != nil {
		return DiagnosticState{}, err
	}
	fields := strings.Fields(handshake)
	if len(fields) != 2 || fields[0] != link.WireGuard.PeerPublicKey {
		return DiagnosticState{}, fmt.Errorf("WireGuard handshake identity mismatch")
	}
	latest, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || latest < 0 {
		return DiagnosticState{}, fmt.Errorf("invalid WireGuard handshake timestamp")
	}
	transfer, err := read("transfer")
	if err != nil {
		return DiagnosticState{}, err
	}
	counts := strings.Fields(transfer)
	if len(counts) != 3 || counts[0] != link.WireGuard.PeerPublicKey {
		return DiagnosticState{}, fmt.Errorf("WireGuard counter identity mismatch")
	}
	rx, err := strconv.ParseUint(counts[1], 10, 64)
	if err != nil {
		return DiagnosticState{}, fmt.Errorf("invalid WireGuard received byte count")
	}
	tx, err := strconv.ParseUint(counts[2], 10, 64)
	if err != nil {
		return DiagnosticState{}, fmt.Errorf("invalid WireGuard transmitted byte count")
	}
	return DiagnosticState{Interface: name, IfIndex: target.IfIndex,
		LocalPublicKey: link.WireGuard.LocalPublicKey, PeerPublicKey: link.WireGuard.PeerPublicKey,
		ListenPort: target.ListenPort, LatestHandshakeUnix: latest, RXBytes: rx, TXBytes: tx}, nil
}
