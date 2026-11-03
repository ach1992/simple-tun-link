package main

import (
	"context"
	"io"
	"net/netip"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Setup Link endpoints describe configuration, not a trusted recipient
// identity. A bounded local address inventory can disprove local assignment;
// a match never proves who the sender intended to contact.
type importReceiverStatus uint8

const (
	importReceiverUnverified importReceiverStatus = iota
	importReceiverAssigned
	importReceiverNotAssigned
	importReceiverAmbiguous
)

func inspectImportReceiver(ctx context.Context, runner linux.Runner, receiver string) importReceiverStatus {
	ip, err := netip.ParseAddr(receiver)
	if err != nil || !ip.Is4() {
		return importReceiverUnverified
	}
	endpoints, err := linux.ListLocalIPv4Endpoints(ctx, runner)
	if err != nil {
		return importReceiverUnverified
	}
	count := 0
	for _, endpoint := range endpoints {
		if endpoint.Address == ip {
			count++
		}
	}
	switch count {
	case 0:
		return importReceiverNotAssigned
	case 1:
		return importReceiverAssigned
	default:
		return importReceiverAmbiguous
	}
}

// This preflight is shared by plaintext and protected interactive Import.
// It is never a substitute for canonical Engine Plan/ownership checks.
// IPsec/NAT-T can legitimately use an externally translated IKE address,
// so an absent public address is an explicit warning, NOT authenticated proof
// of a wrong receiver or permission to override protected service admission.
func reviewImportReceiver(out io.Writer, runner linux.Runner, receiver string, backend domain.Backend, encap domain.Encapsulation) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	natAware := backend == domain.BackendIPsec && encap == domain.EncapNATT
	switch inspectImportReceiver(ctx, runner, receiver) {
	case importReceiverAssigned:
		menuHealthLine(out, "Receiver on THIS host", "OK", "Receiver IPv4 assigned to exactly one local interface")
		menuProse(out, "This local assignment does not verify the sender's endpoint, the offer's intended recipient or remote reachability. Verify BOTH endpoint IPs on the source server.")
		return true
	case importReceiverNotAssigned:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 is not assigned to THIS server.")
		if natAware {
			menuProse(out, "IPsec/NAT-T may use a translated public endpoint. Verify the real receiver, NAT mapping and BOTH endpoint IPs on the sender BEFORE confirming. An unassigned public IP alone does not prove a wrong recipient.")
			return true
		}
		menuProse(out, "This may be a Setup Link for another receiver or an incorrect endpoint. Verify BOTH server IPs on the source server, then create/share a fresh Setup Link for this receiver. No import was attempted.")
	case importReceiverAmbiguous:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 appears on multiple local interfaces.")
		menuProse(out, "Inspect ip -json address show and correct the ambiguous assignment before importing. This does not prove which receiver was intended. No import was attempted.")
	default:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 could not be verified on this server.")
		if natAware {
			menuProse(out, "Local read-only inventory is unavailable or incomplete. This does NOT prove a wrong IPsec recipient; independently verify both endpoints and any NAT mapping before approving import.")
			return true
		}
		menuProse(out, "Local read-only inventory is unavailable or incomplete; this does NOT prove a wrong recipient. Inspect ip -json address show, verify this server's assigned receiver IPv4 and retry. No import was attempted.")
	}
	return false
}
