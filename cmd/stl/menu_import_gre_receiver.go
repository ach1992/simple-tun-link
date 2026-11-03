package main

import (
	"context"
	"io"
	"net/netip"
	"time"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

// A decoded Setup Link declares a receiver address, not a trusted recipient
// identity. A bounded LOCAL address inventory can disprove a receiver match,
// but even an assigned address cannot authenticate the sender or the offer.
type greImportReceiverStatus uint8

const (
	greReceiverUnverified greImportReceiverStatus = iota
	greReceiverAssigned
	greReceiverNotAssigned
	greReceiverAmbiguous
)

func inspectGREImportReceiver(ctx context.Context, runner linux.Runner, receiver string) greImportReceiverStatus {
	ip, err := netip.ParseAddr(receiver)
	if err != nil || !ip.Is4() {
		return greReceiverUnverified
	}
	endpoints, err := linux.ListLocalIPv4Endpoints(ctx, runner)
	if err != nil {
		return greReceiverUnverified
	}
	count := 0
	for _, endpoint := range endpoints {
		if endpoint.Address == ip {
			count++
		}
	}
	switch count {
	case 0:
		return greReceiverNotAssigned
	case 1:
		return greReceiverAssigned
	default:
		return greReceiverAmbiguous
	}
}

// Operator-only preflight. The canonical Engine independently rechecks
// local ownership and resources under its lock before any mutation.
func reviewGREImportReceiver(out io.Writer, runner linux.Runner, receiver string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch inspectGREImportReceiver(ctx, runner, receiver) {
	case greReceiverAssigned:
		menuHealthLine(out, "Receiver on THIS host", "OK", "Receiver IPv4 assigned to exactly one local interface")
		menuProse(out, "This local observation does not verify the sender's endpoint, the offer's intended recipient or remote reachability. Verify BOTH endpoint IPs on the source server.")
		return true
	case greReceiverNotAssigned:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 is not assigned to THIS server.")
		menuProse(out, "This may be a Setup Link for another receiver or an incorrect endpoint. Verify BOTH server IPs on the source server, then create/share a fresh Setup Link for this receiver. No import was attempted.")
	case greReceiverAmbiguous:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 appears on multiple local interfaces.")
		menuProse(out, "Inspect ip -json address show and correct the ambiguous assignment before importing. This does not prove which receiver was intended. No import was attempted.")
	default:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 could not be verified on this server.")
		menuProse(out, "Local read-only inventory is unavailable or incomplete; this does NOT prove a wrong recipient. Inspect ip -json address show, verify this server's assigned receiver IPv4 and retry. No import was attempted.")
	}
	return false
}
