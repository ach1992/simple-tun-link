package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Setup Link endpoint fields describe configuration, not a trusted recipient.
// Use the same bounded local binding classifier as Engine backends. A match
// never authenticates the sender, intended receiver or peer connectivity.
type importReceiverStatus uint8

const (
	importReceiverUnverified importReceiverStatus = iota
	importReceiverAssigned
	importReceiverNotAssigned
	importReceiverAmbiguous
)

// inspectLocalReceiverBinding is read-only and shared by interactive Import,
// machine CLI Import, and their redacted diagnostic projection. It performs
// neither credential staging nor Engine/State initialization.
func inspectLocalReceiverBinding(ctx context.Context, runner linux.Runner, ip netip.Addr) error {
	if !ip.Is4() {
		return errors.New("configured local receiver IPv4 unavailable")
	}
	endpoints, err := linux.ListLocalIPv4Endpoints(ctx, runner)
	if err != nil {
		return err
	}
	_, err = linux.BoundLocalIPv4(endpoints, ip, "")
	return err
}

func inspectImportReceiver(ctx context.Context, runner linux.Runner, receiver string) importReceiverStatus {
	ip, err := netip.ParseAddr(receiver)
	if err != nil {
		return importReceiverUnverified
	}
	err = inspectLocalReceiverBinding(ctx, runner, ip)
	switch {
	case err == nil:
		return importReceiverAssigned
	case errors.Is(err, linux.ErrUnderlayLocalNotAssigned):
		return importReceiverNotAssigned
	case errors.Is(err, linux.ErrUnderlayLocalAmbiguous):
		return importReceiverAmbiguous
	default:
		return importReceiverUnverified
	}
}

// lockedImportReceiverAdmission uses exactly the same read-only bounded
// classifier as the early CLI/menu check, but executes under canonical
// Engine locks at the first protected publication boundary. The runner is
// local to this import invocation, never stored globally on the Engine.
func lockedImportReceiverAdmission(opts *runtimeOptions) app.ReceiverAdmission {
	runner := createRunner(opts)
	return func(ctx context.Context, link domain.Link) error {
		return inspectLocalReceiverBinding(ctx, runner, link.Underlay.Local)
	}
}

// The CLI must not stage a protected key, pending intent or TLS bundle before
// receiver assignment is independently admitted. Engine Plan/Validate MUST
// still re-check under locks: this preflight does not remove the TOCTOU gate.
// It applies to Import only, never to offline/host-independent Preview or
// protected sender-side Resume of an already staged original.
func admitCLIImportReceiver(out, errOut io.Writer, jsonOutput bool, operation string,
	desired domain.Link, opts *runtimeOptions) (bool, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := inspectLocalReceiverBinding(ctx, createRunner(opts), desired.Underlay.Local)
	if err == nil {
		return true, 0
	}
	observed := stlerr.LocalUnderlayUnverified("import_receiver_admission",
		string(desired.ID), string(desired.Backend), err)
	rc := lifecycleFailureWithEvidence(out, errOut, jsonOutput, stlerr.CodePlan,
		operation, nil,
		"Receiver local IPv4 was not verified; no new protected credential, State, or host Apply was attempted",
		preflightEvidence(), observed)
	return false, rc
}

// Shared read-only preflight for ALL interactive Setup Link Import methods.
// IPsec NAT-T also requires the configured LOCAL underlay to be assigned to
// this host; NAT's translated public peer address is not that local binding.
// Canonical Engine Plan/Validate independently rechecks it before host Apply.
func reviewImportReceiver(out io.Writer, runner linux.Runner, receiver string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch inspectImportReceiver(ctx, runner, receiver) {
	case importReceiverAssigned:
		menuHealthLine(out, "Receiver on THIS host", "OK", "Receiver IPv4 assigned to exactly one local interface")
		menuProse(out, "This local assignment does not verify the sender's endpoint, the offer's intended recipient or remote reachability. Verify BOTH endpoint IPs on the source server.")
		return true
	case importReceiverNotAssigned:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 is not assigned to THIS server.")
		menuProse(out, "This may target another server or use a wrong local endpoint. Even with NAT-T, the LOCAL underlay must be assigned here, not merely translated to a public IP. Inspect ip -json address show, verify BOTH endpoints on the sender, then share a corrected Setup Link. No import was attempted.")
	case importReceiverAmbiguous:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 appears on multiple local interfaces.")
		menuProse(out, "Inspect ip -json address show and correct the ambiguous assignment before importing. This does not prove which receiver was intended. No import was attempted.")
	default:
		menuNotice(out, "WARNING", "The Setup Link's receiver IPv4 could not be verified on this server.")
		menuProse(out, "Local read-only inventory is unavailable or incomplete; this does NOT prove a wrong recipient. Inspect ip -json address show, verify this server's assigned receiver IPv4 and retry. No import was attempted.")
	}
	return false
}
