package linux

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// ErrQUICWGGuardEffectUncertain means the nft transaction may have taken
// effect. Its creator must retain the durable QUIC journal and NEVER delete
// or adopt a same-name guard from readback or marker equivalence alone.
var ErrQUICWGGuardEffectUncertain = errors.New("original QUIC ingress effect uncertain")

// QUICWGIngressHost is the platform adapter passed into the canonical
// Engine. It owns no independent journal, locks, manager or State schema.
type QUICWGIngressHost struct {
	Runner BoundedRunner
}

func (h QUICWGIngressHost) PublishOriginalQUICWGIngress(ctx context.Context, id domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
	if wg.Validate() != nil || wg.PeerPort == 0 {
		return fmt.Errorf("unverified QUIC WireGuard public peer and local identity")
	}
	plan, err := NewQUICWGIngressPlan(id, wg.ListenPort, nonce)
	if err != nil {
		return err
	}
	runner := h.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return publishQUICWGIngressOriginalWithNFT(ctx, runner, plan, wg.LocalPublicKey)
}

// publishQUICWGIngressOriginalWithNFT is only for the initial, held-Engine-lock,
// pre-effect-journal-bound generation. An already present table is ALWAYS
// rejected even if its exact bytes match. A failed/ambiguous transaction is
// quarantined, not undone. This is not a standalone host or Link manager.
func publishQUICWGIngressOriginalWithNFT(ctx context.Context, runner BoundedRunner, plan QUICWGIngressPlan, localPublicKey string) error {
	return publishQUICWGIngressOriginal(ctx, runner, plan, localPublicKey, runQUICWGGuardNFTCreate)
}

func publishQUICWGIngressOriginal(ctx context.Context, runner BoundedRunner, plan QUICWGIngressPlan, localPublicKey string,
	apply func(context.Context, string) error) error {
	if ctx == nil || runner == nil || apply == nil {
		return fmt.Errorf("original QUIC ingress needs a bounded runner and transaction context")
	}
	batch, err := plan.NFTBatch()
	if err != nil || !validWSSWGPublicKey(localPublicKey) {
		return fmt.Errorf("original QUIC guard requires a valid journal-bound WG identity")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// No existing early foreign hook may be bypassed. Later packages must
	// separately verify committed sibling generations before exclusions.
	if err := plan.ProbeQUICWGFirewallCoexistence(ctx, runner); err != nil {
		return fmt.Errorf("original QUIC ingress cannot coexist with current host policy: %w", err)
	}
	occupied, err := InspectWGIngressGuard(ctx, runner, plan)
	if err != nil {
		return fmt.Errorf("original QUIC ingress vacancy unverified: %w", err)
	}
	if occupied {
		return fmt.Errorf("original QUIC ingress table already exists; no same-byte adoption")
	}
	// The journal's historical host vacancy is not sufficient: an unrelated
	// application may have bound this UDP port after its publication. Reuse
	// WSS's complete WG key/port and migrated-socket inspector, plus an
	// additional all-state UDP socket census (connected sockets are not in
	// ss -l). Neither a matching public key nor a same-name process is owned.
	vacant, err := WSSGlobalWGKernelVacant(ctx, runner, "wg", localPublicKey, plan.ListenPort)
	if err != nil || !vacant {
		return fmt.Errorf("original QUIC WG or UDP ingress port vacancy unverified")
	}
	sockets, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10},
		"ss", "-H", "-u", "-a", "-n")
	if err != nil || ctx.Err() != nil || len(sockets.Stdout) > 1<<20 || len(sockets.Stderr) != 0 {
		return fmt.Errorf("original QUIC all-state UDP socket census unavailable")
	}
	ports, err := parseUDPListeners(string(sockets.Stdout))
	if err != nil {
		return fmt.Errorf("original QUIC all-state UDP socket census malformed")
	}
	if _, occupied := ports[plan.ListenPort]; occupied {
		return fmt.Errorf("original QUIC UDP ingress port already occupied")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// NFTBatch starts with 'create table': never 'add table' or 'flush'.
	// Kernel transaction is atomic and rejects a concurrent name collision.
	// An error/timeout AFTER attempting dispatch does not establish absence.
	if err := apply(ctx, batch); err != nil {
		return ErrQUICWGGuardEffectUncertain
	}
	// A successful ACK plus strict immediate readback is the one-time
	// positive original creation witness, not a durable recovery permit.
	present, err := InspectWGIngressGuard(ctx, runner, plan)
	if err != nil || !present {
		return ErrQUICWGGuardEffectUncertain
	}
	return nil
}

func runQUICWGGuardNFTCreate(ctx context.Context, batch string) error {
	if ctx == nil || len(batch) == 0 || len(batch) > 4096 {
		return fmt.Errorf("invalid original QUIC nft transaction")
	}
	scoped, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(scoped, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	// No shell, argv secrets, or raw foreign stderr in ordinary errors.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("original QUIC nft transaction outcome unavailable")
	}
	return nil
}
