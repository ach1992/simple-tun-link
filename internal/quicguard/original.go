// Package quicguard contains only the first QUIC nft ingress host effect.
// It deliberately owns no Link manager, State schema, credentials or runtime
// restore machinery: every effect is admitted synchronously by the Engine.
package quicguard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// errEffectUncertain means the nft transaction may have taken effect. The
// durable QUIC journal and any possible guard MUST remain quarantined. It
// never grants adoption, retirement or retry permission after crash/reboot.
var errEffectUncertain = errors.New("original QUIC nft ingress effect uncertain")

// StageOriginal is the only exported initial QUIC nft host writer. No caller
// can supply a fake publisher, runner, plan, journal, nonce, executable or
// success witness. The canonical Engine re-attests original material while
// holding maintenance, Link and resource locks through *both* actual nft
// dispatch and post-effect strict readback. There is no CLI/runtime caller.
func StageOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID) error {
	return stageOriginal(ctx, engine, id, linux.ExecRunner{}, runOriginalNFTCreate)
}

// Internal test seam: production always chooses the actual Linux command
// runner and nft create implementation. A simulated callback is never a
// production success/ownership witness.
func stageOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID,
	runner linux.BoundedRunner, apply func(context.Context, string) error) error {
	if engine == nil || runner == nil || apply == nil {
		return fmt.Errorf("original QUIC nft requires canonical Engine and fixed Linux dispatch")
	}
	return engine.WithQUICCrashIngressAdmission(ctx, id,
		func(c context.Context, journalID domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
			return publishOriginal(c, runner, journalID, nonce, wg, apply)
		})
}

// publishOriginal has package-private effect authority: it must be reached
// only from StageOriginal's exact Engine admission callback in production.
// Unit tests call it with an injected nft effect to explore error edges;
// production exports no equivalent direct host-effect method or interface.
func publishOriginal(ctx context.Context, runner linux.BoundedRunner,
	id domain.LinkID, nonce string, wg domain.WireGuardOptions,
	apply func(context.Context, string) error) error {
	return publishOriginalWithNetworkNS(ctx, runner, id, nonce, wg, apply, currentNetworkNamespace)
}

// Package-private namespace-read seam for deterministic failure tests only.
// StageOriginal always uses the real calling-thread namespace reader.
func publishOriginalWithNetworkNS(ctx context.Context, runner linux.BoundedRunner,
	id domain.LinkID, nonce string, wg domain.WireGuardOptions,
	apply func(context.Context, string) error, readNetworkNS func() (string, error)) error {
	if ctx == nil || runner == nil || apply == nil || readNetworkNS == nil || wg.Validate() != nil || wg.PeerPort == 0 {
		return fmt.Errorf("original QUIC ingress requires valid Engine-owned WG identity and host inputs")
	}
	// All preflight readers, the exclusive CREATE and strict readback must
	// execute in one network namespace. In Go, network namespaces are
	// OS-thread-scoped; a process-level /proc/self label is insufficient.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originalNS, err := readNetworkNS()
	if err != nil || !validNetworkNamespaceID(originalNS) {
		return fmt.Errorf("original QUIC ingress network namespace unverified")
	}
	plan, err := linux.NewQUICWGIngressPlan(id, wg.ListenPort, nonce)
	if err != nil {
		return fmt.Errorf("invalid journal-bound QUIC ingress identity")
	}
	batch, err := plan.NFTBatch()
	if err != nil {
		return fmt.Errorf("invalid original QUIC ingress nft plan")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// A matching name/marker is not authority. A foreign early hook or a
	// truncated or diagnostic-bearing inventory forbids new host effects.
	if err := plan.ProbeQUICWGFirewallCoexistence(ctx, runner); err != nil {
		return fmt.Errorf("original QUIC ingress cannot coexist with current host policy: %w", err)
	}
	occupied, err := linux.InspectWGIngressGuard(ctx, runner, plan)
	if err != nil {
		return fmt.Errorf("original QUIC ingress table vacancy unverified: %w", err)
	}
	if occupied {
		return fmt.Errorf("original QUIC ingress table already exists: no foreign adoption")
	}

	// The historical pre-effect journal's vacancy is not an authorization
	// at dispatch time. Recheck visible WG keys/listen ports, migrated WG
	// sockets and all-state UDP sockets (including connected sockets).
	vacant, err := linux.WSSGlobalWGKernelVacant(ctx, runner, "wg", wg.LocalPublicKey, wg.ListenPort)
	if err != nil || !vacant {
		return fmt.Errorf("current QUIC WireGuard/UDP ingress vacancy unverified")
	}
	vacant, err = linux.QUICWGAllStateUDPPortVacant(ctx, runner, wg.ListenPort)
	if err != nil || !vacant {
		return fmt.Errorf("current QUIC all-state UDP port vacancy unverified")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if now, nsErr := readNetworkNS(); nsErr != nil || !validNetworkNamespaceID(now) || now != originalNS {
		return fmt.Errorf("original QUIC ingress namespace changed before host effect")
	}

	// `create table` rejects a concurrent same-name table atomically. A
	// failure AFTER dispatch is uncertain and never triggers unsafe cleanup.
	if err := apply(ctx, batch); err != nil {
		return errEffectUncertain
	}
	// Once dispatched, even an unexpected namespace drift is an uncertain
	// effect, never evidence that the original guard is absent or removable.
	if now, nsErr := readNetworkNS(); nsErr != nil || !validNetworkNamespaceID(now) || now != originalNS {
		return errEffectUncertain
	}
	present, err := linux.InspectWGIngressGuard(ctx, runner, plan)
	if err != nil || !present {
		return errEffectUncertain
	}
	if now, nsErr := readNetworkNS(); nsErr != nil || !validNetworkNamespaceID(now) || now != originalNS {
		return errEffectUncertain
	}
	return nil
}

func runOriginalNFTCreate(ctx context.Context, batch string) error {
	if ctx == nil || batch == "" || len(batch) > 4096 {
		return fmt.Errorf("invalid original QUIC nft transaction")
	}
	scoped, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(scoped, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	// No shell, argv credentials or untrusted raw stderr in errors.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("original QUIC nft transaction outcome unavailable")
	}
	return nil
}
