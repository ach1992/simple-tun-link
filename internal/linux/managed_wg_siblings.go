package linux

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// VerifiedManagedWGIngressSiblings admits only complete, exact early-DROP
// guards reserved by protected State. This exclusion is observational firewall
// compatibility, never a grant of deletion or recovery authority. Historical
// source-only QUIC reservations do not become managed sibling owners.
func VerifiedManagedWGIngressSiblings(ctx context.Context, runner BoundedRunner, snapshot state.Snapshot, exclude domain.LinkID) (wssResult []WSSWGIngressPlan, quicResult []QUICWGIngressPlan, resultErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	beforeNS, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		afterNS, err := os.Readlink("/proc/thread-self/ns/net")
		if err != nil || afterNS != beforeNS {
			wssResult, quicResult = nil, nil
			resultErr = fmt.Errorf("WG sibling observation namespace changed")
		}
	}()
	var ws []WSSWGIngressPlan
	var qs []QUICWGIngressPlan
	seen := map[domain.LinkID]bool{}
	addWSS := func(link domain.Link, nonce string, claims []domain.ResourceClaim) error {
		if link.ID == exclude || seen[link.ID] {
			return nil
		}
		seen[link.ID] = true
		if err := RequireOwned(link.ID, domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: "wss/nft/" + string(link.ID)}, claims); err != nil {
			return err
		}
		p, err := NewWSSWGIngressPlan(link.ID, link.WireGuard.ListenPort)
		if err != nil {
			return err
		}
		p.OriginalNonce = nonce
		present, err := InspectWGIngressGuard(ctx, runner, p)
		if err != nil {
			return err
		}
		if present {
			ws = append(ws, p)
		}
		return nil
	}
	addQUIC := func(link domain.Link, nonce string, claims []domain.ResourceClaim, generation *state.QUICGeneration) error {
		if link.ID == exclude || seen[link.ID] {
			return nil
		}
		seen[link.ID] = true
		if err := RequireOwned(link.ID, domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: "quic/nft/" + string(link.ID)}, claims); err != nil {
			return err
		}
		p, err := NewQUICWGIngressPlan(link.ID, link.WireGuard.ListenPort, nonce)
		if err != nil {
			return err
		}
		present, handles, err := ReadWGIngressGuardHandles(ctx, runner, p)
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		if generation != nil {
			boot, err := managedSiblingKernelBootID()
			if err != nil {
				return err
			}
			ns, err := os.Readlink("/proc/thread-self/ns/net")
			if err != nil {
				return err
			}
			if generation.Validate(link) != nil || generation.KernelBootID != boot || generation.NetworkNS != ns ||
				handles != (WGIngressLiveHandles{Table: generation.GuardTableHandle, Chain: generation.GuardChainHandle, Rule: generation.GuardRuleHandle}) {
				return fmt.Errorf("committed QUIC sibling guard generation differs")
			}
		}
		qs = append(qs, p)
		return nil
	}
	// A durable pending managed operation can retain a strictly checked DROP
	// guard while its original operation is quarantined. Like WSS, this does
	// not grant any rights to the interrupted resources themselves.
	for _, op := range snapshot.QUICCrashOperations {
		if op.Managed == nil {
			continue
		}
		nonce := op.Nonce
		if op.Managed.HadCommittedLink {
			nonce = op.Managed.OriginalGeneration.OriginNonce
		}
		if err := addQUIC(op.Managed.Intent, nonce, op.Resources, nil); err != nil {
			return nil, nil, err
		}
	}
	for _, r := range snapshot.Links {
		switch r.Desired.Backend {
		case domain.BackendWireGuardWSS:
			if err := addWSS(r.Desired, r.WSSOrigin, r.OwnedResources); err != nil {
				return nil, nil, err
			}
		case domain.BackendWireGuardQUIC:
			if err := addQUIC(r.Desired, r.QUICGeneration.OriginNonce, r.OwnedResources, &r.QUICGeneration); err != nil {
				return nil, nil, err
			}
		}
	}
	for _, op := range snapshot.WSSCrashOperations {
		if op.HadCommittedLink || op.Operation != "ensure" {
			continue
		}
		if err := addWSS(op.Intent, op.Nonce, op.Resources); err != nil {
			return nil, nil, err
		}
	}
	return ws, qs, nil
}

// The current target is admitted separately from siblings after its own
// exact owner check. New-target preflight can never exclude itself.
func (p QUICWGIngressPlan) ProbeQUICWGFirewallCoexistenceWithVerifiedCurrent(ctx context.Context, runner BoundedRunner, wss []WSSWGIngressPlan, quic []QUICWGIngressPlan, current bool) error {
	guards := verifiedWGGuardSpecs(wss, quic)
	if err := checkNewWGSiblingGuards(p.spec(), guards); err != nil {
		return err
	}
	if current {
		guards = append(guards, p.spec())
	}
	return p.spec().probeWGFirewallCoexistence(ctx, runner, guards)
}
func (p WSSWGIngressPlan) ProbeWSSWGFirewallCoexistenceWithVerifiedCurrent(ctx context.Context, runner BoundedRunner, wss []WSSWGIngressPlan, quic []QUICWGIngressPlan, current bool) error {
	guards := verifiedWGGuardSpecs(wss, quic)
	if err := checkNewWGSiblingGuards(p.spec(), guards); err != nil {
		return err
	}
	if current {
		guards = append(guards, p.spec())
	}
	return p.spec().probeWGFirewallCoexistence(ctx, runner, guards)
}
