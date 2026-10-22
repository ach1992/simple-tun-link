package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// CrashCompensateOriginal is an EXPLICIT operator-authorized Engine-only
// operation. The durable pre-effect journal, committed original owner
// evidence (where available), and canonical maintenance/Link/resource
// locks are checked by the Engine before reaching this method.
//
// Every living resource must be independently attributable to the ORIGINAL
// creation nonce. In particular, a public interface name, same-key WG
// configuration, same-name systemd unit or nft marker WITHOUT that nonce
// is never adopted or deleted. The destructive sequence is helper -> WG
// -> nft, never releasing the public-WG ingress guard while an uncertain
// dependent helper/kernel listener remains.
func (b *Backend) CrashCompensateOriginal(ctx context.Context, link domain.Link, observed core.Observation) (bool, error) {
	if b.wssHost == nil || link.Backend != domain.BackendWireGuardWSS {
		return false, fmt.Errorf("WSS original host compensation is unavailable")
	}
	alias, err := linux.WSSOwnerTag(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		return false, fmt.Errorf("missing verified original WSS host identity")
	}
	staging, err := linux.WSSStagingName(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		return false, err
	}
	current, ok := observed.(observation)
	if !ok || current.WSSLink != link {
		return false, fmt.Errorf("WSS original host observation does not match journal")
	}
	name, err := InterfaceName(link.ID)
	if err != nil {
		return false, err
	}
	if err := b.verifyOriginalCrashWG(ctx, link, current, alias, staging, name); err != nil {
		return false, err
	}
	wgLive := current.Target.Exists
	for _, candidate := range current.Links {
		if candidate.Name == staging {
			wgLive = true
		}
	}
	if (wgLive || current.HelperLoaded) && !current.GuardPresent {
		return false, fmt.Errorf("original kernel/helper resource survives without verified protective WSS ingress")
	}
	if !wgLive && !current.HelperLoaded && !current.GuardPresent {
		return false, nil
	}

	// Validate complete, still-current helper/nft owner readbacks before
	// the FIRST destructive effect. Each call is an exact-origin verifier;
	// no resource discovery or cleanup by name alone is allowed.
	if current.HelperLoaded {
		if _, err := b.wssHost.StopHelper(ctx, link); err != nil {
			return false, fmt.Errorf("cannot safely stop and collect original WSS helper: %w", err)
		}
	}
	updated, err := b.Inspect(ctx, link)
	if err != nil {
		return false, fmt.Errorf("cannot reobserve WSS resources after helper collection: %w", err)
	}
	next := updated.(observation)
	if next.HelperLoaded {
		return false, fmt.Errorf("original helper remains loaded after Stop")
	}
	if err := b.verifyOriginalCrashWG(ctx, link, next, alias, staging, name); err != nil {
		return false, err
	}
	// Reinspection checks ifindex as well as the original alias and full
	// WG public configuration immediately before index-targeted deletion.
	var index int
	if next.Target.Exists {
		index = next.Target.IfIndex
	}
	for _, candidate := range next.Links {
		if candidate.Name == staging {
			index = candidate.IfIndex
		}
	}
	if index > 0 {
		if !next.GuardPresent {
			return false, fmt.Errorf("protective original nft ingress absent before kernel WG compensation")
		}
		if err := b.deleteLink(ctx, index); err != nil {
			return false, fmt.Errorf("kernel WG deletion outcome uncertain; preserve nft guard: %w", err)
		}
	}
	updated, err = b.Inspect(ctx, link)
	if err != nil {
		return false, fmt.Errorf("cannot establish WG disappearance after original compensation: %w", err)
	}
	next = updated.(observation)
	if err := b.verifyOriginalCrashWG(ctx, link, next, alias, staging, name); err != nil {
		return false, err
	}
	if next.Target.Exists || next.HelperLoaded {
		return false, fmt.Errorf("original kernel WG or helper survived; preserve ingress guard")
	}
	for _, candidate := range next.Links {
		if candidate.Name == staging {
			return false, fmt.Errorf("original staged kernel WG remains; preserve nft guard")
		}
	}
	if index <= 0 {
		return false, fmt.Errorf("original WG generation not verifiably deleted; preserve journal and ingress guard")
	}
	if next.GuardPresent {
		// Guard removal requires a fresh witness from the exact original
		// nonce/ifindex deletion performed above, plus independent socket
		// and namespace-local WG inventories immediately before nft delete.
		witnessed, witnessErr := core.WithWSSWGDeleted(ctx, link.ID)
		if witnessErr != nil {
			return false, witnessErr
		}
		if _, err := b.wssHost.RemoveGuard(witnessed, link); err != nil {
			return false, fmt.Errorf("cannot collect exactly tagged WSS guard: %w", err)
		}
	}
	return true, nil // Engine must separately inspect ALL host vacancy and commit.
}

// verifyOriginalCrashWG rejects ANY untagged staging object. A derived
// name, even when random, is not proof of creation: a foreign same-name WG
// may appear after the guard and before STL's exclusive kernel NEWLINK.
// An actual pre-alias crash therefore remains quarantined, pending
// independently attested, out-of-band operator recovery. Never guess.
func (b *Backend) verifyOriginalCrashWG(ctx context.Context, link domain.Link,
	observed observation, alias, staging, name string) error {
	canonical, temp := 0, 0
	for _, candidate := range observed.Links {
		switch {
		case candidate.Name == name:
			canonical++
			if !observed.Target.Exists || candidate.IfIndex != observed.Target.IfIndex ||
				candidate.IfIndex <= 0 || candidate.Alias != alias || candidate.Owner != link.ID {
				return fmt.Errorf("foreign original WG public-name replacement")
			}
		case candidate.Name == staging:
			temp++
			if candidate.Alias == "" {
				return fmt.Errorf("unmarked WSS staging interface has no independently attested original ownership; retain guard and journal")
			}
			if candidate.IfIndex <= 0 || candidate.Alias != alias || candidate.Owner != link.ID || candidate.Up {
				return fmt.Errorf("original WG staged ifindex/nonce identity mismatched")
			}
			if err := b.inspectPublicWG(ctx, &candidate); err != nil {
				return fmt.Errorf("incomplete original marked staging WG readback: %w", err)
			}
			if err := b.requireOriginalWSSNoPSK(ctx, candidate); err != nil {
				return err
			}
			addresses, err := b.originalWSSAddresses(ctx, staging, candidate.IfIndex)
			if err != nil || len(addresses) != 0 || !candidate.emptyConfig() || candidate.Endpoint != "" {
				return fmt.Errorf("marked staging WG has foreign or ambiguous configuration")
			}
		case candidate.Alias == alias:
			return fmt.Errorf("original WSS kernel nonce moved to a different interface")
		}
	}
	if canonical > 1 || temp > 1 || canonical+temp > 1 {
		return fmt.Errorf("more than one candidate kernel WG original identity exists")
	}
	if observed.Target.Exists {
		target := observed.Target
		if target.Name != name || target.IfIndex <= 0 || target.Alias != alias || target.Owner != link.ID {
			return fmt.Errorf("original public WG owner alias or ifindex mismatched")
		}
		addrs, err := b.originalWSSAddresses(ctx, name, target.IfIndex)
		if err != nil || !slices.Equal(addrs, target.IPv4Addresses) {
			return fmt.Errorf("original public WG address readback incomplete or changed")
		}
		if !originalWSSWGConfigSubset(target, link) {
			return fmt.Errorf("original kernel WG public configuration drift is unverified")
		}
		if err := b.requireOriginalWSSNoPSK(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

// 'wg show INTERFACE preshared-keys' is the only wireguard-tools query that
// can attest the absence of peer PSK configuration. Its output is SENSITIVE:
// consume through a bounded runner, never retain it in observedLink/State,
// stringify/log it, publish it in a diagnostic, or echo it in an error.
// For a configured peer, only the literal (none) is an acceptable PSK.
func (b *Backend) requireOriginalWSSNoPSK(ctx context.Context, wg observedLink) error {
	bounded, ok := b.runner.(linux.BoundedRunner)
	if !ok || ctx.Err() != nil {
		return fmt.Errorf("original WG preshared-key attestation unavailable")
	}
	out, err := bounded.RunBounded(ctx, linux.CaptureLimits{Stdout: 4096, Stderr: 4096},
		b.wgBinary, "show", wg.Name, "preshared-keys")
	defer clear(out.Stdout)
	defer clear(out.Stderr)
	if err != nil || ctx.Err() != nil || len(out.Stderr) != 0 {
		return fmt.Errorf("original WG preshared-key attestation unavailable")
	}
	rows := bytes.Fields(out.Stdout)
	if len(wg.Peers) == 0 && len(rows) == 0 {
		return nil
	}
	if len(wg.Peers) != 1 || len(rows) != 2 ||
		!bytes.Equal(rows[0], []byte(wg.Peers[0])) ||
		!bytes.Equal(rows[1], []byte("(none)")) {
		return fmt.Errorf("original WG preshared-key configuration is not independently verified absent")
	}
	return nil
}

// Only independently nonce-tagged and correctly ifindex-identified original
// WG objects may be compensated. Each accepted field is absent or a subset
// of the exact intended original wg set; link addressing/up requires the
// complete intended peer configuration to have been installed first.
func originalWSSWGConfigSubset(actual observedLink, link domain.Link) bool {
	wg := link.WireGuard
	if actual.PublicKey != "" && actual.PublicKey != wg.LocalPublicKey {
		return false
	}
	if actual.ListenPort != 0 && actual.ListenPort != wg.ListenPort {
		return false
	}
	if actual.FwMark != 0 {
		return false
	}
	if len(actual.Peers) > 1 || (len(actual.Peers) == 1 && actual.Peers[0] != wg.PeerPublicKey) {
		return false
	}
	if len(actual.Peers) == 0 && (actual.AllowedIPs != "" || actual.Endpoint != "" || actual.Keepalive != 0) {
		return false
	}
	if actual.AllowedIPs != "" && actual.AllowedIPs != netip.PrefixFrom(link.Addresses.Peer.Addr(), 32).String() {
		return false
	}
	if actual.Keepalive != 0 && actual.Keepalive != wg.LocalKeepalive {
		return false
	}
	// WSS uses an exact local helper endpoint; configured, up WG may later
	// learn a different authenticated endpoint through roaming.
	if actual.Endpoint != "" && actual.Endpoint != endpoint(link) &&
		!(actual.Up && actual.configuredFor(link)) {
		return false
	}
	fullyConfigured := actual.configuredFor(link)
	if len(actual.IPv4Addresses) > 1 ||
		(len(actual.IPv4Addresses) == 1 &&
			(actual.IPv4Addresses[0] != link.Addresses.Local || !fullyConfigured)) {
		return false
	}
	if actual.Up && (!fullyConfigured || len(actual.IPv4Addresses) != 1) {
		return false
	}
	// A peer before any private-key-derived public identity is not a
	// plausible prefix of the original kernel configuration sequence.
	if len(actual.Peers) > 0 && actual.PublicKey == "" {
		return false
	}
	return true
}

// Re-read all addresses with the exact ifindex. Generic diagnostics extract
// IPv4 and may ignore IPv6; compensation must reject any additional address,
// missing addr_info member, or change between two readbacks.
func (b *Backend) originalWSSAddresses(ctx context.Context, name string, ifindex int) ([]netip.Prefix, error) {
	out, err := b.runner.Run(ctx, b.ipBinary, "-json", "address", "show", "dev", name)
	if err != nil || ctx.Err() != nil {
		return nil, fmt.Errorf("original WG address inventory unavailable")
	}
	return parseOriginalWSSAddresses(out.Stdout, name, ifindex)
}
