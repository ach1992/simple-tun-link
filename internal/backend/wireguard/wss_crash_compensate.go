package wireguard

import (
	"context"
	"fmt"
	"strings"

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
func (b *Backend) CrashCompensateOriginal(ctx context.Context, link domain.Link, observed core.Observation) error {
	if b.wssHost == nil || link.Backend != domain.BackendWireGuardWSS {
		return fmt.Errorf("WSS original host compensation is unavailable")
	}
	alias, err := linux.WSSOwnerTag(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		return fmt.Errorf("missing verified original WSS host identity")
	}
	staging, err := linux.WSSStagingName(link.ID, core.WSSOrigin(ctx))
	if err != nil {
		return err
	}
	current, ok := observed.(observation)
	if !ok || current.WSSLink != link {
		return fmt.Errorf("WSS original host observation does not match journal")
	}
	name, err := InterfaceName(link.ID)
	if err != nil {
		return err
	}
	if err := b.verifyOriginalCrashWG(ctx, link, current, alias, staging, name); err != nil {
		return err
	}
	wgLive := current.Target.Exists
	for _, candidate := range current.Links {
		if candidate.Name == staging {
			wgLive = true
		}
	}
	if (wgLive || current.HelperLoaded) && !current.GuardPresent {
		return fmt.Errorf("original kernel/helper resource survives without verified protective WSS ingress")
	}
	if !wgLive && !current.HelperLoaded && !current.GuardPresent {
		return nil
	}

	// Validate complete, still-current helper/nft owner readbacks before
	// the FIRST destructive effect. Each call is an exact-origin verifier;
	// no resource discovery or cleanup by name alone is allowed.
	if current.HelperLoaded {
		if _, err := b.wssHost.StopHelper(ctx, link); err != nil {
			return fmt.Errorf("cannot safely stop and collect original WSS helper: %w", err)
		}
	}
	updated, err := b.Inspect(ctx, link)
	if err != nil {
		return fmt.Errorf("cannot reobserve WSS resources after helper collection: %w", err)
	}
	next := updated.(observation)
	if next.HelperLoaded {
		return fmt.Errorf("original helper remains loaded after Stop")
	}
	if err := b.verifyOriginalCrashWG(ctx, link, next, alias, staging, name); err != nil {
		return err
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
			return fmt.Errorf("protective original nft ingress absent before kernel WG compensation")
		}
		if err := b.deleteLink(ctx, index); err != nil {
			return fmt.Errorf("kernel WG deletion outcome uncertain; preserve nft guard: %w", err)
		}
	}
	updated, err = b.Inspect(ctx, link)
	if err != nil {
		return fmt.Errorf("cannot establish WG disappearance after original compensation: %w", err)
	}
	next = updated.(observation)
	if err := b.verifyOriginalCrashWG(ctx, link, next, alias, staging, name); err != nil {
		return err
	}
	if next.Target.Exists || next.HelperLoaded {
		return fmt.Errorf("original kernel WG or helper survived; preserve ingress guard")
	}
	for _, candidate := range next.Links {
		if candidate.Name == staging {
			return fmt.Errorf("original staged kernel WG remains; preserve nft guard")
		}
	}
	if next.GuardPresent {
		// Never remove the original ingress protection while another WG
		// interface still holds the original UDP port or public identity.
		// A strict global readback is needed even after the local ifindex
		// and transient helper have been collected.
		clear, err := b.crashWSSGlobalKernelVacant(ctx, link)
		if err != nil || !clear {
			return fmt.Errorf("cannot prove global WG key/UDP-port vacancy before guard removal: %w", err)
		}
		if _, err := b.wssHost.RemoveGuard(ctx, link); err != nil {
			return fmt.Errorf("cannot collect exactly tagged WSS guard: %w", err)
		}
	}
	return nil // Engine must separately inspect ALL host vacancy and commit.
}

// verifyOriginalCrashWG is read-only and checks every kernel WireGuard
// object before any original-object compensation is attempted. The initial
// staged name carries the original random 70-bit nonce-derived identity;
// it may ONLY be empty/down/untagged (prior to alias) or carry the original
// full 128-bit nonce alias. No same-name foreign replacement is adopted.
func (b *Backend) verifyOriginalCrashWG(ctx context.Context, link domain.Link,
	observed observation, alias, staging, name string) error {
	canonical := 0
	temp := 0
	for _, candidate := range observed.Links {
		if candidate.Name == name {
			canonical++
			if !observed.Target.Exists || candidate.IfIndex != observed.Target.IfIndex ||
				candidate.IfIndex <= 0 || candidate.Alias != alias || candidate.Owner != link.ID {
				return fmt.Errorf("foreign original WG public-name replacement")
			}
		} else if candidate.Name == staging {
			temp++
			if candidate.IfIndex <= 0 || candidate.Up ||
				(candidate.Alias != "" && candidate.Alias != alias) ||
				(candidate.Alias == alias && candidate.Owner != link.ID) ||
				(candidate.Alias == "" && candidate.Owner != "") {
				return fmt.Errorf("original WG staged ifindex/nonce identity mismatched")
			}
			for _, field := range []string{"public-key", "listen-port", "peers"} {
				out, err := b.runner.Run(ctx, b.wgBinary, "show", staging, field)
				if err != nil {
					return fmt.Errorf("incomplete original staging WG %s readback", field)
				}
				value := strings.TrimSpace(string(out.Stdout))
				switch field {
				case "public-key":
					if value != "(none)" {
						return fmt.Errorf("staging WG public key is not original unconfigured state")
					}
				case "listen-port":
					if value != "off" && value != "0" {
						return fmt.Errorf("staging WG unexpectedly listens on UDP")
					}
				case "peers":
					if value != "" {
						return fmt.Errorf("staging WG has unexpected peer configuration")
					}
				}
			}
			address, err := b.runner.Run(ctx, b.ipBinary, "-json", "address", "show", "dev", staging)
			if err != nil {
				return fmt.Errorf("staged kernel WG address cannot be attested")
			}
			addrs, err := parseAddresses(address.Stdout, staging, candidate.IfIndex)
			if err != nil || len(addrs) != 0 {
				return fmt.Errorf("staging WG carries foreign addresses")
			}
		} else if candidate.Alias == alias {
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
		if target.emptyConfig() {
			if target.Up || len(target.IPv4Addresses) != 0 {
				return fmt.Errorf("unconfigured original WG was unexpectedly activated")
			}
		} else if target.configuredFor(link) {
			if len(target.IPv4Addresses) > 1 ||
				(len(target.IPv4Addresses) == 1 && target.IPv4Addresses[0] != link.Addresses.Local) ||
				(target.Up && len(target.IPv4Addresses) != 1) {
				return fmt.Errorf("original configured WG address/up state is foreign")
			}
		} else {
			return fmt.Errorf("original kernel WG public configuration drift is unverified")
		}
	}
	return nil
}
