package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Manual addresses are host IPs, not the network address or a netmask.
// A canonical two-host /31 remains the default. For regular .1/.2 pairs,
// /30 is usable provided neither endpoint is the network or broadcast.
func manualLinkAddressPrefixes(local, peer netip.Addr) (domain.LinkAddresses, error) {
	if !local.Is4() || !peer.Is4() || !local.IsPrivate() || !peer.IsPrivate() || local == peer {
		return domain.LinkAddresses{}, fmt.Errorf("enter two different private IPv4 addresses, one for each server")
	}
	for _, bits := range []int{31, 30} {
		network := netip.PrefixFrom(local, bits).Masked()
		if !network.Contains(peer) {
			continue
		}
		if bits == 30 {
			firstHost := network.Addr().Next()
			secondHost := firstHost.Next()
			if !((local == firstHost && peer == secondHost) ||
				(local == secondHost && peer == firstHost)) {
				continue
			}
		}
		return domain.LinkAddresses{
			Local: netip.PrefixFrom(local, bits),
			Peer:  netip.PrefixFrom(peer, bits),
		}, nil
	}
	return domain.LinkAddresses{}, fmt.Errorf("these IPs are not a valid two-server pair; try 10.235.1.1 and 10.235.1.2")
}

// An explicit CIDR is a conscious Advanced choice, not a hidden default.
// Keep the existing simple two-host /31 or /30 inference for bare addresses.
// Validate real usable IPv4 host addresses without inventing a product prefix
// allowlist; Engine still authoritatively checks routing/resource ownership.
func manualCIDRLinkAddresses(localText, peerText string) (domain.LinkAddresses, error) {
	local, err := netip.ParsePrefix(localText)
	if err != nil {
		return domain.LinkAddresses{}, fmt.Errorf("enter a complete local IPv4/CIDR prefix (for example 10.235.2.10/24)")
	}
	peer, err := netip.ParsePrefix(peerText)
	if err != nil {
		return domain.LinkAddresses{}, fmt.Errorf("enter a complete peer IPv4/CIDR prefix (for example 10.235.2.11/24)")
	}
	if !usableManualHostPrefix(local) || !usableManualHostPrefix(peer) ||
		local.Addr() == peer.Addr() {
		return domain.LinkAddresses{}, fmt.Errorf("enter two distinct, usable unicast IPv4/CIDR host addresses; /0 and network/broadcast hosts are not usable")
	}
	return domain.LinkAddresses{Local: local, Peer: peer}, nil
}

func usableManualHostPrefix(p netip.Prefix) bool {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() == 0 ||
		!p.Addr().IsGlobalUnicast() || p.Addr().IsLoopback() ||
		p.Addr().IsLinkLocalUnicast() || p.Addr().IsMulticast() || p.Addr().Zone() != "" {
		return false
	}
	if p.Bits() >= 31 {
		return true // /31 has both usable hosts; /32 is an exact host route.
	}
	masked := p.Masked().Addr()
	if p.Addr() == masked { // network address
		return false
	}
	broadcast := masked.As4()
	bits := uint32(broadcast[0])<<24 | uint32(broadcast[1])<<16 | uint32(broadcast[2])<<8 | uint32(broadcast[3])
	bits |= ^uint32(0) >> uint(p.Bits())
	value := p.Addr().As4()
	host := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	return host != bits
}

func checkManualLinkSubnet(ctx context.Context, runner linux.Runner, reservations []domain.ResourceClaim, addresses domain.LinkAddresses) (bool, error) {
	subnet := addresses.Local.Masked()
	observed, err := inspectedAddressClaims(ctx, runner, []netip.Prefix{subnet})
	if err != nil {
		return false, err
	}
	wanted := domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: subnet.String()}
	for _, existing := range append(observed, reservations...) {
		overlap, err := domain.ResourceClaimsConflict(wanted, existing)
		if err != nil {
			return false, err
		}
		if overlap {
			return false, nil
		}
	}
	return true, nil
}

// The ordinary path keeps an inferred RFC1918 /31 suggestion. Explicit
// IPv4/CIDR is an Advanced escape hatch and is checked by the selected backend.
func askLinkAddresses(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr, forceManual bool) (domain.LinkAddresses, error) {
	return askLinkAddressesWithPolicy(p, runner, snapshot, underlayPeer, forceManual, false, domain.BackendWireGuard)
}

func askPlainLinkAddresses(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr, forceManual bool, backend domain.Backend) (domain.LinkAddresses, error) {
	return askLinkAddressesWithPolicy(p, runner, snapshot, underlayPeer, forceManual, false, backend)
}

// IPsec's canonical IKE/XFRM profile accepts only matched /31 selectors.
// Reject other choices before confirmation or protected credential staging.
func askIPsecLinkAddresses(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr) (domain.LinkAddresses, error) {
	return askLinkAddressesWithPolicy(p, runner, snapshot, underlayPeer, false, true, domain.BackendIPsec)
}

func askLinkAddressesWithPolicy(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr, forceManual, requireIPsec31 bool, backend domain.Backend) (domain.LinkAddresses, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	proposals, err := domain.Private31Candidates()
	if err != nil {
		return domain.LinkAddresses{}, fmt.Errorf("cannot suggest unused private tunnel IPs")
	}
	live, err := inspectedAddressClaims(ctx, runner, proposals)
	if err != nil {
		return domain.LinkAddresses{}, fmt.Errorf("cannot inspect existing server routes and addresses")
	}
	reserved := collectReservedLinkAddresses(snapshot, underlayPeer)
	automatic, ok, err := domain.FreePrivate31(proposals, append(live, reserved...))
	if err != nil {
		return domain.LinkAddresses{}, fmt.Errorf("cannot verify available tunnel IPs")
	}
	if ok {
		menuSection(p.out, "Tunnel addresses")
		menuField(p.out, "This server", automatic.Addr().String()+" (suggested)")
		menuField(p.out, "Other server", automatic.Addr().Next().String()+" (suggested)")
	} else {
		menuNotice(p.out, "WARNING", "No unused IP pair suggested; enter two private addresses.")
	}
	for {
		prompt := "Tunnel IP on THIS server (Enter=use suggested; q=back): "
		switch {
		case requireIPsec31 && ok && !forceManual:
			prompt = "Tunnel IP on THIS server (Enter=use suggested; manual example 10.235.1.2; q=back): "
		case requireIPsec31:
			prompt = "Tunnel IP on THIS server (example 10.235.1.2; q=back): "
		case !ok || forceManual:
			prompt = "Tunnel IP on THIS server (example 10.235.1.1 or 10.235.2.10/24; q=back): "
		}
		if !requireIPsec31 && ok && !forceManual {
			prompt = "Tunnel IP on THIS server (Enter=use suggested; IPv4/CIDR=advanced; q=back): "
		}
		rawLocal, err := p.ask(prompt)
		if err != nil {
			return domain.LinkAddresses{}, err
		}
		if rawLocal == "" && forceManual {
			menuProse(p.out, "For manual setup without a Setup Link, choose the TWO tunnel IPs yourself on both servers.")
			continue
		}
		if rawLocal == "" && ok {
			return domain.LinkAddresses{
				Local: netip.PrefixFrom(automatic.Addr(), 31),
				Peer:  netip.PrefixFrom(automatic.Addr().Next(), 31),
			}, nil
		}
		isCIDR := strings.Contains(rawLocal, "/")
		if isCIDR {
			if _, err := netip.ParsePrefix(rawLocal); err != nil {
				fmt.Fprintln(p.out, "Use a complete IPv4/CIDR host, for example 10.235.2.10/24. No Link was changed.")
				continue
			}
		} else {
			local, parseErr := netip.ParseAddr(rawLocal)
			if parseErr != nil || !local.Is4() || !local.IsPrivate() {
				example := "10.235.1.1"
				if requireIPsec31 {
					example = "10.235.1.2"
				}
				fmt.Fprintln(p.out, "Use a private IPv4 address such as "+example+" or an explicit IPv4/CIDR for advanced routing. Try again.")
				continue
			}
		}
		peerExample := "10.235.1.2"
		if requireIPsec31 {
			peerExample = "10.235.1.3"
		}
		if isCIDR {
			peerExample = "10.235.2.11/24"
		}
		rawPeer, err := p.ask("Tunnel IP on OTHER server (example " + peerExample + "; q=back): ")
		if err != nil {
			return domain.LinkAddresses{}, err
		}
		var addresses domain.LinkAddresses
		if isCIDR || strings.Contains(rawPeer, "/") {
			if !isCIDR || !strings.Contains(rawPeer, "/") {
				fmt.Fprintln(p.out, "For advanced custom prefixes, enter IPv4/CIDR for BOTH server addresses (for example 10.235.2.10/24 and 10.235.2.11/24).")
				continue
			}
			addresses, err = manualCIDRLinkAddresses(rawLocal, rawPeer)
			if err != nil {
				menuProse(p.out, err.Error())
				continue
			}
			if !addresses.Local.Addr().IsPrivate() || !addresses.Peer.Addr().IsPrivate() {
				menuNotice(p.out, "WARNING", "A custom tunnel address is not RFC1918 private space. Confirm the intended routing with the other endpoint; this is not an Internet reachability test.")
			}
		} else {
			local, _ := netip.ParseAddr(rawLocal)
			peer, parseErr := netip.ParseAddr(rawPeer)
			if parseErr != nil {
				fmt.Fprintln(p.out, "Enter the OTHER server's IPv4 host address (without CIDR in simple mode).")
				continue
			}
			addresses, err = manualLinkAddressPrefixes(local, peer)
			if err != nil {
				if requireIPsec31 {
					fmt.Fprintln(p.out, "IPsec needs two different private IPv4 addresses in one /31 pair (for example 10.235.1.2 and 10.235.1.3).")
				} else {
					fmt.Fprintln(p.out, err.Error())
				}
				continue
			}
		}
		if requireIPsec31 && (addresses.Local.Bits() != 31 || addresses.Peer.Bits() != 31 ||
			addresses.Local.Masked() != addresses.Peer.Masked()) {
			fmt.Fprintln(p.out, "IPsec requires two addresses in the same /31 pair (for example 10.235.1.2 and 10.235.1.3); choose another pair.")
			continue
		}
		if backend == domain.BackendL2TPv3 && (addresses.Local.Bits() != addresses.Peer.Bits() ||
			addresses.Local.Bits() > 31 || addresses.Local.Masked() != addresses.Peer.Masked()) {
			menuProse(p.out, "L2TPv3 Direct-IP is an Ethernet pseudowire: both IPv4 hosts must use the same /1 through /31 subnet, not two /32 host routes.")
			continue
		}
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 20*time.Second)
		free, err := checkManualLinkSubnet(checkCtx, runner, reserved, addresses)
		checkCancel()
		if err != nil {
			menuProse(p.out, "Could not check for address/route conflicts on this server; no changes made. Try again or press q.")
			continue
		}
		if !free {
			menuProse(p.out, "These tunnel IPs conflict with a local address, route, or saved Link. Choose another pair.")
			continue
		}
		menuField(p.out, "Selected local", addresses.Local.String())
		menuField(p.out, "Selected remote", addresses.Peer.String())
		return addresses, nil
	}
}
