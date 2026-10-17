package main

import (
	"context"
	"fmt"
	"net/netip"
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

// The wizard presents IPv4 addresses, not obscure CIDR or first/second /31
// choices. Failures are reparable without restarting the wizard. The Engine
// still performs authoritative locked re-inspection at actual apply.
func askLinkAddresses(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr, forceManual bool) (domain.LinkAddresses, error) {
	return askLinkAddressesWithPolicy(p, runner, snapshot, underlayPeer, forceManual, false)
}

// IPsec's canonical IKE/XFRM profile accepts only matched /31 selectors.
// Reject otherwise valid /30 manual pairs while still inside the address
// wizard, before confirmation or any protected credential/host mutation.
func askIPsecLinkAddresses(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr) (domain.LinkAddresses, error) {
	return askLinkAddressesWithPolicy(p, runner, snapshot, underlayPeer, false, true)
}

func askLinkAddressesWithPolicy(p createPrompts, runner linux.Runner, snapshot state.Snapshot, underlayPeer netip.Addr, forceManual, requireIPsec31 bool) (domain.LinkAddresses, error) {
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
		if !ok || forceManual {
			prompt = "Tunnel IP on THIS server (example 10.235.1.1; q=back): "
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
		local, parseErr := netip.ParseAddr(rawLocal)
		if parseErr != nil || !local.Is4() || !local.IsPrivate() {
			fmt.Fprintln(p.out, "Use a private IPv4 address such as 10.235.1.1 (not a subnet/CIDR). Try again.")
			continue
		}
		rawPeer, err := p.ask("Tunnel IP on OTHER server (example 10.235.1.2; q=back): ")
		if err != nil {
			return domain.LinkAddresses{}, err
		}
		peer, parseErr := netip.ParseAddr(rawPeer)
		if parseErr != nil {
			fmt.Fprintln(p.out, "Enter the OTHER server's plain IPv4 address, without /30 or /31.")
			continue
		}
		addresses, err := manualLinkAddressPrefixes(local, peer)
		if err != nil {
			fmt.Fprintln(p.out, err.Error())
			continue
		}
		if requireIPsec31 && (addresses.Local.Bits() != 31 || addresses.Peer.Bits() != 31) {
			fmt.Fprintln(p.out, "IPsec requires two addresses in the same /31 pair (for example 10.235.1.2 and 10.235.1.3); choose another pair.")
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
