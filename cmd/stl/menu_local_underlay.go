package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

// The creation wizard only proposes a local source/device. ip route get is
// a local kernel lookup, never a ping; a missing peer route is not an error
// that prevents choosing another genuinely assigned local IPv4. No host
// mutations or bilateral network probes occur in this function.
func askLocalUnderlay(p createPrompts, runner linux.Runner, peer netip.Addr) (linux.Route, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Independently inspect the *host's* assigned addresses first. The
	// route to peer is only an optional suggestion; it is not proof of an
	// address's local ownership or usable remote reachability.
	endpoints, err := linux.ListLocalIPv4Endpoints(ctx, runner)
	if err != nil || len(endpoints) == 0 {
		menuNotice(p.out, "WARNING", "Cannot verify an assigned local IPv4/interface. No tunnel created.")
		menuProse(p.out, "Inspect ip -json address show locally; assign a usable IPv4 to an interface and retry. Peer reachability is not required.")
		return linux.Route{}, fmt.Errorf("assigned local IPv4 inventory unavailable")
	}
	route, routeErr := (linux.RouteResolver{Runner: runner}).Resolve(ctx, peer)
	manualOverride := false
	if routeErr == nil && route.Source.Is4() && route.Source != peer {
		// A matching device alone is insufficient when the same IPv4 is
		// listed on more than one interface. The Link schema records only
		// the local IPv4, so it must resolve to exactly one host device.
		if unique, err := linux.BoundLocalIPv4(endpoints, route.Source, ""); err == nil &&
			unique.Interface == route.Device {
			menuField(p.out, "Local IPv4", route.Source.String()+" (verified local kernel suggestion)")
			menuField(p.out, "Network device", safeMenuText(route.Device))
			menuProse(p.out, "This is a LOCAL route lookup, not a connectivity check. Peer traffic remains unverified until you test after pairing.")
			// A multi-homed host may deliberately bind a different assigned
			// local address even when a valid kernel route exists. Keep the
			// common one-IP path prompt-free while allowing an explicit
			// operator override without changing the public Link schema.
			if len(endpoints) == 1 {
				return route, nil
			}
			for {
				answer, err := p.ask("Use this local IPv4/interface? (Enter=use, m=choose another assigned pair, q=back): ")
				if err != nil {
					return linux.Route{}, err
				}
				switch strings.ToLower(strings.TrimSpace(answer)) {
				case "", "y", "yes":
					return route, nil
				case "m", "manual":
					manualOverride = true
					break
				default:
					menuProse(p.out, "Enter to use the kernel suggestion or m to choose a different locally assigned IPv4/interface.")
					continue
				}
				break
			}
		}
	}
	if manualOverride {
		menuNotice(p.out, "INFO", "You selected manual local IPv4/interface configuration instead of the verified route suggestion.")
	} else {
		menuNotice(p.out, "INFO", "No trustworthy automatic local IPv4/source/interface. This does not mean the peer is offline or block manual setup.")
	}
	menuSection(p.out, "Choose THIS server's assigned underlay IPv4/interface")
	for _, ep := range endpoints {
		menuField(p.out, ep.Address.String(), safeMenuText(ep.Interface))
	}
	suggested := netip.Addr{}
	if len(endpoints) == 1 && endpoints[0].Address != peer {
		suggested = endpoints[0].Address
	}
	for {
		question := "Local IPv4 on THIS server (must be listed; q=back): "
		if suggested.IsValid() {
			question = "Local IPv4 [" + suggested.String() + "] (Enter=detected; q=back): "
		}
		raw, err := p.ask(question)
		if err != nil {
			return linux.Route{}, err
		}
		if raw == "" && suggested.IsValid() {
			raw = suggested.String()
		}
		local, parseErr := netip.ParseAddr(raw)
		if parseErr != nil {
			menuProse(p.out, "Choose a listed local IPv4, without CIDR or port.")
			continue
		}
		candidates := make([]linux.LocalIPv4Endpoint, 0, 2)
		for _, ep := range endpoints {
			if ep.Address == local {
				candidates = append(candidates, ep)
			}
		}
		if len(candidates) == 0 {
			menuProse(p.out, "That IPv4 is not assigned to this server. Choose a listed address.")
			continue
		}
		suggestion := ""
		if len(candidates) == 1 {
			suggestion = candidates[0].Interface
		}
		question = "Network interface for that IPv4 (required; q=back): "
		if suggestion != "" {
			question = "Network interface [" + suggestion + "] (Enter=detected; q=back): "
		}
		device, err := p.ask(question)
		if err != nil {
			return linux.Route{}, err
		}
		device = strings.TrimSpace(device)
		if device == "" {
			device = suggestion
		}
		selected, err := linux.BoundLocalIPv4(endpoints, local, device)
		if err != nil {
			menuProse(p.out, "That local IP/interface pair was not verified. Recheck ip -json address show and retry.")
			continue
		}
		if _, err := linux.BoundLocalIPv4(endpoints, local, ""); err != nil {
			menuProse(p.out, "This IPv4 exists on multiple interfaces and cannot be persisted unambiguously. Choose a unique assigned IPv4.")
			continue
		}
		menuField(p.out, "Selected local", selected.Address.String()+" on "+selected.Interface)
		menuProse(p.out, "Manual local configuration selected. This does NOT confirm peer reachability.")
		return linux.Route{Peer: peer, Source: local, Device: selected.Interface}, nil
	}
}
