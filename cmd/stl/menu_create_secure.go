package main

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// The guided sender path is deterministic: one protected receiver handoff
// per immutable Link ID, not a user-entered path likely to be forgotten.
func askPrivateHandoffPath(p createPrompts, options *runtimeOptions, id domain.LinkID) (string, error) {
	path, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return "", fmt.Errorf("cannot choose safe protected receiver file")
	}
	fmt.Fprintln(p.out, "The OTHER server's sensitive Setup Link will be kept securely by STL.")
	fmt.Fprintln(p.out, "Later use My tunnels -> Share Setup Link; no filename to remember.")
	return path, nil
}

func askPortDefault(p createPrompts, prompt string, fallback uint16) (uint16, error) {
	for {
		input, err := p.ask(prompt)
		if err != nil {
			return 0, err
		}
		if input == "" {
			return fallback, nil
		}
		value, err := strconv.ParseUint(input, 10, 16)
		if err == nil && value != 0 {
			return uint16(value), nil
		}
		fmt.Fprintln(p.out, "Use a port number between 1 and 65535.")
	}
}

// Validate with the same identity rules used by the selected carrier. A bad
// SAN must not survive until final confirmation and waste prior wizard input.
func askTLSCertificateSAN(p createPrompts, carrier composition.Kind, listener netip.Addr) (string, error) {
	if carrier != composition.WSS && carrier != composition.QUIC {
		return "", fmt.Errorf("unsupported TLS carrier %q", carrier)
	}
	for {
		name, err := p.ask("TLS certificate SAN (Enter = listener IP; or exact DNS name): ")
		if err != nil {
			return "", err
		}
		identity := name
		if identity == "" {
			identity = listener.String()
		}
		valid := false
		switch carrier {
		case composition.WSS:
			valid = composition.ValidWSSTLSName(identity, listener)
		case composition.QUIC:
			valid = composition.ValidQUICTLSName(identity, listener)
		}
		if valid {
			return name, nil // Preserve the existing empty/default wire contract.
		}
		if ip, parseErr := netip.ParseAddr(name); parseErr == nil && ip != listener {
			fmt.Fprintf(p.out, "An IP SAN must match the physical listener IP %s; use that IP or a canonical DNS SAN. Try again or press q.\n", listener)
		} else if carrier == composition.QUIC {
			fmt.Fprintln(p.out, "QUIC requires a canonical lowercase DNS name with a dot, or the exact listener IPv4 (no @, colon, spaces or paths). Try again or press q.")
		} else {
			fmt.Fprintln(p.out, "WSS requires a canonical lowercase DNS name or the exact listener IP (no @, colon, spaces or paths). Try again or press q.")
		}
	}
}
