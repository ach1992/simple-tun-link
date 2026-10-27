package wss

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// dialRestartProbe is a best-effort startup wake for a NEW dialer unit. A
// wstunnel UDP forward does not establish its WebSocket until a local WireGuard
// packet is sent. A controlled helper-only restart can otherwise leave the
// private Link idle until its next (normally 25s) WG keepalive. The bounded
// ping creates genuine kernel WG traffic without changing persistent Link
// state, credentials, firewall, routes, peer settings or any foreign service.
// A post-start failure must never make the actual sidecar fail or restart.
// This is not a health check and cannot assert the peer received any packet.
func dialRestartProbe(link domain.Link) (Command, error) {
	if link.Backend != domain.BackendWireGuardWSS || link.Validate() != nil {
		return Command{}, fmt.Errorf("invalid managed WSS restart probe identity")
	}
	if link.WSS.Role != "dial" {
		return Command{}, nil
	}
	id := string(link.ID)
	if len(id) != 36 || !strings.HasPrefix(id, "lnk_") {
		return Command{}, fmt.Errorf("invalid WSS Link ID")
	}
	peer := link.Addresses.Peer.Addr()
	if !peer.IsValid() || !peer.Is4() || peer == netip.IPv4Unspecified() || peer.IsMulticast() {
		return Command{}, fmt.Errorf("invalid WSS peer address for restart probe")
	}
	// Keep this name aligned with wireguard.InterfaceName; both derive from
	// the canonical validated Link ID, never from an operator shell string.
	iface := "stlwg" + id[4:14]
	return Command{Binary: "/usr/bin/ping", Args: []string{
		"-q", "-n", "-I", iface, "-s", "8", "-c", "8", "-i", "0.25", "-W", "1", peer.String(),
	}}, nil
}

func (h Host) restartProbeProperty(link domain.Link) (string, error) {
	cmd, err := dialRestartProbe(link)
	if err != nil || cmd.Binary == "" {
		return "", err
	}
	// All derived argv elements are validated and whitespace-free. systemd
	// parses the leading '-' as ignore-failure: a down peer never prevents a
	// managed Link from starting or triggers a restart loop.
	return "--property=ExecStartPost=-" + strings.Join(append([]string{cmd.Binary}, cmd.Args...), " "), nil
}

// Accept old pre-wakeup units without granting permission to modify or adopt
// them. Their already-running argv, per-Link TLS and systemd security policy
// must still match exactly; updating the executable does not silently edit a
// live transient unit. The new policy applies only after an owner-authorized
// unit re-creation, not by pretending existing units were upgraded.
func verifyWSSRestartProbe(observed string, link domain.Link) error {
	expected, err := dialRestartProbe(link)
	if err != nil {
		return err
	}
	if observed == "" {
		return nil
	} // verified legacy unit
	if expected.Binary == "" || strings.Count(observed, "argv[]=") != 1 ||
		!strings.Contains(observed, "ignore_errors=yes") ||
		!matchesExactWSSExecStart(observed, expected) {
		return fmt.Errorf("WSS post-start probe differs from exact Link identity")
	}
	return nil
}
