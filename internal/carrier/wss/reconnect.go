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
		"-q", "-n", "-I", iface, "-s", "8", "-c", "8", "-i", "0.25", "-W", "1", "-w", "3", peer.String(),
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

// Admit verified legacy units only when BOTH post-start properties are truly
// absent/empty. The legacy D-Bus property (ExecStartPost) omits execution flags
// other than ignore_errors; ExecStartPostEx exposes *all* flags, including '+',
// which can bypass sandbox restrictions. Never trust a command when only one
// property is present, the properties disagree, or any extra flag is set.
// Existing units are not silently recreated when STL is upgraded.
func verifyWSSRestartProbe(legacy, extended string, link domain.Link) error {
	expected, err := dialRestartProbe(link)
	if err != nil {
		return err
	}
	if legacy == "" && extended == "" {
		return nil // genuinely unset post-start command in a verified legacy unit
	}
	if expected.Binary == "" ||
		!matchesExactWSSCommandReadback(legacy, expected, "ignore_errors", "yes") ||
		!matchesExactWSSCommandReadback(extended, expected, "flags", "ignore-failure") {
		return fmt.Errorf("WSS post-start command or execution flags differ from exact Link identity")
	}
	return nil
}

// systemctl show renders each command as one structured record. Check the
// complete property shape, exact argv, all fields once, and the entire flag
// set (not just a substring): unknown/missing fields or additional records
// are not proof of STL-owned executable identity. Status fields are runtime
// observations; only their presence/nonemptiness is required.
func matchesExactWSSCommandReadback(observed string, cmd Command, policyKey, policyValue string) bool {
	if cmd.Binary == "" || len(cmd.Args) == 0 ||
		!strings.HasPrefix(observed, "{ ") || !strings.HasSuffix(observed, " }") {
		return false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(observed, "{ "), " }")
	parts := strings.Split(body, " ; ")
	wantKeys := []string{"path", "argv[]", policyKey, "start_time", "stop_time", "pid", "code", "status"}
	if len(parts) != len(wantKeys) {
		return false
	}
	for i, key := range wantKeys {
		// The main ExecStart has no execution flags; systemctl renders
		// its extended flag list as the valid, empty "flags=" member.
		allowEmpty := i == 2 && key == "flags" && policyValue == ""
		if !strings.HasPrefix(parts[i], key+"=") || (len(parts[i]) == len(key)+1 && !allowEmpty) {
			return false
		}
	}
	if parts[0] != "path="+cmd.Binary ||
		parts[1] != "argv[]="+strings.Join(append([]string{cmd.Binary}, cmd.Args...), " ") ||
		parts[2] != policyKey+"="+policyValue {
		return false
	}
	return true
}
