package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Used only for manual GRE Native. GRE keys are nonsecret receive selectors,
// not credentials; enabling a key here makes manual pairing of an already
// configured keyed-GRE peer possible without copying a Setup Link.
func askManualGREKey(p createPrompts) (domain.GREOptions, error) {
	fmt.Fprintln(p.out, "Manual GRE uses the SAME receive key on BOTH servers if keyed.")
	fmt.Fprintln(p.out, "Copy that key from My tunnels -> Connection details on the first server.")
	for {
		value, err := p.ask("GRE receive key (Enter=none/unkeyed, or decimal key from OTHER server; q=back): ")
		if err != nil {
			return domain.GREOptions{}, err
		}
		if value == "" || strings.EqualFold(value, "off") {
			fmt.Fprintln(p.out, "GRE key: none (unkeyed). This is NOT encrypted.")
			return domain.GREOptions{}, nil
		}
		key, err := strconv.ParseUint(value, 10, 32)
		if err == nil {
			fmt.Fprintf(p.out, "GRE key: %d (not an encryption key). Configure the SAME number on both servers.\n", key)
			return domain.GREOptions{KeyEnabled: true, Key: uint32(key)}, nil
		}
		fmt.Fprintln(p.out, "Enter an unsigned decimal GRE key (0 through 4294967295), or press Enter for none.")
	}
}

// Read-only copy block derived from the canonical persisted Link (never
// external network observations). The values are a two-server plan, not
// evidence that the remote host is configured or reachable. No credential
// store is read and no private/PSK key is reconstructed.
func printManualConnectionDetails(out io.Writer, l domain.Link) {
	menuSection(out, "Two-server connection details / saved")
	menuField(out, "Type", fmt.Sprintf("%s / %s", l.Backend, l.Encapsulation))
	menuField(out, "Saved ID", string(l.ID)+" (advanced CLI)")
	menuField(out, "Local endpoint", l.Underlay.Local.String())
	menuField(out, "Remote endpoint", l.Underlay.Peer.String())
	menuField(out, "Local tunnel IP", l.Addresses.Local.String())
	menuField(out, "Remote tunnel IP", l.Addresses.Peer.String())
	menuField(out, "Local MTU", humanMTUPolicy(l.MTU))

	menuSection(out, "Manual setup on the other server")
	fmt.Fprintf(out, "  Other server's PEER connection IP: %s  (THIS server)\n", l.Underlay.Local)
	fmt.Fprintf(out, "  Other server's OWN tunnel IP:      %s\n", l.Addresses.Peer.Addr())
	fmt.Fprintf(out, "  Other server's PEER tunnel IP:     %s\n", l.Addresses.Local.Addr())
	fmt.Fprintf(out, "  Both tunnel IPs must use prefix /%d; reverse local and peer roles.\n", l.Addresses.Local.Bits())

	switch l.Backend {
	case domain.BackendGRE:
		if l.GRE.KeyEnabled {
			fmt.Fprintf(out, "  GRE receive key: %d (must match both sides; NOT encryption)\n", l.GRE.Key)
		} else {
			fmt.Fprintln(out, "  GRE receive key: none/unkeyed (press Enter at manual-key prompt)")
		}
		if l.Encapsulation == domain.EncapNative {
			fmt.Fprintln(out, "  OTHER server menu: Create tunnel -> 4 Manual -> 1 GRE Native.")
			fmt.Fprintln(out, "  Carrier: IP protocol 47 (GRE), NOT TCP/UDP port 47.")
		} else {
			fmt.Fprintf(out, "  UDP encapsulation: %s, configured receive UDP port: %d\n", l.Encapsulation, l.GRE.UDPPort)
			fmt.Fprintln(out, "  For FOU/GUE use My tunnels -> Share Setup Link (manual menu is Native only).")
		}
		fmt.Fprintln(out, "  GRE traffic is NOT encrypted or authenticated.")
	case domain.BackendIPIP:
		if l.Encapsulation == domain.EncapNative {
			fmt.Fprintln(out, "  OTHER server menu: Create tunnel -> 4 Manual -> 2 IPIP Native.")
			fmt.Fprintln(out, "  Carrier: IP protocol 4 (IPIP), NOT TCP/UDP port 4.")
		} else {
			fmt.Fprintf(out, "  UDP encapsulation: %s\n", l.Encapsulation)
			fmt.Fprintln(out, "  For IPIP FOU/GUE use My tunnels -> Share Setup Link (receiver UDP port is paired automatically).")
		}
		fmt.Fprintln(out, "  IPIP traffic is NOT encrypted or authenticated.")
	case domain.BackendWireGuard:
		fmt.Fprintln(out, "  WireGuard: encrypted UDP; do NOT assume these addresses alone will pair the other server.")
		fmt.Fprintf(out, "  THIS server UDP listen port: %d | OTHER server UDP listen port: %d\n", l.WireGuard.ListenPort, l.WireGuard.PeerPort)
		fmt.Fprintf(out, "  THIS server PUBLIC key: %s\n", l.WireGuard.LocalPublicKey)
		fmt.Fprintf(out, "  OTHER server PUBLIC key: %s\n", l.WireGuard.PeerPublicKey)
		fmt.Fprintln(out, "  The original protected receiver offer remains available via My tunnels -> Share -> SHOW.")
		fmt.Fprintln(out, "  Deleted/lost receiver secrets cannot be regenerated from ordinary saved Link State.")
	case domain.BackendIPsec:
		fmt.Fprintln(out, "  IPsec/IKEv2 uses an independent protected PSK and native-exclusive strongSwan.")
		fmt.Fprintln(out, "  Public details alone are insufficient: use My tunnels -> Share -> SHOW for the protected receiver offer.")
		fmt.Fprintln(out, "  An already staged/private receiver PSK cannot be exported from ordinary Link state.")
	default:
		fmt.Fprintln(out, "  This backend is not supported for manual setup; use its canonical Setup Link.")
	}
	menuNotice(out, "WARNING", "Saved settings are NOT a remote connectivity test. Verify both peers.")

}

func humanMTUPolicy(m domain.MTUPolicy) string {
	switch m.Mode {
	case domain.MTUAuto:
		return "Auto (local route estimate, not measured peer PMTU)"
	case domain.MTUManual:
		return fmt.Sprintf("Manual %d bytes", m.Bytes)
	default:
		return "Unmanaged/default"
	}
}
