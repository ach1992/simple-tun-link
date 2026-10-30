package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// An authenticated QUIC receiver offer is never parsed as a v1/v2 native
// setup token. This path enforces hidden paste and fresh confirmation.
func menuImportQUIC(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	menuScreen(out, "Import QUIC / sensitive peer offer")
	menuNotice(out, "WARNING", "Paste the COMPLETE one-line JSON handoff privately. It contains WireGuard and mTLS private keys.")
	raw, err := readPrivateMenuURLWithPrompt(input, reader, func() {
		fmt.Fprint(out, "Paste protected QUIC receiver JSON (terminal echo off): ")
	})
	fmt.Fprintln(out)
	if errors.Is(err, io.EOF) {
		return 0
	}
	if err != nil || raw == "" || raw == "q" || raw == "0" {
		menuNotice(out, "WARNING", "Missing or interrupted private QUIC offer; no Link changed.")
		return 0
	}
	offer, decoded, err := decodeQUICOffer(strings.NewReader(raw))
	defer clear(decoded)
	if err != nil {
		menuNotice(out, "WARNING", "This is not a verified versioned QUIC receiver offer. No Link was changed.")
		return 2
	}
	defer offer.clear()
	var preview bytes.Buffer
	code := linkQUICCommand([]string{"preview-quic", "--stdin", "--json"},
		strings.NewReader(raw), &preview, io.Discard, opts)
	if code != 0 {
		menuNotice(out, "WARNING", "QUIC peer preview failed. No Link was changed.")
		return code
	}
	var details struct {
		LinkID             domain.LinkID `json:"link_id"`
		Role               string        `json:"receiver_role"`
		PeerRole           string        `json:"peer_role"`
		PrivateIP          string        `json:"receiver_private_ip"`
		PeerPrivateIP      string        `json:"receiver_peer_private_ip"`
		Underlay           string        `json:"receiver_underlay"`
		PeerUnderlay       string        `json:"receiver_peer_underlay"`
		UDPPort            uint16        `json:"quic_udp_port"`
		ForwardUDPPort     uint16        `json:"receiver_forward_udp_port"`
		PeerForwardUDPPort uint16        `json:"peer_forward_udp_port"`
		WGListenPort       uint16        `json:"receiver_wireguard_udp_port"`
		WGPeerPort         uint16        `json:"peer_wireguard_udp_port"`
		TLSListener        string        `json:"tls_listener_name"`
		Confirm            string        `json:"confirmation_sha256"`
	}
	plan, planErr := quicPlanForLink(offer.Receiver)
	if json.Unmarshal(preview.Bytes(), &details) != nil || details.LinkID != offer.Receiver.ID ||
		details.Confirm == "" || planErr != nil || details.TLSListener != plan.TLSName ||
		details.PeerUnderlay != offer.Receiver.Underlay.Peer.String() || details.PeerPrivateIP != offer.Receiver.Addresses.Peer.String() ||
		details.UDPPort != offer.Receiver.QUIC.UDPPort || details.ForwardUDPPort != offer.Receiver.QUIC.ForwardUDPPort ||
		details.PeerForwardUDPPort != offer.Sender.QUIC.ForwardUDPPort {
		menuNotice(out, "WARNING", "QUIC confirmation is inconsistent.")
		return 2
	}
	menuScreen(out, "Review / QUIC receiver before importing")
	menuField(out, "Link", string(details.LinkID))
	menuField(out, "Backend", "WireGuard / QUIC + mTLS")
	menuField(out, "THIS server role", details.Role)
	menuField(out, "THIS underlay", details.Underlay)
	menuField(out, "THIS private IP", details.PrivateIP)
	menuField(out, "PEER server role", details.PeerRole)
	menuField(out, "PEER underlay", details.PeerUnderlay)
	menuField(out, "PEER private IP", details.PeerPrivateIP)
	menuField(out, "TLS QUIC UDP port", fmt.Sprintf("%d", details.UDPPort))
	menuField(out, "TLS listener identity", details.TLSListener)
	menuField(out, "Loopback forwarding UDP", fmt.Sprintf("this %d / peer %d (0 = no forwarder)", details.ForwardUDPPort, details.PeerForwardUDPPort))
	menuField(out, "Guarded WireGuard UDP", fmt.Sprintf("this %d / peer %d", details.WGListenPort, details.WGPeerPort))
	menuNotice(out, "WARNING", "Private keys will be staged; the Engine will create an owned WG interface, nft guard and QUIC helper. Peer traffic must then be checked independently.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot obtain fresh terminal approval; no Link changed.")
		return 2
	}
	fmt.Fprint(out, menuActionPrompt(out, "YES", "Import and start this authenticated QUIC Link? Type YES (Enter=no): "))
	approval, err := readMenuAnswer(reader)
	if err != nil || !strings.EqualFold(approval, "yes") {
		menuNotice(out, "INFO", "Import cancelled; no new Link changes.")
		return 0
	}
	menuScreen(out, "Applying / QUIC receiver")
	code = linkQUICCommand([]string{"import-quic", "--stdin", "--confirm", details.Confirm},
		strings.NewReader(raw), out, errOut, opts)
	if code == 0 {
		menuNotice(out, "OK", "QUIC receiver Link was locally ensured through STL. Verify kernel handshake and bidirectional private-IP traffic.")
	} else {
		menuNotice(out, "WARNING", "Local QUIC import not fully confirmed; reconcile exact existing credentials and Link State before retry.")
	}
	return code
}
