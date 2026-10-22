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

// An authenticated WSS receiver offer is never parsed as a v1/v2 native
// setup token. This path enforces hidden paste and fresh confirmation.
func menuImportWSS(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	menuScreen(out, "Import WSS / sensitive peer offer")
	menuNotice(out, "WARNING", "Paste the COMPLETE one-line JSON handoff privately. It contains WireGuard and mTLS private keys.")
	raw, err := readPrivateMenuURLWithPrompt(input, reader, func() {
		fmt.Fprint(out, "Paste protected WSS receiver JSON (terminal echo off): ")
	})
	fmt.Fprintln(out)
	if errors.Is(err, io.EOF) {
		return 0
	}
	if err != nil || raw == "" || raw == "q" || raw == "0" {
		menuNotice(out, "WARNING", "Missing or interrupted private WSS offer; no Link changed.")
		return 0
	}
	offer, _, err := decodeWSSOffer(strings.NewReader(raw))
	if err != nil {
		menuNotice(out, "WARNING", "This is not a verified versioned WSS receiver offer. No Link was changed.")
		return 2
	}
	defer offer.clear()
	var preview bytes.Buffer
	code := linkWSSCommand([]string{"preview-wss", "--stdin", "--json"},
		strings.NewReader(raw), &preview, io.Discard, opts)
	if code != 0 {
		menuNotice(out, "WARNING", "WSS peer preview failed. No Link was changed.")
		return code
	}
	var details struct {
		LinkID    domain.LinkID `json:"link_id"`
		Role      string        `json:"receiver_role"`
		PrivateIP string        `json:"receiver_private_ip"`
		Underlay  string        `json:"receiver_underlay"`
		Confirm   string        `json:"confirmation_sha256"`
	}
	if json.Unmarshal(preview.Bytes(), &details) != nil || details.LinkID != offer.Receiver.ID ||
		details.Confirm == "" {
		menuNotice(out, "WARNING", "WSS confirmation is inconsistent.")
		return 2
	}
	menuScreen(out, "Review / WSS receiver before importing")
	menuField(out, "Link", string(details.LinkID))
	menuField(out, "Backend", "WireGuard / WSS + mTLS")
	menuField(out, "THIS server role", details.Role)
	menuField(out, "THIS underlay", details.Underlay)
	menuField(out, "THIS private IP", details.PrivateIP)
	menuField(out, "TLS WSS TCP port", fmt.Sprintf("%d", offer.Receiver.WSS.TCPPort))
	menuNotice(out, "WARNING", "Private keys will be staged; the Engine will create an owned WG interface, nft guard and WSS helper. Peer traffic must then be checked independently.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot obtain fresh terminal approval; no Link changed.")
		return 2
	}
	fmt.Fprint(out, menuActionPrompt(out, "YES", "Import and start this authenticated WSS Link? Type YES (Enter=no): "))
	approval, err := readMenuAnswer(reader)
	if err != nil || !strings.EqualFold(approval, "yes") {
		menuNotice(out, "INFO", "Import cancelled; no new Link changes.")
		return 0
	}
	menuScreen(out, "Applying / WSS receiver")
	code = linkWSSCommand([]string{"import-wss", "--stdin", "--confirm", details.Confirm},
		strings.NewReader(raw), out, errOut, opts)
	if code == 0 {
		menuNotice(out, "OK", "WSS receiver Link was locally ensured through STL. Verify kernel handshake and bidirectional private-IP traffic.")
	} else {
		menuNotice(out, "WARNING", "Local WSS import not fully confirmed; reconcile exact existing credentials and Link State before retry.")
	}
	return code
}
