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
	"github.com/ach1992/simple-tun-link/internal/masquehost"
)

// MASQUE receiver handoffs are secret JSON bundles, never visible/stl://
// native pairing strings. No key is staged before an explicit fresh YES.
func menuImportMASQUE(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	menuScreen(out, "Import / private MASQUE receiver handoff")
	menuNotice(out, "WARNING", "Enter the absolute path to the original private receiver offer (mode 0600), or paste its complete single-line JSON. It contains a TLS private key.")
	raw, err := readPrivateMenuURLWithPromptLimit(input, reader, func() {
		fmt.Fprint(out, "Private MASQUE offer file or JSON (terminal echo off; q=back): ")
	}, maxMASQUEOfferBytes)
	fmt.Fprintln(out)
	if errors.Is(err, io.EOF) || raw == "0" || raw == "q" {
		return 0
	}
	if err != nil || raw == "" {
		menuNotice(out, "WARNING", "Private offer missing or incomplete; nothing imported.")
		return 2
	}
	if strings.HasPrefix(raw, "/") {
		// Reuse the existing descriptor-relative, no-follow, mode-0600,
		// current-owner and single-link handoff reader. Never execute, echo
		// or rewrite a file supplied by the operator.
		raw, err = readPrivateHandoffFile(raw)
		if err != nil {
			menuNotice(out, "WARNING", "Cannot safely read that offer file. Use the original complete single-line JSON in an owner-private (0600) file inside a private directory; no Link changed.")
			return 2
		}
	}
	offer, _, err := decodeMASQUEOffer(strings.NewReader(raw), createStateRoot(opts))
	if err != nil {
		menuNotice(out, "WARNING", "Invalid or modified MASQUE receiver offer; no Link changed.")
		return 2
	}
	defer offer.Clear()
	var preview bytes.Buffer
	if code := linkMASQUECommand([]string{"preview-masque", "--stdin", "--json"}, strings.NewReader(raw), &preview, io.Discard, opts); code != 0 {
		menuNotice(out, "WARNING", "Private MASQUE preview unavailable; nothing imported.")
		return code
	}
	var details struct {
		Role      string `json:"role"`
		PublicTLS bool   `json:"public_tls"`
		Underlay  string `json:"local_underlay"`
		PrivateIP string `json:"local_private"`
		Confirm   string `json:"confirmation_sha256"`
	}
	if json.Unmarshal(preview.Bytes(), &details) != nil || details.Confirm != setupLinkConfirmation(raw) || details.Role != offer.Receiver.MASQUE.Role || details.PublicTLS != offer.Receiver.MASQUE.PublicTLS {
		menuNotice(out, "WARNING", "Original private handoff confirmation is inconsistent; no action taken.")
		return 2
	}
	menuScreen(out, "Review / MASQUE receiver")
	menuField(out, "Link ID", string(offer.Receiver.ID))
	menuField(out, "Backend", "RFC 9484 CONNECT-IP / authenticated HTTP/2 TCP")
	menuField(out, "THIS server role", details.Role)
	menuField(out, "THIS physical source", details.Underlay)
	menuField(out, "OTHER physical endpoint", offer.Receiver.Underlay.Peer.String())
	menuField(out, "THIS private IPv4", details.PrivateIP)
	menuField(out, "OTHER private IPv4", offer.Receiver.Addresses.Peer.String())
	menuField(out, "HTTPS TCP port", fmt.Sprintf("%d", offer.Receiver.MASQUE.TCPPort))
	menuField(out, "TLS server name", safeMenuText(offer.Receiver.MASQUE.TLSServerName))
	if details.PublicTLS {
		menuField(out, "TLS authentication", "Public TLS + per-Link request bearer")
	} else {
		menuField(out, "TLS authentication", "Private mTLS (default)")
	}
	if masquehost.VerifyLocalUnderlay(offer.Receiver.Underlay.Local) != nil {
		menuNotice(out, "WARNING", "This host does not uniquely own the handoff's physical source IP; verify the intended receiver and ip address show before import.")
		return 2
	}
	menuNotice(out, "INFO", "Local physical assignment is verified; remote identity and traffic are not yet proven. Verify the offer SHA256 through an independent trusted channel.")
	// Match Create: inspect and (only on fresh PREPARE consent) install the
	// minimal selected MASQUE prerequisites before staging receiver keys.
	selected := tunnelOption{backend: domain.BackendMASQUE, mode: domain.EncapTLS}
	if prep := menuPrepareSelectedPackages(input, reader, out, errOut, selected, opts); !prep.canContinue {
		menuNotice(out, "INFO", "MASQUE import stopped before any receiver credential or Link change. Complete the selected prerequisites, then import the same original offer.")
		return 0
	}
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		return 2
	}
	fmt.Fprint(out, menuActionPrompt(out, "YES", "Import authenticated MASQUE Link and stage the original receiver identity? Type YES (Enter=no): "))
	answer, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && !strings.EqualFold(answer, "yes") {
		return 0
	}
	if err != nil {
		return 2
	}
	code := linkMASQUECommand([]string{"import-masque", "--stdin", "--confirm", details.Confirm}, strings.NewReader(raw), out, errOut, opts)
	if code == 0 {
		menuNotice(out, "OK", "Receiver Link locally ensured; now verify real authenticated stream and private IPv4 traffic in both directions.")
	} else {
		menuNotice(out, "WARNING", "Receiver import incomplete; preserve the original offer and inspect State and owned resources before retry.")
	}
	return code
}
