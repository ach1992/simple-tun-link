package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// A narrow test seam for the three canonical actions. Production always
// supplies the real read-only Status/Diagnose and Engine-backed Connect.
type menuIPsecConnectActions struct {
	status  func(domain.LinkID, *runtimeOptions) (linkStatusResponse, []byte, int)
	connect func([]string, io.Writer, io.Writer, *runtimeOptions) int
	check   func(domain.LinkID, io.Writer, io.Writer, *runtimeOptions) int
}

// A human-facing optional action, NEVER part of Status/Diagnose.
// Reuses the existing canonical Engine-locked connect-ipsec command rather
// than attempting direct swanctl, kernel, firewall or service operations.
func menuConnectIPsec(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, selected domain.Link) int {
	return menuConnectIPsecWithActions(input, reader, out, errOut, options, selected, menuIPsecConnectActions{
		status:  menuReadVerifiedStatus,
		connect: linkIPsecLifecycleCommand,
		check:   menuCheckOneConnection,
	})
}

func menuConnectIPsecWithActions(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, selected domain.Link, actions menuIPsecConnectActions) int {
	if actions.status == nil || actions.connect == nil || actions.check == nil {
		menuNotice(out, "WARNING", "IPsec Connect backend unavailable; no initiation started.")
		return 1
	}
	if selected.Backend != domain.BackendIPsec || selected.ID.Validate() != nil {
		menuNotice(out, "WARNING", "This action is only for an existing IPsec tunnel.")
		return 2
	}
	stdin, stdinOK := input.(*os.File)
	_, stdoutOK := menuTerminal(out)
	if !stdinOK || !stdoutOK || !terminalIsInteractive(stdin) {
		menuCopyLine(out, "Once both ends are imported, initiate with",
			"stl link connect-ipsec "+string(selected.ID)+" --confirm "+string(selected.ID))
		menuProse(out, "Connecting changes IKE/IPsec session state and requires explicit operator consent. No connection was started.")
		return 0
	}

	// Do not use a stale saved-menu row as authorization for another Link.
	current, err := savedMenuLinks(options)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot inspect the saved IPsec tunnel. No connection started.")
		return 1
	}
	matches := false
	for _, row := range current {
		if row.Desired.ID == selected.ID {
			matches = row.Desired == selected
			break
		}
	}
	if !matches {
		menuNotice(out, "WARNING", "The saved IPsec Link changed or was removed. Reselect it before connecting.")
		return 1
	}

	status, _, statusCode := actions.status(selected.ID, options)
	if statusCode != 0 || status.IPsecState == nil || !status.InterfaceVerified ||
		!status.IPsecState.ConnectionConfigured {
		menuNotice(out, "WARNING", "Cannot verify the exact local IPsec interface and configuration. No initiation started.")
		menuProse(out, "Run stl doctor ipsec and the read-only Local status first.")
		return 1
	}
	if status.IPsecState.SecurityAssociationPresent {
		menuNotice(out, "OK", "IPsec security association already observed. Checking peer traffic without reconnecting.")
		return actions.check(selected.ID, out, errOut, options)
	}

	menuScreen(out, "IPsec / connect after both sides are configured")
	menuField(out, "Type", "ipsec / "+string(selected.Encapsulation))
	menuField(out, "Local IP", selected.Addresses.Local.String())
	menuField(out, "Other IP", selected.Addresses.Peer.String())
	menuNotice(out, "WARNING", "This explicitly starts IKEv2 for ONLY this saved tunnel; it may contact the peer and create an IPsec SA.")
	menuProse(out, "Ensure the OTHER server has already completed import. No firewall, routing, service or other tunnel is changed by this menu action.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Could not clear pre-entered terminal input. No IKE initiation started.")
		return 2
	}
	fmt.Fprint(out, menuActionPrompt(out, "CONNECT", "To initiate IKEv2, type CONNECT (Enter cancels): "))
	typed, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && typed != "CONNECT" {
		fmt.Fprintln(out, "IPsec connection cancelled. Saved tunnel unchanged.")
		return 0
	}
	if err != nil {
		menuNotice(out, "WARNING", "Invalid confirmation. No initiation started.")
		return 2
	}
	// A second current-state check closes ordinary menu-selection staleness;
	// the Engine performs the authoritative locked ownership checks.
	current, err = savedMenuLinks(options)
	if err != nil {
		menuNotice(out, "WARNING", "Could not recheck saved Link identity. No initiation started.")
		return 1
	}
	matches = false
	for _, row := range current {
		if row.Desired.ID == selected.ID {
			matches = row.Desired == selected
			break
		}
	}
	if !matches {
		menuNotice(out, "WARNING", "IPsec Link changed while waiting for confirmation. No initiation started.")
		return 1
	}
	menuScreen(out, "IPsec / verifying SA and connecting if needed")
	code := actions.connect([]string{"connect-ipsec", string(selected.ID),
		"--confirm", string(selected.ID)}, out, errOut, options)
	if code != 0 {
		menuNotice(out, "WARNING", "IKE initiation failed or outcome is unknown. Inspect Local status before another attempt.")
		return code
	}
	// Accepted initiation is not SA or packet-delivery proof. Reuse the
	// canonical read-only bounded probe for the actual outcome.
	return actions.check(selected.ID, out, errOut, options)
}
