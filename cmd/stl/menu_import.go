package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/pairing"
	"golang.org/x/sys/unix"
)

// readMenuURL reads exactly one line, bounded by the canonical pairing wire
// limit. It does not read until EOF, which would block at an interactive TTY.
func readMenuURL(reader *bufio.Reader) (string, error) {
	return readMenuURLWithDelimiter(reader, true)
}

// For secret-bearing Setup Links, never discard an unexpected raw CR or
// other control before the strict paste grammar can reject it. Ordinary
// visible GRE/IPIP paste retains its original CRLF compatibility.
func readPrivateMenuLine(reader *bufio.Reader) (string, error) {
	return readMenuURLWithDelimiter(reader, false)
}

func readMenuURLWithDelimiter(reader *bufio.Reader, stripCR bool) (string, error) {
	ending := func(data []byte) string {
		if stripCR {
			return strings.TrimSuffix(string(data), "\r")
		}
		return string(data)
	}
	data := make([]byte, 0, 256)
	oversized := false
	for count := 0; count < pairing.MaxLinkBytes+64*1024; count++ {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) != 0 && !oversized {
				return ending(data), nil
			}
			if oversized {
				return "", errMenuInputTooLong
			}
			return "", err
		}
		if b == '\n' {
			if oversized {
				return "", errMenuInputTooLong
			}
			return ending(data), nil
		}
		if len(data) < pairing.MaxLinkBytes {
			data = append(data, b)
		} else {
			oversized = true
		}
	}
	return "", errMenuInputTooLong
}

// On a terminal, prevent echo of a pasted offer before it is even decoded:
// unsupported offers may contain receiver private keys. Terminal settings
// are always restored before any preview, confirmation or network apply.
// Nonterminal streams already have no kernel terminal echo.
func readPrivateMenuURL(input io.Reader, reader *bufio.Reader) (url string, err error) {
	return readPrivateMenuURLWithPrompt(input, reader, nil)
}

// The first visible secret-paste prompt MUST be printed after terminal ECHO
// has been disabled. Keeping prompt and read inside one protected operation
// avoids a race where the user pastes immediately when the prompt appears.
func readPrivateMenuURLWithPrompt(input io.Reader, reader *bufio.Reader, prompt func()) (url string, err error) {
	showPrompt := func() {
		if prompt != nil {
			prompt()
		}
	}
	file, ok := input.(*os.File)
	if !ok {
		showPrompt()
		return readPrivateMenuLine(reader)
	}
	fd := int(file.Fd())
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if errors.Is(err, unix.ENOTTY) {
		// An ordinary redirected file/pipe does not have terminal echo.
		showPrompt()
		return readPrivateMenuLine(reader)
	}
	if err != nil {
		// An unreadable/indeterminate terminal must not silently fall back
		// to an input mode that could echo credentials.
		return "", errors.New("cannot inspect protected terminal input")
	}
	masked := *before
	masked.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &masked); err != nil {
		// The terminal driver may have changed flags before reporting a
		// failure. No protected prompt has been exposed; nevertheless
		// attempt to restore the exact original state before refusing.
		if unix.IoctlSetTermios(fd, unix.TCSETS, before) != nil {
			return "", errors.New("cannot protect or restore terminal input")
		}
		return "", errors.New("cannot protect terminal input")
	}
	defer func() {
		if resetErr := unix.IoctlSetTermios(fd, unix.TCSETS, before); resetErr != nil {
			url = ""
			err = errors.New("cannot restore terminal input settings")
		}
	}()
	showPrompt()
	return readPrivateMenuLine(reader)
}

// normalizeMenuSetupPaste removes only exact, known clipboard presentation
// framing. The strict canonical Setup Link decoder still validates the full
// opaque token; never attempt to repair a partial token or strip arbitrary
// terminal controls from secret-bearing input.
func normalizeMenuSetupPaste(raw string) (string, bool) {
	// Validate the RAW input before any trimming. Only ASCII space is an
	// allowed presentation separator; TrimSpace would silently discard
	// TAB, vertical tab, form feed and other unexpected controls.
	const start, end = "\x1b[200~", "\x1b[201~"
	value := raw
	if strings.HasPrefix(value, start) {
		if !strings.HasSuffix(value, end) {
			return "", false
		}
		value = strings.TrimSuffix(strings.TrimPrefix(value, start), end)
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return "", false
		}
	}
	value = strings.Trim(value, " ")
	const label = "Setup link:"
	if len(value) >= len(label) && strings.EqualFold(value[:len(label)], label) {
		if !strings.HasPrefix(value, label) {
			return "", false
		}
		value = strings.TrimLeft(value[len(label):], " ")
	}
	// Raw ESC outside the exact framing is never a valid data character.
	// The canonical Setup Link decoder still checks the entire token.
	return value, true
}

// Before asking for an APPLY confirmation, discard terminal bytes that
// might have been pasted with the setup URL. A pre-pasted second line must
// not count as review/confirmation of details that appeared only afterwards.
func clearQueuedMenuConfirmation(input io.Reader, reader *bufio.Reader) error {
	file, ok := input.(*os.File)
	if !ok {
		return nil
	}
	fd := int(file.Fd())
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if errors.Is(err, unix.ENOTTY) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect confirmation terminal")
	}
	if _, err := reader.Discard(reader.Buffered()); err != nil {
		return errors.New("cannot discard queued terminal input")
	}
	if err := unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH); err != nil {
		return errors.New("cannot clear queued terminal confirmation")
	}
	return nil
}

// menuImport delegates all decoding, preview, canonical inversion,
// import eligibility, state locking and mutation to existing commands.
// The extra operator confirmation is intentionally human-only.
// A plain GRE/IPIP offer may be visible on the terminal; a credentialed
// WireGuard/IPsec offer stays protected. Both use the canonical preview
// and import commands, with a freshly typed affirmative after the preview.
func menuImport(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	for {
		menuScreen(out, "Import Setup Link / choose type")
		menuOption(out, "1", "GRE / IPIP", "Unencrypted; visible paste")
		menuOption(out, "2", "WireGuard / IPsec", "Sensitive; hidden paste")
		menuOption(out, "3", "WireGuard / WSS + TLS", "Sensitive peer JSON; hidden paste")
		menuOption(out, "0", "Back", "Main menu")
		fmt.Fprint(out, "Choose type [1]: ")
		mode, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			menuNotice(out, "WARNING", "Choose a listed number: 0, 1, 2 or 3.")
			continue
		}
		if mode == "" {
			mode = "1"
		}
		if mode == "0" || strings.EqualFold(mode, "q") {
			return 0
		}
		if mode != "1" && mode != "2" && mode != "3" {
			menuNotice(out, "WARNING", "Choose 1 for GRE/IPIP, 2 for WireGuard/IPsec or 3 for WireGuard/WSS.")
			continue
		}
		if mode == "3" {
			return menuImportWSS(input, reader, out, errOut, options)
		}
		// Only display a secret-bearing paste prompt AFTER ECHO is masked.
		// The protected operation also owns terminal restoration on every
		// path. Validation retries do not require reselecting a type.
		for {
			prompt := func() {
				menuScreen(out, "Import / paste complete Setup Link")
				if mode == "1" {
					fmt.Fprintln(out, "Paste the GRE/IPIP stl:// line. It is not encrypted and WILL be visible while typing.")
				} else {
					fmt.Fprintln(out, "Paste the secret-bearing stl:// line. Terminal input is hidden to protect peer keys.")
				}
				fmt.Fprintln(out, "Copy the FULL setup line, then press Enter. Enter 0 alone to return.")
				fmt.Fprint(out, "Setup link: ")
			}
			var encoded string
			if mode == "2" {
				encoded, err = readPrivateMenuURLWithPrompt(input, reader, prompt)
			} else {
				prompt()
				encoded, err = readMenuURL(reader)
			}
			fmt.Fprintln(out)
			if errors.Is(err, io.EOF) {
				return 0
			}
			if errors.Is(err, errMenuInputTooLong) {
				menuNotice(out, "WARNING", "Setup Link too long (maximum 24 KB). Copy one complete stl:// line.")
				continue
			}
			if err != nil {
				menuNotice(out, "WARNING", "Paste interrupted. No tunnel changed; retry the same Setup Link.")
				continue
			}
			encoded, ok := normalizeMenuSetupPaste(encoded)
			if !ok {
				menuNotice(out, "WARNING", "Paste contains unexpected terminal control bytes. Copy only the complete Setup Link and retry; no changes made.")
				continue
			}
			if encoded == "0" || strings.EqualFold(encoded, "q") {
				return 0
			}
			if encoded == "" {
				menuNotice(out, "WARNING", "No Setup Link received. Paste one complete stl:// line or choose Back.")
				continue
			}
			if !strings.HasPrefix(encoded, "stl://") {
				menuNotice(out, "WARNING", "This is not an STL setup link. Paste the complete stl:// line.")
				continue
			}
			var buffer bytes.Buffer
			if code := linkPreviewCommand([]string{"preview", "--stdin", "--json"},
				strings.NewReader(encoded), &buffer, io.Discard); code != 0 {
				menuProse(out, "The setup link could not be read: it may be incomplete, altered, or from an unsupported STL version.")
				menuProse(out, "Copy the original COMPLETE line from the other server (Manage -> Share for GRE/IPIP) and retry.")
				continue
			}
			var preview ImportPreviewResponse
			if err := json.Unmarshal(buffer.Bytes(), &preview); err != nil {
				menuNotice(out, "WARNING", "Setup Link preview unavailable; no changes applied.")
				continue
			}
			if mode == "1" && (preview.Sensitive || preview.HasCredential) {
				fmt.Fprintln(out, "This setup link contains a private credential. No changes were applied.")
				fmt.Fprintln(out, "Use option 2 (Protected link) so the next paste is hidden.")
				break
			}
			if mode == "2" && !preview.Sensitive && !preview.HasCredential {
				menuProse(out, "This is an ordinary plaintext GRE/IPIP setup link; importing it in protected mode is also supported.")
			}
			menuScreen(out, "Import / review before applying")
			menuField(out, "Type", fmt.Sprintf("%s / %s", preview.Backend, preview.Encapsulation))
			menuField(out, "Local endpoint", preview.LocalUnderlay)
			menuField(out, "Local tunnel IP", preview.LocalAddress)
			menuField(out, "Remote endpoint", preview.PeerUnderlay)
			menuField(out, "Remote tunnel IP", preview.PeerAddress)
			if preview.HasCredential || preview.Sensitive {
				menuNotice(out, "WARNING", "SENSITIVE receiver credential present but HIDDEN. Share only privately.")
			} else if preview.GRE != nil {
				menuNotice(out, "WARNING", "GRE is unencrypted; its key is only an identifier.")
			}
			if preview.ImportConfirmation == "" {
				menuProse(out, "This offer is preview-only on this STL version. Nothing was changed; use a supported newer offer.")
				continue
			}
			if preview.Backend == "ipsec" {
				menuProse(out, "IPsec needs a verified STL-owned strongSwan service before import. Import alone does not connect IKE.")
			}
			menuProse(out, "Check that the underlay IPs and both tunnel IPs are correct. Import changes THIS server's configuration.")
			if err := clearQueuedMenuConfirmation(input, reader); err != nil {
				fmt.Fprintln(out, "Cannot establish a fresh terminal confirmation; nothing was imported.")
				return 2
			}
			fmt.Fprint(out, menuActionPrompt(out, "YES", "Import this tunnel? Type YES to confirm (Enter=no): "))
			confirm, err := readMenuAnswer(reader)
			if errors.Is(err, io.EOF) {
				return 0
			}
			if err != nil {
				fmt.Fprintln(out, "Invalid confirmation; no tunnel imported.")
				continue
			}
			if !strings.EqualFold(confirm, "yes") {
				fmt.Fprintln(out, "Import cancelled. No changes applied.")
				return 0
			}
			menuScreen(out, "Applying / importing tunnel")
			menuSection(out, "Importing and verifying local tunnel")
			code := linkImportCommand([]string{"import", "--stdin", "--confirm", preview.ImportConfirmation},
				strings.NewReader(encoded), out, errOut, options)
			if code != 0 {
				if !menuSessionErrorTTY(out, errOut) {
					menuNotice(out, "WARNING", "Import unconfirmed. Inspect current State before retrying.")
				}
			} else {
				menuScreen(out, "Import / complete")
				menuNotice(out, "OK", "Tunnel imported locally. Remote connectivity is not yet verified.")
				if preview.Backend == "ipsec" {
					menuProse(out, "IPsec import configures the local Link; it does not start IKEv2. After both ends are configured, use My tunnels -> Connect IPsec, then Test connectivity.")
					// A real terminal can opt in to the canonical exact-Link
					// Connect immediately after import; it is never automatic.
					if _, terminal := menuTerminal(out); terminal {
						if current, loadErr := savedMenuLinks(options); loadErr == nil {
							for _, row := range current {
								if row.Desired.ID == preview.LinkID && row.Desired.Backend == "ipsec" {
									menuConnectIPsec(input, reader, out, errOut, options, row.Desired)
									break
								}
							}
						}
					}
				} else {
					fmt.Fprintln(out, "Next: Test connectivity on both servers (5 peer pings and latency).")
				}
			}
			return code
		}
	}
}
