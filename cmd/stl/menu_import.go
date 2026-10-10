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
	data := make([]byte, 0, 256)
	for len(data) <= pairing.MaxLinkBytes {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) != 0 {
				return strings.TrimSuffix(string(data), "\r"), nil
			}
			return "", err
		}
		if b == '\n' {
			return strings.TrimSuffix(string(data), "\r"), nil
		}
		data = append(data, b)
	}
	return "", errMenuInputTooLong
}

// On a terminal, prevent echo of a pasted offer before it is even decoded:
// unsupported offers may contain receiver private keys. Terminal settings
// are always restored before any preview, confirmation or network apply.
// Nonterminal streams already have no kernel terminal echo.
func readPrivateMenuURL(input io.Reader, reader *bufio.Reader) (url string, err error) {
	file, ok := input.(*os.File)
	if !ok {
		return readMenuURL(reader)
	}
	fd := int(file.Fd())
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if errors.Is(err, unix.ENOTTY) {
		// An ordinary redirected file/pipe does not have terminal echo.
		return readMenuURL(reader)
	}
	if err != nil {
		// An unreadable/indeterminate terminal must not silently fall back
		// to an input mode that could echo credentials.
		return "", errors.New("cannot inspect protected terminal input")
	}
	masked := *before
	masked.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &masked); err != nil {
		return "", errors.New("cannot protect terminal input")
	}
	defer func() {
		if resetErr := unix.IoctlSetTermios(fd, unix.TCSETS, before); resetErr != nil {
			url = ""
			err = errors.New("cannot restore terminal input settings")
		}
	}()
	return readMenuURL(reader)
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
func menuImport(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	fmt.Fprintln(out, "Paste only after the next prompt. Terminal echo will be suppressed while reading.")
	fmt.Fprintln(out, "Do not pass setup URLs as command arguments or paste them into shell history.")
	fmt.Fprint(out, "Setup link: ")
	encoded, err := readPrivateMenuURL(input, reader)
	fmt.Fprintln(out)
	if err != nil || encoded == "" {
		fmt.Fprintln(errOut, "setup link input unavailable or too large; nothing was applied")
		return 2
	}

	var previewBuffer bytes.Buffer
	if code := linkPreviewCommand([]string{"preview", "--stdin", "--json"},
		strings.NewReader(encoded), &previewBuffer, io.Discard); code != 0 {
		fmt.Fprintln(errOut, "setup link is invalid or unsupported; nothing was applied")
		return code
	}
	var preview ImportPreviewResponse
	if err := json.Unmarshal(previewBuffer.Bytes(), &preview); err != nil {
		fmt.Fprintln(errOut, "cannot interpret redacted setup preview; nothing was applied")
		return 1
	}
	fmt.Fprintf(out, "PREVIEW ONLY: Link %s, %s/%s, mode %s\n",
		preview.LinkID, preview.Backend, preview.Encapsulation, preview.Mode)
	fmt.Fprintf(out, "Receiver underlay %s, peer underlay %s\n",
		preview.LocalUnderlay, preview.PeerUnderlay)
	fmt.Fprintf(out, "Receiver Link Address %s, peer Link Address %s\n",
		preview.LocalAddress, preview.PeerAddress)
	if g := preview.GRE; g != nil {
		fmt.Fprintf(out, "GRE: key_enabled=%t key=%d udp_port=%d ttl=%d tos=%d disable_pmtud=%t checksum=%t sequence=%t\n",
			g.KeyEnabled, g.Key, g.UDPPort, g.TTL, g.TOS, g.DisablePMTUD, g.Checksum, g.Sequence)
	}
	if w := preview.WireGuard; w != nil {
		fmt.Fprintf(out, "WireGuard local public key %s, peer public key %s\n", w.LocalPublicKey, w.PeerPublicKey)
		fmt.Fprintf(out, "WireGuard receive port %d, peer port %d, local keepalive %d, peer keepalive %d\n",
			w.ListenPort, w.PeerPort, w.LocalKeepalive, w.PeerKeepalive)
	}
	if preview.HasCredential || preview.Sensitive {
		fmt.Fprintln(out, "Recipient credentials: present / REDACTED (SENSITIVE)")
	}
	if preview.ImportConfirmation == "" {
		fmt.Fprintln(out, "Protected credential import is not available yet. No changes were applied.")
		return 0
	}

	fmt.Fprintln(out, "Quick Links are neither encrypted nor peer-authenticated. Verify sender and recipient identity separately.")
	fmt.Fprintln(out, "This apply changes local network state via the canonical Link Engine.")
	fmt.Fprintln(out, "Existing Link IDs with different saved configuration are never reconfigured by import.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "cannot ensure a fresh terminal confirmation; nothing was applied")
		return 2
	}
	fmt.Fprintf(out, "To APPLY, type exact Link ID %s (Enter cancels): ", preview.LinkID)
	confirm, err := readMenuAnswer(reader)
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(errOut, "invalid confirmation; nothing was applied")
		return 2
	}
	if errors.Is(err, io.EOF) || confirm != string(preview.LinkID) {
		fmt.Fprintln(out, "Import cancelled; nothing was applied.")
		return 0
	}
	return linkImportCommand([]string{"import", "--stdin", "--confirm", preview.ImportConfirmation},
		strings.NewReader(encoded), out, errOut, options)
}
