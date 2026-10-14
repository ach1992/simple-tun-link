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
	oversized := false
	for count := 0; count < pairing.MaxLinkBytes+64*1024; count++ {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(data) != 0 && !oversized {
				return strings.TrimSuffix(string(data), "\r"), nil
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
			return strings.TrimSuffix(string(data), "\r"), nil
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
// A plain GRE/IPIP offer may be visible on the terminal; a credentialed
// WireGuard/IPsec offer stays protected. Both use the canonical preview
// and import commands, with a freshly typed affirmative after the preview.
func menuImport(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	for {
		fmt.Fprintln(out, "\nIMPORT SETUP LINK — join a tunnel created on the OTHER server")
		fmt.Fprintln(out, "  1  GRE / IPIP link (plaintext; pasted text will be visible)")
		fmt.Fprintln(out, "  2  WireGuard / IPsec (contains secret keys; paste hidden)")
		fmt.Fprintln(out, "  0  Back")
		fmt.Fprint(out, "Choose type [1]: ")
		mode, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			fmt.Fprintln(out, "Invalid input; choose 0, 1 or 2.")
			continue
		}
		if mode == "" {
			mode = "1"
		}
		if mode == "0" || strings.EqualFold(mode, "q") {
			return 0
		}
		if mode != "1" && mode != "2" {
			fmt.Fprintln(out, "Choose 1 for ordinary GRE/IPIP or 2 for protected credentials.")
			continue
		}
		// Once chosen, a bad paste retries THIS prompt; the operator does
		// not have to navigate the backend choice again.
		for {
			if mode == "1" {
				fmt.Fprintln(out, "Paste the GRE/IPIP stl:// line. It is not encrypted and WILL be visible while typing.")
			} else {
				fmt.Fprintln(out, "Paste the secret-bearing stl:// line. Terminal input is hidden to protect peer keys.")
			}
			fmt.Fprintln(out, "Copy the FULL setup line, then press Enter. Enter 0 alone to return.")
			fmt.Fprint(out, "Setup link: ")
			var encoded string
			if mode == "2" {
				encoded, err = readPrivateMenuURL(input, reader)
			} else {
				encoded, err = readMenuURL(reader)
			}
			fmt.Fprintln(out)
			if errors.Is(err, io.EOF) {
				return 0
			}
			if errors.Is(err, errMenuInputTooLong) {
				fmt.Fprintln(out, "The pasted line is too long (maximum 24 KB). Copy only ONE complete stl:// line, without surrounding text.")
				continue
			}
			if err != nil {
				fmt.Fprintln(out, "Terminal input was interrupted; no tunnel was changed. Try again.")
				continue
			}
			encoded = strings.TrimSpace(encoded)
			if encoded == "0" || strings.EqualFold(encoded, "q") {
				return 0
			}
			if encoded == "" {
				fmt.Fprintln(out, "No setup link received. Paste a complete stl:// line or choose Back.")
				continue
			}
			if !strings.HasPrefix(encoded, "stl://") {
				fmt.Fprintln(out, "This is not an STL setup link. It must start with stl:// (no commands or surrounding text).")
				continue
			}
			var buffer bytes.Buffer
			if code := linkPreviewCommand([]string{"preview", "--stdin", "--json"},
				strings.NewReader(encoded), &buffer, io.Discard); code != 0 {
				fmt.Fprintln(out, "The setup link could not be read: it may be incomplete, altered, or from an unsupported STL version.")
				fmt.Fprintln(out, "Copy the original COMPLETE line from the other server (Manage -> Share for GRE/IPIP) and retry.")
				continue
			}
			var preview ImportPreviewResponse
			if err := json.Unmarshal(buffer.Bytes(), &preview); err != nil {
				fmt.Fprintln(out, "Cannot interpret the setup preview. No changes applied.")
				continue
			}
			if mode == "1" && (preview.Sensitive || preview.HasCredential) {
				fmt.Fprintln(out, "This setup link contains a private credential. No changes were applied.")
				fmt.Fprintln(out, "Use option 2 (Protected link) so the next paste is hidden.")
				break
			}
			if mode == "2" && !preview.Sensitive && !preview.HasCredential {
				fmt.Fprintln(out, "This is an ordinary plaintext GRE/IPIP setup link; importing it in protected mode is also supported.")
			}
			fmt.Fprintln(out, "\nReview the tunnel you are about to add:")
			fmt.Fprintf(out, "  Type: %s / %s\n", preview.Backend, preview.Encapsulation)
			fmt.Fprintf(out, "  THIS server: %s (tunnel IP %s)\n", preview.LocalUnderlay, preview.LocalAddress)
			fmt.Fprintf(out, "  OTHER server: %s (tunnel IP %s)\n", preview.PeerUnderlay, preview.PeerAddress)
			if preview.HasCredential || preview.Sensitive {
				fmt.Fprintln(out, "  SENSITIVE one-time receiver credential: present but HIDDEN")
			} else if preview.GRE != nil {
				fmt.Fprintln(out, "  GRE: no encryption. Its key is only an identifier.")
			}
			if preview.ImportConfirmation == "" {
				fmt.Fprintln(out, "This offer is preview-only on this STL version. Nothing was changed; use a supported newer offer.")
				continue
			}
			if preview.Backend == "ipsec" {
				fmt.Fprintln(out, "IPsec needs a verified STL-owned strongSwan service before import. Import alone does not connect IKE.")
			}
			fmt.Fprintln(out, "Check that the underlay IPs and both tunnel IPs are correct. Import changes THIS server's configuration.")
			if err := clearQueuedMenuConfirmation(input, reader); err != nil {
				fmt.Fprintln(out, "Cannot establish a fresh terminal confirmation; nothing was imported.")
				return 2
			}
			fmt.Fprint(out, "Import this tunnel? Type YES to confirm (Enter=no): ")
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
			code := linkImportCommand([]string{"import", "--stdin", "--confirm", preview.ImportConfirmation},
				strings.NewReader(encoded), out, errOut, options)
			if code != 0 {
				fmt.Fprintln(out, "Import was not confirmed. Check the reported reason, existing saved tunnels, and peer before another attempt.")
			} else {
				fmt.Fprintln(out, "Import finished. Both servers can now use Test connectivity to check tunnel traffic.")
			}
			return code
		}
	}
}
