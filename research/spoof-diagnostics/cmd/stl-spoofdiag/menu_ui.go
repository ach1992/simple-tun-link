package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// menu is deliberately a thin operator presentation layer. All mutating
// operations route to the same CLI/engine used by automation.
func menu() error {
	reader := bufio.NewReaderSize(os.Stdin, 64*1024)
	for {
		menuHeader()
		fmt.Fprint(os.Stdout, "Choose [0-8] (or q): ")
		choice, err := menuRead(reader)
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stdout, "\nSession ended.")
			return nil
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Input error:", err)
			continue
		}
		var opErr error
		switch strings.ToLower(choice) {
		case "0", "q", "quit", "exit":
			fmt.Fprintln(os.Stdout, "Goodbye. No background agent was started.")
			return nil
		case "1":
			opErr = preflight()
		case "2":
			opErr = pretty(versionInfo())
		case "3":
			opErr = menuSources(reader)
		case "4":
			opErr = menuEvidence(reader)
		case "5":
			opErr = menuCreateChallenge(reader)
		case "6":
			opErr = menuVerifyReceipt(reader)
		case "7":
			opErr = menuOfflineIdentity(reader)
		case "8", "h", "help":
			menuHelp()
		default:
			fmt.Fprintln(os.Stderr, "Unknown choice. Enter a number from 0 to 8, or q to exit.")
		}
		if opErr != nil {
			fmt.Fprintln(os.Stderr, "Operation not completed:", opErr, "\nNo success was recorded. Correct the input and choose the operation again.")
		}
	}
}

func menuHeader() {
	width := 72
	if c, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && c >= 48 && c <= 120 {
		width = c
	}
	line := strings.Repeat("=", width)
	fmt.Fprintln(os.Stdout, "\n"+line)
	fmt.Fprintln(os.Stdout, "STL SPOOF DIAGNOSTICS   |   standalone research tool")
	fmt.Fprintf(os.Stdout, "Version: %s   Git: %.12s   Host: %s/%s\n", version, commit, runtime.GOOS, runtime.GOARCH)
	fmt.Fprintln(os.Stdout, "Mode: loopback + isolated private netns laboratory only")
	fmt.Fprintln(os.Stdout, "Field traffic: DISABLED   |   Real provider reachability: NOT_TESTED")
	fmt.Fprintln(os.Stdout, "Evidence levels: SUBMITTED != PEER_OBSERVED != RETURN_PATH != PRIVATE_L3")
	fmt.Fprintln(os.Stdout, "Keys/CA: operator-managed; never share a private CA signing key.")
	fmt.Fprintln(os.Stdout, line)
	fmt.Fprintln(os.Stdout, "1) Host prerequisites & diagnostic   2) Version and build identity")
	fmt.Fprintln(os.Stdout, "3) Source IP inventory               4) Read declared evidence")
	fmt.Fprintln(os.Stdout, "5) Create signed lab challenge       6) Verify signed peer receipt")
	fmt.Fprintln(os.Stdout, "7) Create disposable local identities 8) Help / usage & safety")
	fmt.Fprintln(os.Stdout, "0) Exit")
}

func menuRead(r *bufio.Reader) (string, error) {
	// Reader is bounded; reject an entire oversized line before interpreting it.
	var b []byte
	for {
		chunk, prefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		if len(b)+len(chunk) > 16*1024 {
			// Drain remainder, to keep the next menu prompt aligned.
			for prefix {
				_, prefix, err = r.ReadLine()
				if err != nil {
					break
				}
			}
			return "", errors.New("input too long (maximum 16384 bytes)")
		}
		b = append(b, chunk...)
		if !prefix {
			return strings.TrimSpace(string(b)), nil
		}
	}
}

func menuAsk(r *bufio.Reader, label string) (string, error) {
	fmt.Fprint(os.Stdout, label, ": ")
	return menuRead(r)
}

func menuAskNonempty(r *bufio.Reader, label string) (string, error) {
	v, err := menuAsk(r, label)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New(label + " is required")
	}
	return v, nil
}

func menuSources(r *bufio.Reader) error {
	fmt.Fprintln(os.Stdout, "\nSource inventory (offline only): 1) List  2) Add  3) Import  4) Remove  5) Replace  0) Back")
	action, err := menuAsk(r, "Action")
	if err != nil {
		return err
	}
	if action == "0" || strings.EqualFold(action, "back") {
		return nil
	}
	if action != "1" && action != "2" && action != "3" && action != "4" && action != "5" {
		return errors.New("choose an inventory action from 0 to 5")
	}
	path, err := menuAskNonempty(r, "Owned JSON inventory path")
	if err != nil {
		return err
	}
	switch action {
	case "1":
		return sourceCommand([]string{"list", "--file", path})
	case "2":
		mode, err := menuAsk(r, "Mode for a NEW file (private_lab; blank for existing)")
		if err != nil {
			return err
		}
		ip, err := menuAskNonempty(r, "Exact source IPv4")
		if err != nil {
			return err
		}
		dir, err := menuAskNonempty(r, "Direction (A_TO_B or B_TO_A)")
		if err != nil {
			return err
		}
		sender, err := menuAskNonempty(r, "Sender role (A or B)")
		if err != nil {
			return err
		}
		receiver, err := menuAskNonempty(r, "Receiver role (B or A)")
		if err != nil {
			return err
		}
		args := []string{"add", "--file", path, "--ip", ip, "--direction", dir, "--sender", sender, "--receiver", receiver}
		if mode != "" {
			args = append(args, "--mode", mode)
		}
		return sourceCommand(args)
	case "3":
		from, err := menuAskNonempty(r, "Exact existing CSV or JSON input path")
		if err != nil {
			return err
		}
		return sourceCommand([]string{"import", "--file", path, "--from", from})
	case "4", "5":
		ip, err := menuAskNonempty(r, "Existing source IPv4")
		if err != nil {
			return err
		}
		dir, err := menuAskNonempty(r, "Existing direction (A_TO_B or B_TO_A)")
		if err != nil {
			return err
		}
		sender, err := menuAskNonempty(r, "Existing sender role")
		if err != nil {
			return err
		}
		receiver, err := menuAskNonempty(r, "Existing receiver role")
		if err != nil {
			return err
		}
		verb := "remove"
		if action == "5" {
			verb = "replace"
		}
		args := []string{verb, "--file", path, "--old-ip", ip, "--old-direction", dir, "--old-sender", sender, "--old-receiver", receiver}
		if action == "5" {
			newIP, err := menuAskNonempty(r, "NEW source IPv4")
			if err != nil {
				return err
			}
			newDir, err := menuAskNonempty(r, "NEW direction")
			if err != nil {
				return err
			}
			newSender, err := menuAskNonempty(r, "NEW sender role")
			if err != nil {
				return err
			}
			newReceiver, err := menuAskNonempty(r, "NEW receiver role")
			if err != nil {
				return err
			}
			args = append(args, "--ip", newIP, "--direction", newDir, "--sender", newSender, "--receiver", newReceiver)
		}
		return sourceCommand(args)
	}
	return nil
}

func menuEvidence(r *bufio.Reader) error {
	path, err := menuAskNonempty(r, "Existing declared evidence JSON path")
	if err != nil {
		return err
	}
	return run([]string{"report", "--file", path})
}

func menuCreateChallenge(r *bufio.Reader) error {
	fmt.Fprintln(os.Stdout, "Creates a signed, short-lived LOCAL LAB plan without sending traffic.")
	file, err := menuAskNonempty(r, "Owned private_lab source CSV/JSON")
	if err != nil {
		return err
	}
	cert, err := menuAskNonempty(r, "Local sender certificate PEM path")
	if err != nil {
		return err
	}
	key, err := menuAskNonempty(r, "Local sender private key PEM path (never pasted)")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted laboratory CA public certificate path")
	if err != nil {
		return err
	}
	sender, err := menuAskNonempty(r, "Sender role (A or B)")
	if err != nil {
		return err
	}
	receiver, err := menuAskNonempty(r, "Receiver role (B or A)")
	if err != nil {
		return err
	}
	out, err := menuAskNonempty(r, "New challenge output JSON path")
	if err != nil {
		return err
	}
	return labCLI([]string{"challenge", "--file", file, "--cert", cert, "--key", key, "--ca", ca, "--sender", sender, "--receiver", receiver, "--out", out})
}

func menuVerifyReceipt(r *bufio.Reader) error {
	challenge, err := menuAskNonempty(r, "Existing sender-signed challenge JSON path")
	if err != nil {
		return err
	}
	receipt, err := menuAskNonempty(r, "Existing receiver-signed receipt JSON path")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted CA public certificate path")
	if err != nil {
		return err
	}
	return labCLI([]string{"offline-verify", "--challenge", challenge, "--receipt", receipt, "--ca", ca})
}

func menuOfflineIdentity(r *bufio.Reader) error {
	fmt.Fprintln(os.Stdout, "Disposable LOCAL LAB only. Output contains CA private key plus both node private keys.")
	dir, err := menuAskNonempty(r, "New PRIVATE directory path (must not already exist)")
	if err != nil {
		return err
	}
	agree, err := menuAsk(r, "Type LOCAL to create expendable credentials")
	if err != nil {
		return err
	}
	if agree != "LOCAL" {
		return errors.New("not authorized: type LOCAL only for a disposable local laboratory")
	}
	return labCLI([]string{"identity", "--dir", dir})
}

func menuHelp() {
	fmt.Fprintln(os.Stdout, "\nRequirements: Linux amd64/arm64 binary matching this host; no Go/Python at runtime.")
	fmt.Fprintln(os.Stdout, "Offline: verify independently trusted archive identity, then run install-offline.sh --verify and --install.")
	fmt.Fprintln(os.Stdout, "Local peers: lab serve/run for loopback mTLS; lab challenge/offline-listen/offline-send/offline-verify for signed evidence.")
	fmt.Fprintln(os.Stdout, "Raw RFC1918 netns adapter is confined to an independently isolated, no-WAN, test-owned topology.")
	fmt.Fprintln(os.Stdout, "Troubleshooting: check exact IP, direction, CA/certificate role and expiry, firewall, route, MTU, permissions and listener state.")
	fmt.Fprintln(os.Stdout, "Receipt with zero packets is INCONCLUSIVE; NO field/provider admission, sender return or private L3 is implied.")
	fmt.Fprintln(os.Stdout, "Detailed commands and acceptance: README-GO.md and docs/VALIDATION-MATRIX.md in the source tree.")
	fmt.Fprintln(os.Stdout, "Use the CLI for automation; never parse text menus or send private keys in logs/chat.")
}
