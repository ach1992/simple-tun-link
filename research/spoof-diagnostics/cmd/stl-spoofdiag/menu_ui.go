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
		fmt.Fprint(os.Stdout, "Choose [0-15] (or q): ")
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
		case "9":
			opErr = menuLoopbackAgent(reader, "serve")
		case "10":
			opErr = menuLoopbackAgent(reader, "run")
		case "11":
			opErr = menuOfflineAgent(reader, "offline-listen")
		case "12":
			opErr = menuOfflineAgent(reader, "offline-send")
		case "13":
			opErr = menuPeerReceipt(reader)
		case "14":
			opErr = menuPlan(reader)
		case "15":
			opErr = menuIsolatedNetnsAgent(reader)
		default:
			fmt.Fprintln(os.Stderr, "Unknown choice. Enter a number from 0 to 15, or q to exit.")
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
	fmt.Fprintln(os.Stdout, "STL SPOOF DIAGNOSTICS   |   standalone Go utility")
	fmt.Fprintf(os.Stdout, "Version: %s   Git: %.12s   Host: %s/%s\n", version, commit, runtime.GOOS, runtime.GOARCH)
	fmt.Fprintln(os.Stdout, "Mode: loopback + isolated private netns laboratory only")
	fmt.Fprintln(os.Stdout, "Field traffic: DISABLED   |   Real provider reachability: NOT_TESTED")
	fmt.Fprintln(os.Stdout, "Evidence levels: SUBMITTED != PEER_OBSERVED != RETURN_PATH != PRIVATE_L3")
	fmt.Fprintln(os.Stdout, line)
	fmt.Fprintln(os.Stdout, "INSPECT / PLAN")
	fmt.Fprintln(os.Stdout, " 1) Host prerequisites         2) Version/build identity")
	fmt.Fprintln(os.Stdout, " 3) Edit/list sources           4) Read declared evidence")
	fmt.Fprintln(os.Stdout, "14) Validate an offline candidate plan")
	fmt.Fprintln(os.Stdout, "SIGNED EVIDENCE")
	fmt.Fprintln(os.Stdout, " 5) Create signed challenge     6) Verify signed offline receipt")
	fmt.Fprintln(os.Stdout, " 7) Generate disposable identities")
	fmt.Fprintln(os.Stdout, "13) Verify signed live-session receipt")
	fmt.Fprintln(os.Stdout, "LOCAL LOOPBACK SESSION (run receive/send in separate terminals)")
	fmt.Fprintln(os.Stdout, " 9) Start TLS receiver         10) Run TLS sender")
	fmt.Fprintln(os.Stdout, "11) Start signed-file receiver 12) Run signed-file sender")
	fmt.Fprintln(os.Stdout, "15) Advanced: isolated private netns raw laboratory")
	fmt.Fprintln(os.Stdout, " 8) Help / command reference    0) Exit")
	fmt.Fprintln(os.Stdout, line)
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
		mode, err := menuAsk(r, "NEW file mode (private_lab or approved_field_plan; blank for existing)")
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
	args := []string{"challenge", "--file", file, "--cert", cert, "--key", key, "--ca", ca, "--sender", sender, "--receiver", receiver, "--out", out}
	transport, err := menuAsk(r, "Transport (blank for loopback_transport; isolated_private_raw for detached netns)")
	if err != nil {
		return err
	}
	if transport != "" {
		args = append(args, "--transport", transport)
	}
	if transport == "isolated_private_raw" {
		destination, err := menuAskNonempty(r, "Exact private RFC1918 destination IPv4")
		if err != nil {
			return err
		}
		args = append(args, "--destination-ip", destination)
	}
	return labCLI(args)
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
	fmt.Fprintln(os.Stdout, "Local peers: menu options 9-12 wrap the same loopback mTLS / signed-file CLI engines.")
	fmt.Fprintln(os.Stdout, "Start a loopback receiver in another terminal before invoking its sender; use identical source file/roles/CA.")
	fmt.Fprintln(os.Stdout, "Offline public candidate inventory: new JSON --mode approved_field_plan (no packet emission).")
	fmt.Fprintln(os.Stdout, "Raw RFC1918 netns adapter (option 15) is confined to independently isolated, no-WAN, test-owned topology.")
	fmt.Fprintln(os.Stdout, "Troubleshooting: check exact IP, direction, CA/certificate role and expiry, firewall, route, MTU, permissions and listener state.")
	fmt.Fprintln(os.Stdout, "Receipt with zero packets is INCONCLUSIVE; NO field/provider admission, sender return or private L3 is implied.")
	fmt.Fprintln(os.Stdout, "Detailed commands and acceptance: README.md and docs/VALIDATION-MATRIX.md in the source tree.")
	fmt.Fprintln(os.Stdout, "Use the CLI for automation; never parse text menus or send private keys in logs/chat.")
}

// The interactive actions delegate to the exact same checked CLI paths as
// scripts. Receivers wait for a matching peer or operator interruption, while
// senders and signed-file observation windows enforce their normal timeouts.
func menuLabIdentityFields(r *bufio.Reader, receiver, needsInventory bool) ([]string, error) {
	fields := []string{}
	if needsInventory {
		file, err := menuAskNonempty(r, "Existing local private_lab inventory")
		if err != nil {
			return nil, err
		}
		fields = append(fields, "--file", file)
	}
	label := "Sender"
	if receiver {
		label = "Receiver"
	}
	fmt.Fprintln(os.Stdout, "Use the identity for the local", label, "role. Never paste private-key contents.")
	cert, err := menuAskNonempty(r, "Local node certificate PEM path")
	if err != nil {
		return nil, err
	}
	key, err := menuAskNonempty(r, "Local node private key PEM path")
	if err != nil {
		return nil, err
	}
	ca, err := menuAskNonempty(r, "Trusted test CA certificate PEM path")
	if err != nil {
		return nil, err
	}
	sender, err := menuAskNonempty(r, "Sender role (A or B)")
	if err != nil {
		return nil, err
	}
	recipient, err := menuAskNonempty(r, "Receiver role (B or A)")
	if err != nil {
		return nil, err
	}
	return append(fields, "--cert", cert, "--key", key, "--ca", ca, "--sender", sender, "--receiver", recipient), nil
}

func menuLabPort(r *bufio.Reader, label string, fallback int) (string, error) {
	choice, err := menuAsk(r, fmt.Sprintf("%s (blank for %d)", label, fallback))
	if err != nil {
		return "", err
	}
	if choice == "" {
		return strconv.Itoa(fallback), nil
	}
	port, err := strconv.Atoi(choice)
	if err != nil || port < 1024 || port > 65535 {
		return "", errors.New("port must be 1024..65535")
	}
	return strconv.Itoa(port), nil
}

func menuLoopbackAgent(r *bufio.Reader, op string) error {
	fmt.Fprintln(os.Stdout, "LOCAL LOOPBACK only; receiver and sender must run on the same host.")
	fields, err := menuLabIdentityFields(r, op == "serve", true)
	if err != nil {
		return err
	}
	port, err := menuLabPort(r, "TLS control port", 24001)
	if err != nil {
		return err
	}
	fields = append(fields, "--control-port", port)
	if op == "serve" {
		dataPort, err := menuLabPort(r, "UDP data port", 24002)
		if err != nil {
			return err
		}
		fields = append(fields, "--data-port", dataPort)
	} else if op == "run" {
		out, err := menuAsk(r, "New signed receipt JSON path (blank for no export)")
		if err != nil {
			return err
		}
		if out != "" {
			fields = append(fields, "--out", out)
		}
	}
	return labCLI(append([]string{op}, fields...))
}

func menuOfflineAgent(r *bufio.Reader, op string) error {
	fmt.Fprintln(os.Stdout, "Signed-file LOCAL LOOPBACK operation; signed challenge must still be live.")
	challenge, err := menuAskNonempty(r, "Existing signed challenge JSON")
	if err != nil {
		return err
	}
	fields, err := menuLabIdentityFields(r, op == "offline-listen", op == "offline-listen")
	if err != nil {
		return err
	}
	port, err := menuLabPort(r, "UDP data port", 24002)
	if err != nil {
		return err
	}
	fields = append(fields, "--challenge", challenge, "--data-port", port)
	if op == "offline-listen" {
		state, err := menuAskNonempty(r, "Receiver replay-ledger directory (private mode 0700)")
		if err != nil {
			return err
		}
		out, err := menuAskNonempty(r, "New signed receipt JSON path")
		if err != nil {
			return err
		}
		fields = append(fields, "--state-dir", state, "--out", out)
	}
	return labCLI(append([]string{op}, fields...))
}

func menuPeerReceipt(r *bufio.Reader) error {
	path, err := menuAskNonempty(r, "Existing signed live-session receipt JSON path")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted local CA PEM")
	if err != nil {
		return err
	}
	peer, err := menuAskNonempty(r, "Expected signer DNS identity (spoofdiag-a.local or spoofdiag-b.local)")
	if err != nil {
		return err
	}
	run, err := menuAskNonempty(r, "Independent expected run ID")
	if err != nil {
		return err
	}
	return labCLI([]string{"verify", "--file", path, "--ca", ca, "--peer", peer, "--run", run})
}

func menuPlan(r *bufio.Reader) error {
	path, err := menuAskNonempty(r, "Existing CSV or JSON source inventory")
	if err != nil {
		return err
	}
	return run([]string{"plan", "--file", path})
}

// Advanced isolated kernel lab is not a general field mode. The CLI still
// enforces the namespace, interface, routing, source, signed plan and role
// gates; the menu never constructs packets or bypasses those checks.
func menuIsolatedNetnsAgent(r *bufio.Reader) error {
	fmt.Fprintln(os.Stdout, "ISOLATED PRIVATE NETNS ONLY. Requires detached test-owned sdg* veth, private routing and raw-socket capability.")
	choice, err := menuAsk(r, "Operation: 1) Receive signed samples  2) Send signed samples  0) Back")
	if err != nil || choice == "0" || strings.EqualFold(choice, "back") {
		return err
	}
	if choice != "1" && choice != "2" {
		return errors.New("choose isolated netns action 0, 1 or 2")
	}
	op := "netns-send"
	if choice == "1" {
		op = "netns-listen"
	}
	challenge, err := menuAskNonempty(r, "Existing signed isolated_private_raw challenge JSON")
	if err != nil {
		return err
	}
	fields, err := menuLabIdentityFields(r, choice == "1", choice == "1")
	if err != nil {
		return err
	}
	iface, err := menuAskNonempty(r, "Existing dedicated private veth interface")
	if err != nil {
		return err
	}
	port, err := menuLabPort(r, "Diagnostic UDP destination port", 24572)
	if err != nil {
		return err
	}
	fields = append(fields, "--challenge", challenge, "--interface", iface, "--data-port", port)
	if choice == "1" {
		bind, err := menuAskNonempty(r, "Private RFC1918 receiver interface IPv4")
		if err != nil {
			return err
		}
		state, err := menuAskNonempty(r, "Private receiver consumed-run directory (0700)")
		if err != nil {
			return err
		}
		out, err := menuAskNonempty(r, "New signed receipt JSON path")
		if err != nil {
			return err
		}
		fields = append(fields, "--bind-ip", bind, "--state-dir", state, "--out", out)
	} else {
		destination, err := menuAskNonempty(r, "Private RFC1918 signed destination IPv4")
		if err != nil {
			return err
		}
		fields = append(fields, "--destination-ip", destination)
	}
	return labCLI(append([]string{op}, fields...))
}
