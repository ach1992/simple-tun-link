package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func menu() error {
	reader := bufio.NewReaderSize(os.Stdin, 64*1024)
	for {
		menuHeader()
		fmt.Fprint(os.Stdout, "Choose [0-12] (or q): ")
		answer, err := menuRead(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Input error:", err)
			continue
		}
		var result error
		switch strings.ToLower(answer) {
		case "0", "q", "quit", "exit":
			fmt.Fprintln(os.Stdout, "Goodbye. No background agent was started.")
			return nil
		case "1":
			result = preflight()
		case "2":
			result = pretty(versionInfo())
		case "3":
			result = menuSources(reader)
		case "4":
			result = menuFieldPlan(reader)
		case "5":
			result = menuFieldReport(reader)
		case "6":
			result = menuFieldIdentity(reader)
		case "7":
			result = menuFieldOperation(reader, "challenge")
		case "8":
			result = menuFieldOperation(reader, "grant")
		case "9":
			result = menuFieldOperation(reader, "listen")
		case "10":
			result = menuFieldOperation(reader, "send")
		case "11":
			result = menuFieldVerify(reader)
		case "12", "h", "help":
			menuFieldHelp()
		default:
			fmt.Fprintln(os.Stderr, "Unknown option; use 0..12")
		}
		if result != nil {
			fmt.Fprintln(os.Stderr, "Operation not completed:", result)
		}
	}
}

func menuHeader() {
	fmt.Fprintln(os.Stdout, "\n==============================================================")
	fmt.Fprintln(os.Stdout, "STL SPOOF DIAGNOSTICS | independent Go Field research")
	fmt.Fprintf(os.Stdout, "Build: %s (%s) | Field runtime: UNVALIDATED\n", version, commit)
	fmt.Fprintln(os.Stdout, " 1) Static prerequisites       2) Version/build")
	fmt.Fprintln(os.Stdout, " 3) Manage selected source IPs 4) Offline plan")
	fmt.Fprintln(os.Stdout, " 5) Read declared evidence     6) Provision identities offline")
	fmt.Fprintln(os.Stdout, " 7) Create sender challenge    8) Grant receiver approval")
	fmt.Fprintln(os.Stdout, " 9) Start field receiver      10) Send bounded field samples")
	fmt.Fprintln(os.Stdout, "11) Verify signed receipt     12) Help")
	fmt.Fprintln(os.Stdout, " 0) Exit")
	fmt.Fprintln(os.Stdout, "NOTE: Source match != provider permission != return-path proof.")
	fmt.Fprintln(os.Stdout, "==============================================================")
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
		mode, err := menuAsk(r, "NEW file mode (field_candidates; blank for existing)")
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

func menuFieldPlan(r *bufio.Reader) error {
	path, err := menuAskNonempty(r, "Existing selected-source CSV/JSON")
	if err != nil {
		return err
	}
	return run([]string{"plan", "--file", path})
}
func menuFieldReport(r *bufio.Reader) error {
	path, err := menuAskNonempty(r, "Existing declared evidence JSON")
	if err != nil {
		return err
	}
	return run([]string{"report", "--file", path})
}
func menuFieldIdentity(r *bufio.Reader) error {
	fmt.Fprintln(os.Stdout, "OFFLINE TRUSTED PROVISIONING ONLY. Output contains CA key and both node keys.")
	dir, err := menuAskNonempty(r, "New private credential directory")
	if err != nil {
		return err
	}
	acknowledgement, err := menuAsk(r, "Type PROVISION to create keys on this trusted machine")
	if err != nil {
		return err
	}
	if acknowledgement != "PROVISION" {
		return errors.New("credential creation was not authorized")
	}
	return fieldCLI([]string{"identity", "--dir", dir})
}
func menuFieldCredentials(r *bufio.Reader) ([]string, error) {
	cert, err := menuAskNonempty(r, "Local node certificate .crt path")
	if err != nil {
		return nil, err
	}
	key, err := menuAskNonempty(r, "Local node private .key path (never paste contents)")
	if err != nil {
		return nil, err
	}
	ca, err := menuAskNonempty(r, "Trusted CA public .crt path")
	if err != nil {
		return nil, err
	}
	sender, err := menuAskNonempty(r, "Sender role A or B")
	if err != nil {
		return nil, err
	}
	receiver, err := menuAskNonempty(r, "Receiver role B or A")
	if err != nil {
		return nil, err
	}
	return []string{"--cert", cert, "--key", key, "--ca", ca, "--sender", sender, "--receiver", receiver}, nil
}
func menuFieldOperation(r *bufio.Reader, op string) error {
	args := []string{op}
	creds, err := menuFieldCredentials(r)
	if err != nil {
		return err
	}
	args = append(args, creds...)
	if op == "challenge" || op == "grant" || op == "listen" || op == "send" {
		file, err := menuAskNonempty(r, "Local source allowlist field_candidates CSV/JSON")
		if err != nil {
			return err
		}
		args = append(args, "--file", file)
	}
	if op == "challenge" {
		dest, err := menuAskNonempty(r, "Exact receiver destination IPv4")
		if err != nil {
			return err
		}
		args = append(args, "--destination-ip", dest)
		port, err := menuAsk(r, "Signed UDP destination port (blank=24572)")
		if err != nil {
			return err
		}
		if port != "" {
			args = append(args, "--data-port", port)
		}
		transport, err := menuAsk(r, "Transport (blank=field_udp_bound; or field_raw_ipv4)")
		if err != nil {
			return err
		}
		if transport != "" {
			args = append(args, "--transport", transport)
		}
		size, err := menuAsk(r, "Packet bytes (blank=192, range 128..1200)")
		if err != nil {
			return err
		}
		if size != "" {
			args = append(args, "--packet-size", size)
		}
		repeats, err := menuAsk(r, "Signed samples per selected IP (blank=5, range 1..10)")
		if err != nil {
			return err
		}
		if repeats != "" {
			args = append(args, "--samples-per-source", repeats)
		}
		out, err := menuAskNonempty(r, "New signed challenge .json output")
		if err != nil {
			return err
		}
		args = append(args, "--out", out)
	} else {
		challenge, err := menuAskNonempty(r, "Existing sender signed challenge .json")
		if err != nil {
			return err
		}
		args = append(args, "--challenge", challenge)
		if op == "grant" {
			out, err := menuAskNonempty(r, "New receiver signed grant .json output")
			if err != nil {
				return err
			}
			args = append(args, "--out", out)
		} else {
			grant, err := menuAskNonempty(r, "Existing receiver signed grant .json")
			if err != nil {
				return err
			}
			args = append(args, "--grant", grant)
			dest, err := menuAskNonempty(r, "Signed receiver destination IPv4")
			if err != nil {
				return err
			}
			args = append(args, "--destination-ip", dest)
			port, err := menuAsk(r, "Signed UDP destination port (blank=24572)")
			if err != nil {
				return err
			}
			if port != "" {
				args = append(args, "--data-port", port)
			}
			if op == "listen" {
				args = append(args, "--bind-ip", dest)
				state, err := menuAskNonempty(r, "Private replay-ledger directory (0700)")
				if err != nil {
					return err
				}
				out, err := menuAskNonempty(r, "New receiver signed receipt .json")
				if err != nil {
					return err
				}
				args = append(args, "--state-dir", state, "--out", out)
			} else {
				chosen, err := readSignedFieldChallenge(challenge)
				if err != nil {
					return err
				}
				if chosen.Challenge.Environment == "field_raw_ipv4" {
					iface, err := menuAskNonempty(r, "Required authorized raw IPv4 sending NIC")
					if err != nil {
						return err
					}
					if iface != "" {
						args = append(args, "--interface", iface)
						ok, err := menuAsk(r, "Type PROVIDER_APPROVED only if you independently hold owner/provider authorization")
						if err != nil {
							return err
						}
						if ok != "PROVIDER_APPROVED" {
							return errors.New("no verified permission for raw field emission")
						}
						args = append(args, "--provider-authorized")
					}
				}
			}
		}
	}
	return fieldCLI(args)
}
func menuFieldVerify(r *bufio.Reader) error {
	c, err := menuAskNonempty(r, "Sender signed challenge JSON")
	if err != nil {
		return err
	}
	g, err := menuAskNonempty(r, "Receiver signed grant JSON")
	if err != nil {
		return err
	}
	receipt, err := menuAskNonempty(r, "Receiver signed receipt JSON")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted public CA certificate")
	if err != nil {
		return err
	}
	return fieldCLI([]string{"verify", "--challenge", c, "--grant", g, "--receipt", receipt, "--ca", ca})
}
func menuFieldHelp() {
	fmt.Fprintln(os.Stdout, "This build contains no private-lab, local-loopback, or detached-netns diagnostic commands.")
	fmt.Fprintln(os.Stdout, "Field protocol: sender challenge -> signed receiver grant -> listen/send -> signed receipt -> verify.")
	fmt.Fprintln(os.Stdout, "Each approved source IP gets 5 signed samples by default (configurable 1..10 per run).")
	fmt.Fprintln(os.Stdout, "All IP choices are exact source IPv4s in field_candidates inventory, no CIDR scanning.")
	fmt.Fprintln(os.Stdout, "Normal UDP supports local interface-owned IPv4s. Raw IPv4 needs CAP_NET_RAW, an exact NIC")
	fmt.Fprintln(os.Stdout, "and separate proven owner/provider authorization; CLI acknowledgement is not permission proof.")
	fmt.Fprintln(os.Stdout, "No network tests have established any real host/provider behavior for this field candidate.")
	fmt.Fprintln(os.Stdout, "Use README.md for explicit ports, identity transfer and detailed CLI argument instructions.")
}
