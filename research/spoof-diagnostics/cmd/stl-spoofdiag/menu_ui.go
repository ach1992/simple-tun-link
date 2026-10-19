package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func menu() error {
	reader := bufio.NewReaderSize(os.Stdin, 64*1024)
	for {
		menuHeader()
		fmt.Fprint(os.Stdout, "Choose [0-26] (or q): ")
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
		case "13":
			result = menuCampaignCreate(reader)
		case "14":
			result = menuCampaignNext(reader)
		case "15":
			result = menuCampaignReport(reader)
		case "16":
			result = menuFieldCheck(reader)
		case "17":
			result = menuFieldAccept(reader)
		case "18":
			result = menuCampaignSend(reader)
		case "19":
			result = menuCampaignReceive(reader)
		case "20", "21", "22", "23", "24", "25", "26":
			result = menuExchange(reader, answer)
		default:
			fmt.Fprintln(os.Stderr, "Unknown option; use 0..26")
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
	fmt.Fprintln(os.Stdout, "13) Prepare IP campaign       14) Prepare next batch (offline)")
	fmt.Fprintln(os.Stdout, "15) Signed campaign report    16) Read-only field prerequisites")
	fmt.Fprintln(os.Stdout, "17) Receiver accept + listen  18) Send ONE approved campaign batch")
	fmt.Fprintln(os.Stdout, "19) Campaign receiver: independently approve + listen (one batch)")
	fmt.Fprintln(os.Stdout, "20) New offline Case ID         21) Initialize private exchange folders")
	fmt.Fprintln(os.Stdout, "22) Export signed case bundle   23) Analyze inbox / four bundles")
	fmt.Fprintln(os.Stdout, "24) Inspect one signed bundle")
	fmt.Fprintln(os.Stdout, "25) Import + verify inbox safely (no execution)")
	fmt.Fprintln(os.Stdout, "26) Prepare IP list (ip.txt) to native inventory without network")
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
			plan, err := readSignedFieldChallenge(challenge)
			if err != nil {
				return err
			}
			bind, err := menuAsk(r, "Receiver-local bind IPv4 (blank=signed destination; use private address for owned DNAT)")
			if err != nil {
				return err
			}
			if bind != "" {
				args = append(args, "--bind-ip", bind)
				if bind != plan.Challenge.DestinationIP {
					ack, err := menuAsk(r, "Type FORWARDED if you independently configured this exact receiver endpoint's DNAT")
					if err != nil {
						return err
					}
					if ack != "FORWARDED" {
						return errors.New("receiver forwarding not acknowledged")
					}
					args = append(args, "--allow-forwarded-destination")
				}
			}
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
				g, err := readSignedFieldGrant(grant)
				if err != nil {
					return err
				}
				bind := g.Grant.BindIP
				if bind == "" {
					bind = dest
				}
				args = append(args, "--bind-ip", bind)
				if bind != dest {
					args = append(args, "--allow-forwarded-destination")
				}
				state, err := menuAskNonempty(r, "Private replay-ledger directory (0700)")
				if err != nil {
					return err
				}
				out, err := menuAskNonempty(r, "New receiver signed receipt .json")
				if err != nil {
					return err
				}
				args = append(args, "--state-dir", state, "--out", out)
				ready, err := menuAsk(r, "Optional NEW signed listener readiness .json (blank=skip)")
				if err != nil {
					return err
				}
				if ready != "" {
					args = append(args, "--ready-out", ready)
				}
			} else {
				out, err := menuAskNonempty(r, "New SIGNED sender syscall evidence .json output")
				if err != nil {
					return err
				}
				args = append(args, "--out", out)
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
	args := []string{"verify", "--challenge", c, "--grant", g, "--receipt", receipt, "--ca", ca}
	sender, err := menuAsk(r, "Optional sender-signed syscall report JSON (blank=skip)")
	if err != nil {
		return err
	}
	if sender != "" {
		args = append(args, "--sender-report", sender)
	}
	return fieldCLI(args)
}
func menuFieldHelp() {
	fmt.Fprintln(os.Stdout, "This build contains no private-lab, local-loopback, or detached-netns diagnostic commands.")
	fmt.Fprintln(os.Stdout, "Field protocol: sender challenge -> signed receiver grant -> listen/send -> signed receipt -> verify.")
	fmt.Fprintln(os.Stdout, "Each approved source IP gets 5 signed samples by default (configurable 1..10 per run).")
	fmt.Fprintln(os.Stdout, "All IP choices are exact source IPv4s in field_candidates inventory, no CIDR scanning.")
	fmt.Fprintln(os.Stdout, "Normal UDP supports local interface-owned IPv4s. Raw IPv4 needs CAP_NET_RAW, an exact NIC")
	fmt.Fprintln(os.Stdout, "and separate proven owner/provider authorization; CLI acknowledgement is not permission proof.")
	fmt.Fprintln(os.Stdout, "No network tests have established any real host/provider behavior for this field candidate.")
	fmt.Fprintln(os.Stdout, "Only signed UDP diagnostics exist today; TCP, ICMP and QUIC are future, unimplemented protocol options.")
	fmt.Fprintln(os.Stdout, "Use README.md for explicit ports, identity transfer and detailed CLI argument instructions.")
}

// The guided campaign frontend reuses the exact machine commands and never
// maintains an independent interactive execution engine.
func menuCampaignCreate(r *bufio.Reader) error {
	source, err := menuAsk(r, "Source IP inventory path (blank=exchange/inbox/ip.txt)")
	if err != nil {
		return err
	}
	if source == "" {
		source = filepath.Join(exchangeDefaultBase, "inbox", "ip.txt")
	}
	inventory, err := exchangeReadSourceAnyName(source)
	if err != nil {
		return err
	}
	// Single-direction TXT/JSON/CSV needs no extra question. Preserve
	// the mixed-inventory menu's ability to choose either direction.
	direction := ""
	for _, candidate := range inventory.Candidates[1:] {
		if candidate.Direction != inventory.Candidates[0].Direction {
			direction, err = menuAskNonempty(r, "Choose campaign direction A_TO_B or B_TO_A (mixed inventory)")
			if err != nil {
				return err
			}
			break
		}
	}
	dir, err := menuAskNonempty(r, "NEW private campaign directory")
	if err != nil {
		return err
	}
	destination, err := menuAskNonempty(r, "Receiver advertised IPv4 (no DNS)")
	if err != nil {
		return err
	}
	transport, err := menuAsk(r, "Transport (blank=field_udp_bound, or field_raw_ipv4)")
	if err != nil {
		return err
	}
	args := []string{"create", "--file", source, "--dir", dir, "--destination-ip", destination}
	if direction != "" {
		args = append(args, "--direction", direction)
	}
	if transport != "" {
		args = append(args, "--transport", transport)
	}
	return campaignCLI(args)
}
func menuCampaignNext(r *bufio.Reader) error {
	dir, err := menuAskNonempty(r, "Existing campaign directory")
	if err != nil {
		return err
	}
	cert, err := menuAskNonempty(r, "Sender certificate .crt (only needed for new batch)")
	if err != nil {
		return err
	}
	key, err := menuAskNonempty(r, "Sender private .key (only needed for new batch)")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted CA .crt")
	if err != nil {
		return err
	}
	retry, err := menuAsk(r, "Retry an expired uncompleted run with new independent grant? (type RETRY, else no)")
	if err != nil {
		return err
	}
	args := []string{"next", "--dir", dir, "--cert", cert, "--key", key, "--ca", ca}
	if retry == "RETRY" {
		args = append(args, "--retry-expired")
	}
	return campaignCLI(args)
}
func menuCampaignReport(r *bufio.Reader) error {
	dir, err := menuAskNonempty(r, "Existing campaign directory")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted CA certificate")
	if err != nil {
		return err
	}
	return campaignCLI([]string{"report", "--dir", dir, "--ca", ca})
}
func menuFieldCheck(r *bufio.Reader) error {
	creds, err := menuFieldCredentials(r)
	if err != nil {
		return err
	}
	role, err := menuAskNonempty(r, "Local role (sender or receiver)")
	if err != nil {
		return err
	}
	file, err := menuAskNonempty(r, "Source inventory JSON/CSV")
	if err != nil {
		return err
	}
	ch, err := menuAskNonempty(r, "Signed challenge JSON")
	if err != nil {
		return err
	}
	grant, err := menuAskNonempty(r, "Signed receiver grant JSON")
	if err != nil {
		return err
	}
	dest, err := menuAskNonempty(r, "Signed advertised receiver destination IPv4")
	if err != nil {
		return err
	}
	plan, err := readSignedFieldChallenge(ch)
	if err != nil {
		return err
	}
	args := append([]string{"check"}, creds...)
	args = append(args, "--role", role, "--file", file, "--challenge", ch, "--grant", grant,
		"--destination-ip", dest, "--data-port", fmt.Sprint(plan.Challenge.DataPort))
	if role == "receiver" {
		g, err := readSignedFieldGrant(grant)
		if err != nil {
			return err
		}
		bind := g.Grant.BindIP
		if bind == "" {
			bind = dest
		}
		args = append(args, "--bind-ip", bind)
		if bind != dest {
			args = append(args, "--allow-forwarded-destination")
		}
	} else if plan.Challenge.Environment == "field_raw_ipv4" {
		nic, err := menuAskNonempty(r, "Exact approved egress interface")
		if err != nil {
			return err
		}
		args = append(args, "--interface", nic)
		ack, err := menuAsk(r, "Type PROVIDER_APPROVED only if independently authorized")
		if err != nil {
			return err
		}
		if ack == "PROVIDER_APPROVED" {
			args = append(args, "--provider-authorized")
		}
	}
	return fieldCLI(args)
}

// One-menu-operation B approval plus foreground listener; no daemon and no
// traffic until the operator selects this deliberate Field action.
func menuFieldAccept(r *bufio.Reader) error {
	creds, err := menuFieldCredentials(r)
	if err != nil {
		return err
	}
	file, err := menuAskNonempty(r, "Receiver-controlled exact source allowlist")
	if err != nil {
		return err
	}
	ch, err := menuAskNonempty(r, "Existing signed sender challenge JSON")
	if err != nil {
		return err
	}
	dest, err := readSignedFieldChallenge(ch)
	if err != nil {
		return err
	}
	args := append([]string{"accept"}, creds...)
	args = append(args, "--file", file, "--challenge", ch,
		"--destination-ip", dest.Challenge.DestinationIP, "--data-port", fmt.Sprint(dest.Challenge.DataPort))
	bind, err := menuAsk(r, "Receiver-local bind IPv4 (blank=advertised destination)")
	if err != nil {
		return err
	}
	if bind != "" {
		args = append(args, "--bind-ip", bind)
		if bind != dest.Challenge.DestinationIP {
			ack, err := menuAsk(r, "Type FORWARDED to acknowledge separately owned/configured DNAT")
			if err != nil {
				return err
			}
			if ack != "FORWARDED" {
				return errors.New("forwarded destination not authorized")
			}
			args = append(args, "--allow-forwarded-destination")
		}
	}
	grant, err := menuAskNonempty(r, "New receiver grant JSON to securely transfer to A")
	if err != nil {
		return err
	}
	receipt, err := menuAskNonempty(r, "New receiver-signed receipt JSON output")
	if err != nil {
		return err
	}
	state, err := menuAskNonempty(r, "Private consumed-run ledger directory (0700)")
	if err != nil {
		return err
	}
	ready, err := menuAskNonempty(r, "New receiver-signed readiness JSON after listener binds (transfer to A)")
	if err != nil {
		return err
	}
	args = append(args, "--grant-out", grant, "--ready-out", ready, "--out", receipt, "--state-dir", state)
	return fieldCLI(args)
}

func menuCampaignSend(r *bufio.Reader) error {
	dir, err := menuAskNonempty(r, "Existing campaign directory on sender")
	if err != nil {
		return err
	}
	cert, err := menuAskNonempty(r, "Local sender certificate")
	if err != nil {
		return err
	}
	key, err := menuAskNonempty(r, "Local sender private key path")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted CA certificate path")
	if err != nil {
		return err
	}
	manifest, err := readCampaign(dir)
	if err != nil {
		return err
	}
	args := []string{"send", "--dir", dir, "--cert", cert, "--key", key, "--ca", ca}
	if manifest.Transport == "field_raw_ipv4" {
		iface, err := menuAskNonempty(r, "Authorized raw source sending interface")
		if err != nil {
			return err
		}
		ack, err := menuAsk(r, "Type PROVIDER_APPROVED only if owner AND provider permission independently verified")
		if err != nil {
			return err
		}
		if ack != "PROVIDER_APPROVED" {
			return errors.New("no independently verified raw source authorization")
		}
		args = append(args, "--interface", iface, "--provider-authorized")
	}
	ack, err := menuAsk(r, "Type SEND_ONE to send at most ONE independently granted bounded batch")
	if err != nil {
		return err
	}
	if ack != "SEND_ONE" {
		return errors.New("sending not selected")
	}
	return campaignCLI(args)
}

// The guided B-side campaign operation is intentionally foreground and
// bounded to one batch. It reuses the CLI and its independent allowlist,
// cryptographic grant checks, local bind checks and replay ledger.
func menuCampaignReceive(r *bufio.Reader) error {
	dir, err := menuAskNonempty(r, "Existing campaign directory transferred to receiver")
	if err != nil {
		return err
	}
	allowlist, err := menuAskNonempty(r, "Receiver-owned independently approved source allowlist")
	if err != nil {
		return err
	}
	cert, err := menuAskNonempty(r, "Receiver certificate .crt")
	if err != nil {
		return err
	}
	key, err := menuAskNonempty(r, "Receiver private .key path")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(r, "Trusted public CA certificate")
	if err != nil {
		return err
	}
	bind, err := menuAsk(r, "Receiver-local bind IPv4 (blank=advertised destination)")
	if err != nil {
		return err
	}
	args := []string{"receive", "--dir", dir, "--file", allowlist,
		"--cert", cert, "--key", key, "--ca", ca}
	if bind != "" {
		manifest, err := readCampaign(dir)
		if err != nil {
			return err
		}
		args = append(args, "--bind-ip", bind)
		if bind != manifest.DestinationIP {
			ack, err := menuAsk(r, "Type FORWARDED only for a separately owned/configured exact DNAT endpoint")
			if err != nil {
				return err
			}
			if ack != "FORWARDED" {
				return errors.New("receiver forwarded destination not acknowledged")
			}
			args = append(args, "--allow-forwarded-destination")
		}
	}
	ack, err := menuAsk(r, "Type LISTEN_ONE to approve one finite receiver batch (no sender traffic)")
	if err != nil {
		return err
	}
	if ack != "LISTEN_ONE" {
		return errors.New("receiver operation not selected")
	}
	return campaignCLI(args)
}
