package diagnostics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// These files reflect only the caller's CURRENT network namespace and
// inspection instant, never exclusive future access or host-wide ownership.
const maxIPsecPortInventory = 1024 * 1024

type ipsecPortReader func(context.Context, string) ([]byte, error)

func readIPsecPortInventory(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect UDP inventory")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxIPsecPortInventory+1))
	if err != nil || len(data) > maxIPsecPortInventory || ctx.Err() != nil {
		clear(data)
		return nil, fmt.Errorf("UDP inventory unavailable or incomplete")
	}
	return data, nil
}

// inspectIPsecIKEPorts is read-only. Absence in /proc/net/udp{,6} is NEVER
// an admission permit: inherited namespaces, another process and time-of-
// check/time-of-use races remain unproved. Errors do not reveal proc content.
func inspectIPsecIKEPorts(ctx context.Context, reader ipsecPortReader) IPsecHostCheck {
	unknown := IPsecHostCheck{
		Name: "ike_udp_ports", Status: "unknown", ReasonCode: "ike_udp_inventory_unverified",
		Summary:  "Cannot establish a complete read-only UDP 500/4500 socket inventory.",
		NextStep: "Inspect standard IKE/NAT-T port use and network namespace manually; do not stop, bind over or adopt another service.",
	}
	if ctx == nil || reader == nil || ctx.Err() != nil {
		return unknown
	}
	occupied, incomplete := false, false
	for _, item := range []struct {
		path  string
		width int
	}{
		{"/proc/net/udp", 8}, {"/proc/net/udp6", 32},
	} {
		if ctx.Err() != nil {
			return unknown
		}
		content, err := reader(ctx, item.path)
		if err != nil {
			clear(content)
			incomplete = true
			continue
		}
		matched, parseErr := parseIPsecPortInventory(content, item.width)
		clear(content)
		if parseErr != nil {
			incomplete = true
			continue
		}
		occupied = occupied || matched
	}
	if ctx.Err() != nil {
		return unknown
	}
	// A valid positive collision is actionable even if a separate inventory
	// failed. In contrast, absence requires BOTH tables to be complete.
	if occupied {
		return IPsecHostCheck{
			Name: "ike_udp_ports", Status: "blocked", ReasonCode: "ike_udp_ports_observed",
			Summary:  "A UDP socket is already bound to standard IKE/NAT-T port 500 or 4500 in the current network namespace.",
			NextStep: "Do not interrupt or adopt this socket; establish its owner before considering IPsec activation.",
		}
	}
	if incomplete {
		return unknown
	}
	return IPsecHostCheck{
		Name: "ike_udp_ports", Status: "observed", ReasonCode: "ike_udp_ports_not_observed",
		Summary:  "No UDP 500/4500 binding was observed in this network namespace at inspection time; future availability and ownership are unverified.",
		NextStep: "A separate exclusive service/socket/port ownership transaction is required before any IPsec write.",
	}
}

// /proc/net/udp rows combine pairs of header columns (tx_queue/rx_queue
// and tr/tm->when). Require the full, structurally recognizable row through
// inode before accepting an observed absence. Extra kernel columns may
// follow inode; they do not affect the local socket identity.
func parseIPsecPortInventory(data []byte, addressHexWidth int) (bool, error) {
	if addressHexWidth != 8 && addressHexWidth != 32 {
		return false, fmt.Errorf("invalid UDP address family")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	if !scanner.Scan() {
		return false, fmt.Errorf("missing UDP inventory header")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 12 || fields[0] != "sl" || fields[1] != "local_address" ||
		(fields[2] != "rem_address" && fields[2] != "remote_address") || fields[3] != "st" ||
		fields[4] != "tx_queue" || fields[5] != "rx_queue" ||
		fields[6] != "tr" || fields[7] != "tm->when" ||
		fields[8] != "retrnsmt" || fields[9] != "uid" ||
		fields[10] != "timeout" || fields[11] != "inode" {
		return false, fmt.Errorf("invalid UDP inventory header")
	}
	found := false
	for scanner.Scan() {
		row := strings.Fields(scanner.Text())
		if len(row) < 10 || !strings.HasSuffix(row[0], ":") {
			return false, fmt.Errorf("invalid UDP inventory row")
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(row[0], ":"), 10, 32); err != nil {
			return false, fmt.Errorf("invalid UDP inventory row index")
		}
		localPort, err := parseProcUDPEndpoint(row[1], addressHexWidth)
		if err != nil {
			return false, fmt.Errorf("invalid UDP local socket")
		}
		if _, err := parseProcUDPEndpoint(row[2], addressHexWidth); err != nil {
			return false, fmt.Errorf("invalid UDP remote socket")
		}
		if !isHexWidth(row[3], 2) ||
			!isHexPair(row[4], 8, 8) || !isHexPair(row[5], 2, 8) ||
			!isHexWidth(row[6], 8) {
			return false, fmt.Errorf("invalid UDP queue or socket status")
		}
		for _, number := range row[7:10] {
			if _, err := strconv.ParseUint(number, 10, 64); err != nil {
				return false, fmt.Errorf("invalid UDP socket owner/inode descriptor")
			}
		}
		if localPort == 500 || localPort == 4500 {
			found = true
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("incomplete UDP inventory")
	}
	return found, nil
}

func parseProcUDPEndpoint(value string, width int) (uint64, error) {
	pair := strings.Split(value, ":")
	if len(pair) != 2 || len(pair[0]) != width || len(pair[1]) != 4 ||
		!isHexWidth(pair[0], width) || !isHexWidth(pair[1], 4) {
		return 0, fmt.Errorf("malformed UDP endpoint")
	}
	port, err := strconv.ParseUint(pair[1], 16, 16)
	if err != nil {
		return 0, fmt.Errorf("malformed UDP port")
	}
	return port, nil
}

func isHexPair(value string, first, second int) bool {
	pair := strings.Split(value, ":")
	return len(pair) == 2 && isHexWidth(pair[0], first) && isHexWidth(pair[1], second)
}

func isHexWidth(value string, width int) bool {
	if len(value) != width {
		return false
	}
	var decoded [16]byte
	_, err := hex.Decode(decoded[:], []byte(value))
	return err == nil
}
