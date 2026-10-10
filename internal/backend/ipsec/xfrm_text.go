package ipsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// xfrmInventoryUsesID supports both modern JSON iproute2 inventories and
// traditional iproute2 releases (including Debian bookworm 6.1), which ignore
// -json for xfrm state/policy and print structured text instead. Both formats
// are parsed fail-closed; raw output may contain SA key material and must be
// zeroized by the caller without ever appearing in an error or log.
func xfrmInventoryUsesID(raw []byte, target uint32, kind string) (bool, error) {
	if kind != "policy" && kind != "state" {
		return false, fmt.Errorf("unsupported XFRM inventory")
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		var rows []json.RawMessage
		parseErr := json.Unmarshal(raw, &rows)
		// RawMessage unmarshal copies entire rows, which may include SA
		// encryption material. Clear all copies on success AND failure.
		defer func() {
			for _, row := range rows {
				clear(row)
			}
		}()
		if parseErr != nil || rows == nil {
			return false, fmt.Errorf("invalid JSON XFRM inventory")
		}
		for _, rawRow := range rows {
			collision, err := xfrmJSONRowUsesID(rawRow, target, kind)
			if err != nil {
				return false, err
			}
			if collision {
				return true, nil
			}
		}
		return false, nil
	}
	return xfrmTextUsesID(raw, target, kind)
}

// Reject duplicate JSON keys before decoding their values. Go's ordinary
// struct/map unmarshal otherwise silently keeps the LAST duplicate, including
// a conflicting if_id, dir, proto, src or dst. A noncanonical case variant of
// any of these security-relevant names is also ambiguous, not ignorable.
func xfrmUniqueJSONObject(raw json.RawMessage, retain ...string) (result map[string]json.RawMessage, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') {
		return nil, fmt.Errorf("invalid XFRM JSON row")
	}
	values := make(map[string]json.RawMessage)
	seen := make(map[string]bool)
	// Decoding fields can allocate copies of SA encryption material.
	// On early parse failure clear previously retained values too.
	defer func() {
		if err != nil {
			for _, value := range values {
				clear(value)
			}
		}
	}()
	for dec.More() {
		token, tokenErr := dec.Token()
		if tokenErr != nil {
			return nil, fmt.Errorf("invalid XFRM JSON field")
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid XFRM JSON field name")
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate XFRM JSON field")
		}
		seen[key] = true
		for _, reserved := range []string{"if_id", "dir", "proto", "src", "dst", "ifname", "linkinfo", "info_kind", "info_data"} {
			if strings.EqualFold(key, reserved) && key != reserved {
				return nil, fmt.Errorf("noncanonical XFRM JSON field")
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			clear(value)
			return nil, fmt.Errorf("invalid XFRM JSON field value")
		}
		needed := false
		for _, field := range retain {
			if field == key {
				needed = true
				break
			}
		}
		if needed {
			values[key] = value
		} else {
			// Unrelated SA fields may contain secret keys; never retain
			// decoded copies, even though the caller also clears raw bytes.
			clear(value)
		}
	}
	close, err := dec.Token()
	if err != nil || close != json.Delim('}') {
		return nil, fmt.Errorf("invalid XFRM JSON row")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("extra XFRM JSON data")
	}
	return values, nil
}

// Only the structurally validated policy/SA row may supply an optional if_id.
// Always zero the retained decoded JSON values before returning.
func xfrmJSONRowUsesID(raw []byte, target uint32, kind string) (bool, error) {
	row, err := xfrmUniqueJSONObject(raw, "if_id", "dir", "proto", "src", "dst")
	if err != nil {
		return false, fmt.Errorf("ambiguous JSON XFRM inventory")
	}
	defer func() {
		for _, value := range row {
			clear(value)
		}
	}()
	if !xfrmJSONHasEndpoints(row, kind) || !xfrmJSONHasDescriptor(row, kind) {
		return false, fmt.Errorf("incomplete JSON XFRM inventory")
	}
	rawID, present := row["if_id"]
	if !present {
		return false, nil // Valid wildcard policy/SA with no interface ID.
	}
	// An explicitly present but null ID is ambiguous, not absent.
	if bytes.Equal(bytes.TrimSpace(rawID), []byte("null")) {
		return false, fmt.Errorf("invalid JSON XFRM interface identifier")
	}
	id, err := xfrmIfID(rawID, false)
	if err != nil {
		return false, fmt.Errorf("unverifiable XFRM inventory identifier")
	}
	return id == target, nil
}

func xfrmJSONHasDescriptor(row map[string]json.RawMessage, kind string) bool {
	field := "proto"
	if kind == "policy" {
		field = "dir"
	}
	raw, ok := row[field]
	if !ok {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && validXFRMDescriptor(kind, value)
}

func xfrmJSONHasEndpoints(row map[string]json.RawMessage, kind string) bool {
	for _, field := range []string{"src", "dst"} {
		raw, exists := row[field]
		if !exists {
			return false
		}
		var value string
		if json.Unmarshal(raw, &value) != nil || !validXFRMEndpoint(value, kind) {
			return false
		}
	}
	return true
}

// These are the Linux xfrm policy directions and iproute2 XFRM state
// protocols. Unknown descriptors cannot prove resource absence.
func validXFRMDescriptor(kind, value string) bool {
	switch kind {
	case "policy":
		return value == "in" || value == "out" || value == "fwd"
	case "state":
		return value == "esp" || value == "ah" || value == "comp" ||
			value == "route2" || value == "hao"
	default:
		return false
	}
}

func validXFRMEndpoint(value, kind string) bool {
	// SA endpoints must be single addresses; policy selectors may be
	// addresses or masked CIDRs (including intentional wildcard selectors).
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	if kind == "policy" {
		_, err := netip.ParsePrefix(value)
		return err == nil
	}
	return false
}

// Parse only documented textual XFRM entries. Every record must have an
// unindented concrete src/dst header and ONE valid policy dir or state proto.
// An if_id token must have exactly one bounded value per record. Ambiguous
// input is unknown, not proof of empty state; we do not accept free-form grep.
func xfrmTextUsesID(raw []byte, target uint32, kind string) (bool, error) {
	seenRecord := false
	hasDescriptor := false
	seenID := false
	found := false
	finish := func() error {
		if seenRecord && !hasDescriptor {
			return fmt.Errorf("incomplete XFRM text record")
		}
		return nil
	}
	descriptor := []byte("proto")
	if kind == "policy" {
		descriptor = []byte("dir")
	}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		fields := bytes.Fields(trimmed)
		if bytes.HasPrefix(line, []byte("src ")) {
			if err := finish(); err != nil {
				return false, err
			}
			if len(fields) < 4 || !bytes.Equal(fields[0], []byte("src")) ||
				!bytes.Equal(fields[2], []byte("dst")) ||
				!validXFRMEndpoint(string(fields[1]), kind) ||
				!validXFRMEndpoint(string(fields[3]), kind) {
				return false, fmt.Errorf("invalid XFRM text header")
			}
			seenRecord, seenID, hasDescriptor = true, false, false
		} else if !seenRecord || bytes.Equal(fields[0], []byte("src")) {
			return false, fmt.Errorf("unexpected XFRM text inventory")
		}
		// The record descriptor belongs to the canonical first token of
		// the SA/protocol or policy/direction line. State selectors such as
		// "sel src ... dst ... proto tcp" and policy templates may also
		// contain "proto", but do not describe the parent SA's protocol.
		if bytes.Equal(fields[0], descriptor) {
			if hasDescriptor || len(fields) < 2 ||
				!validXFRMDescriptor(kind, string(fields[1])) {
				return false, fmt.Errorf("invalid or duplicate XFRM text descriptor")
			}
			hasDescriptor = true
		}
		if bytes.Equal(fields[0], []byte("sel")) {
			if kind != "state" || len(fields) < 5 ||
				!bytes.Equal(fields[1], []byte("src")) ||
				!bytes.Equal(fields[3], []byte("dst")) ||
				!validXFRMEndpoint(string(fields[2]), "policy") ||
				!validXFRMEndpoint(string(fields[4]), "policy") {
				return false, fmt.Errorf("invalid XFRM state selector")
			}
			// A selector-level proto/if_id does not grant parent identity.
			continue
		}
		for j, field := range fields {
			if !bytes.Equal(field, []byte("if_id")) {
				continue
			}
			if seenID || j+1 >= len(fields) {
				return false, fmt.Errorf("ambiguous XFRM text interface identifier")
			}
			id, err := strconv.ParseUint(string(fields[j+1]), 0, 32)
			if err != nil {
				return false, fmt.Errorf("invalid XFRM text interface identifier")
			}
			seenID = true
			if uint32(id) == target {
				found = true
			}
		}
	}
	if !seenRecord {
		return false, fmt.Errorf("nonempty unknown XFRM text inventory")
	}
	if err := finish(); err != nil {
		return false, err
	}
	return found, nil
}
