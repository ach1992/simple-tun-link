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
			// Link identity keys are meaningful at exactly one nesting
			// level. A misplaced key must not disappear into the ignored
			// data path and incorrectly prove absence of a foreign device.
			// Ordinary nonidentity attributes remain driver-specific.
			misplaced := xfrmLinkIdentityKey(key)
			// Unrelated SA fields may contain secret keys; never retain
			// decoded copies, even though the caller also clears raw bytes.
			clear(value)
			if misplaced {
				return nil, fmt.Errorf("misplaced XFRM link identity field")
			}
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

// Link identity is scope-specific: ifname/linkinfo at the outer record,
// info_kind/info_data inside linkinfo, and if_id only inside info_data.
// All other appearances are malformed, regardless of the ID's value.
// This helper intentionally excludes ordinary driver-specific attributes.
func xfrmLinkIdentityKey(name string) bool {
	switch name {
	case "ifname", "linkinfo", "info_kind", "info_data", "if_id":
		return true
	default:
		return false
	}
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
	seenSelector := false
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
			seenRecord, seenID, hasDescriptor, seenSelector = true, false, false, false
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
			if kind != "state" || !hasDescriptor || seenSelector {
				return false, fmt.Errorf("misplaced or duplicate XFRM state selector")
			}
			if err := validateXFRMStateSelector(fields); err != nil {
				return false, err
			}
			seenSelector = true
			continue
		}
		// iproute2 prints XFRM if_id as its own top-level attribute line.
		// A similarly spelled token inside another line is misplaced and must
		// never establish vacancy, even when its value is not our target.
		if bytes.Equal(fields[0], []byte("if_id")) {
			if seenID || len(fields) != 2 {
				return false, fmt.Errorf("ambiguous XFRM text interface identifier")
			}
			id, err := strconv.ParseUint(string(fields[1]), 0, 32)
			if err != nil {
				return false, fmt.Errorf("invalid XFRM text interface identifier")
			}
			seenID = true
			if uint32(id) == target {
				found = true
			}
			continue
		}
		for _, field := range fields {
			if bytes.Equal(field, []byte("if_id")) {
				return false, fmt.Errorf("misplaced XFRM text interface identifier")
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

// validateXFRMStateSelector recognizes the bounded token/value grammar
// printed by iproute2's xfrm_selector_print. Selector attributes are NOT
// parent-SA identifiers; in particular any if_id at this scope is malformed.
// Unknown attributes fail closed rather than being skipped as an empty ID.
func validateXFRMStateSelector(fields [][]byte) error {
	if len(fields) < 5 || !bytes.Equal(fields[0], []byte("sel")) ||
		!bytes.Equal(fields[1], []byte("src")) || !bytes.Equal(fields[3], []byte("dst")) ||
		!validXFRMEndpoint(string(fields[2]), "policy") ||
		!validXFRMEndpoint(string(fields[4]), "policy") {
		return fmt.Errorf("invalid XFRM selector header")
	}
	seen := make(map[string]bool)
	protoID := uint64(0)
	rank := 0
	for i := 5; i < len(fields); i += 2 {
		if i+1 >= len(fields) {
			return fmt.Errorf("incomplete XFRM selector attribute")
		}
		name, value := string(fields[i]), string(fields[i+1])
		if seen[name] {
			return fmt.Errorf("duplicate XFRM selector attribute")
		}
		seen[name] = true
		currentRank := 0
		switch name {
		case "proto":
			currentRank = 1
			var ok bool
			protoID, ok = xfrmSelectorProtocol(value)
			if !ok {
				return fmt.Errorf("invalid XFRM selector protocol")
			}
		case "sport", "dport", "type", "code":
			if name == "sport" || name == "type" {
				currentRank = 2
			} else {
				currentRank = 3
			}
			if !xfrmUnsignedDecimal(value, 16) {
				return fmt.Errorf("invalid XFRM selector port or type")
			}
		case "key":
			currentRank = 2
			if !xfrmUnsignedDecimal(value, 32) {
				return fmt.Errorf("invalid XFRM selector key")
			}
		case "(dport)":
			currentRank = 3
			if !strings.HasPrefix(value, "0x") || len(value) < 3 || len(value) > 6 {
				return fmt.Errorf("invalid XFRM selector mobility port")
			}
			if _, err := strconv.ParseUint(value[2:], 16, 16); err != nil {
				return fmt.Errorf("invalid XFRM selector mobility port")
			}
		case "dev":
			currentRank = 4
			if len(value) == 0 || len(value) >= 16 || value[0] == '-' {
				return fmt.Errorf("invalid XFRM selector device")
			}
			for j := 0; j < len(value); j++ {
				c := value[j]
				if !((c >= '0' && c <= '9') ||
					(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
					c == '_' || c == '-' || c == '.' || c == '@' || c == '+') {
					return fmt.Errorf("invalid XFRM selector device")
				}
			}
		case "uid":
			currentRank = 5
			if !xfrmUnsignedDecimal(value, 32) {
				return fmt.Errorf("invalid XFRM selector uid")
			}
		default:
			return fmt.Errorf("unknown XFRM selector attribute")
		}
		// iproute2 prints proto, selector transport/type fields, dev,
		// then optional uid in that order.
		if currentRank < rank {
			return fmt.Errorf("ambiguous XFRM selector attribute order")
		}
		rank = currentRank
	}

	// iproute2 prints ports for most transport protocols, type/code for
	// ICMP, key for GRE, and type/(dport) for mobility headers.
	if seen["key"] && protoID != 47 {
		return fmt.Errorf("invalid XFRM selector GRE key")
	}
	if seen["type"] || seen["code"] || seen["(dport)"] {
		if protoID != 1 && protoID != 58 && protoID != 135 {
			return fmt.Errorf("invalid XFRM selector type or code")
		}
		if (protoID == 135 && seen["code"]) ||
			(protoID != 135 && seen["(dport)"]) {
			return fmt.Errorf("invalid XFRM selector mobility fields")
		}
	}
	if seen["sport"] || seen["dport"] {
		if protoID == 1 || protoID == 58 || protoID == 47 || protoID == 135 {
			return fmt.Errorf("invalid XFRM selector transport fields")
		}
	}
	return nil
}

func xfrmUnsignedDecimal(value string, bits int) bool {
	if len(value) == 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, bits)
	return err == nil
}

// iproute2's strxf_proto() prints getprotobynumber names, or a numeric
// fallback for unlisted protocol numbers. Do not treat arbitrary words as
// valid identities: reject unknown protocol spellings rather than guessing.
func xfrmSelectorProtocol(value string) (uint64, bool) {
	if xfrmUnsignedDecimal(value, 8) {
		n, _ := strconv.ParseUint(value, 10, 8)
		return n, n != 0
	}
	// Common documented IANA/Linux protocol names across supported distros.
	names := map[string]uint64{
		"icmp": 1, "igmp": 2, "ipencap": 4, "ipip": 4,
		"tcp": 6, "udp": 17, "dccp": 33, "ipv6": 41,
		"ipv6-route": 43, "ipv6-frag": 44, "rsvp": 46,
		"gre": 47, "esp": 50, "ah": 51,
		"ipv6-icmp": 58, "icmpv6": 58,
		"ipv6-nonxt": 59, "ipv6-opts": 60,
		"ospf": 89, "etherip": 97, "encap": 98,
		"pim": 103, "ipcomp": 108, "vrrp": 112,
		"l2tp": 115, "sctp": 132, "mh": 135,
		"mobility-header": 135, "udplite": 136,
	}
	proto, ok := names[value]
	return proto, ok
}
