package ipsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
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
		var rows []struct {
			IfID json.RawMessage `json:"if_id"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
			return false, fmt.Errorf("invalid JSON XFRM inventory")
		}
		for _, row := range rows {
			id, err := xfrmIfID(row.IfID, false)
			if err != nil {
				return false, fmt.Errorf("unverifiable XFRM inventory identifier")
			}
			if id == target {
				return true, nil
			}
		}
		return false, nil
	}
	return xfrmTextUsesID(raw, target, kind)
}

// Parse only documented textual XFRM entries. Every record must have an
// unindented src/dst header and the expected policy dir or state proto.
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
				!bytes.Equal(fields[2], []byte("dst")) {
				return false, fmt.Errorf("invalid XFRM text header")
			}
			seenRecord, seenID, hasDescriptor = true, false, false
		} else if !seenRecord {
			return false, fmt.Errorf("unexpected XFRM text inventory")
		}
		for j, field := range fields {
			if (kind == "policy" && bytes.Equal(field, []byte("dir"))) ||
				(kind == "state" && bytes.Equal(field, []byte("proto"))) {
				hasDescriptor = true
			}
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
