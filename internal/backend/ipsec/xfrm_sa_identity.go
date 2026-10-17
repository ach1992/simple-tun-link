package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
)

// An XFRM if_id identifies an interface, NOT an established CHILD SA.
// The two ESP tunnel directions must share a nonzero CHILD reqid and have
// exactly the outer underlay endpoints of the canonical owned profile.
// "false,nil" means a verified empty scope, not partial negotiation.
type profileSADirections struct {
	reqid uint32
	sides uint8
}

func (s *profileSADirections) observe(p Profile, src, dst netip.Addr, proto, mode string, spi, reqid uint32) error {
	if proto != "esp" || mode != "tunnel" || spi == 0 || reqid == 0 {
		return fmt.Errorf("unverified IPsec CHILD protocol or identity")
	}
	var side uint8
	switch {
	case src == p.Link.Underlay.Local && dst == p.Link.Underlay.Peer:
		side = 1
	case src == p.Link.Underlay.Peer && dst == p.Link.Underlay.Local:
		side = 2
	default:
		return fmt.Errorf("IPsec CHILD endpoints differ from the committed peer")
	}
	if s.reqid != 0 && s.reqid != reqid {
		return fmt.Errorf("multiple unrelated IPsec CHILD request identities")
	}
	s.reqid = reqid
	s.sides |= side
	return nil
}

func (s profileSADirections) result() (bool, error) {
	if s.sides == 0 {
		return false, nil
	}
	if s.sides != 3 {
		return false, fmt.Errorf("incomplete IPsec CHILD security association")
	}
	return true, nil
}

// matchingProfileSA reads *every* record, even after finding a valid pair.
// A stale/wrong-target record, malformed inventory or partial SA must never
// masquerade as verified absence or establish peer reachability.
// The caller MUST zero its raw XFRM inventory: it can contain encryption keys.
func matchingProfileSA(ctx context.Context, raw []byte, p Profile) (bool, error) {
	if ctx == nil || ctx.Err() != nil || p.validateIdentity() != nil {
		return false, fmt.Errorf("invalid IPsec SA inspection context or profile")
	}
	if bytes.HasPrefix(xfrmTrimASCIIWhitespace(raw), []byte("[")) {
		return matchingProfileSAJSON(ctx, raw, p)
	}
	return matchingProfileSAText(ctx, raw, p)
}

func matchingProfileSAJSON(ctx context.Context, raw []byte, p Profile) (bool, error) {
	var rows []json.RawMessage
	parseErr := json.Unmarshal(raw, &rows)
	defer func() {
		for _, row := range rows {
			clear(row)
		}
	}()
	if parseErr != nil || rows == nil {
		return false, fmt.Errorf("invalid JSON IPsec SA inventory")
	}
	var checked profileSADirections
	for _, rawRow := range rows {
		if ctx.Err() != nil {
			return false, fmt.Errorf("IPsec SA inspection interrupted")
		}
		// Reuse the structural, duplicate-key and reserved-field gate used
		// for XFRM vacancy. Never trust a row solely because if_id matches.
		target, err := xfrmJSONRowUsesID(rawRow, p.InterfaceID, "state")
		if err != nil {
			return false, fmt.Errorf("ambiguous JSON IPsec SA record")
		}
		if !target {
			continue
		}
		fields, err := xfrmUniqueJSONObject(rawRow, "src", "dst", "proto", "mode", "spi", "reqid", "if_id")
		if err != nil {
			return false, fmt.Errorf("ambiguous JSON IPsec SA identity")
		}
		src, dst, proto, mode := "", "", "", ""
		e1 := json.Unmarshal(fields["src"], &src)
		e2 := json.Unmarshal(fields["dst"], &dst)
		e3 := json.Unmarshal(fields["proto"], &proto)
		e4 := json.Unmarshal(fields["mode"], &mode)
		spi, e5 := xfrmIfID(fields["spi"], false)
		reqid, e6 := xfrmIfID(fields["reqid"], false)
		clearXFRMJSONObject(fields)
		source, es := netip.ParseAddr(src)
		destination, ed := netip.ParseAddr(dst)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil ||
			e5 != nil || e6 != nil || es != nil || ed != nil ||
			checked.observe(p, source, destination, proto, mode, spi, reqid) != nil {
			return false, fmt.Errorf("unverifiable JSON IPsec CHILD association")
		}
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("IPsec SA inspection interrupted")
	}
	return checked.result()
}

func matchingProfileSAText(ctx context.Context, raw []byte, p Profile) (bool, error) {
	// First validate the COMPLETE legacy iproute2 grammar, including
	// selector nesting and per-record if_id uniqueness, before extracting
	// minimal public identity fields. All remaining key material stays raw.
	if _, err := xfrmTextUsesID(ctx, raw, p.InterfaceID, "state"); err != nil {
		return false, fmt.Errorf("unverifiable legacy IPsec SA inventory")
	}
	var checked profileSADirections
	type record struct {
		src, dst       netip.Addr
		proto, mode    string
		spi, reqid, id uint32
		hasID          bool
	}
	var row record
	hasRow := false
	finish := func() error {
		if !hasRow || !row.hasID || row.id != p.InterfaceID {
			return nil
		}
		if err := checked.observe(p, row.src, row.dst, row.proto, row.mode, row.spi, row.reqid); err != nil {
			return fmt.Errorf("unverifiable legacy IPsec CHILD association")
		}
		return nil
	}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if ctx.Err() != nil {
			return false, fmt.Errorf("IPsec SA inspection interrupted")
		}
		fields := xfrmASCIIFields(line)
		if len(fields) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("src ")) {
			if err := finish(); err != nil {
				return false, err
			}
			if len(fields) != 4 {
				return false, fmt.Errorf("unverifiable legacy IPsec SA header")
			}
			source, e1 := netip.ParseAddr(string(fields[1]))
			dest, e2 := netip.ParseAddr(string(fields[3]))
			if e1 != nil || e2 != nil {
				return false, fmt.Errorf("invalid legacy IPsec SA endpoints")
			}
			row = record{src: source, dst: dest}
			hasRow = true
			continue
		}
		if !hasRow {
			return false, fmt.Errorf("unverifiable legacy IPsec SA order")
		}
		switch string(fields[0]) {
		case "proto":
			if len(fields) < 8 || !bytes.Equal(fields[2], []byte("spi")) ||
				!bytes.Equal(fields[4], []byte("reqid")) ||
				!bytes.Equal(fields[6], []byte("mode")) {
				// A structurally valid but incomplete foreign SA is not
				// enough to prove the target CHILD; retain as unknown only
				// when its if_id later matches.
				continue
			}
			spi, e1 := strconv.ParseUint(string(fields[3]), 0, 32)
			reqid, e2 := strconv.ParseUint(string(fields[5]), 0, 32)
			if e1 == nil && e2 == nil {
				row.proto, row.mode = string(fields[1]), string(fields[7])
				row.spi, row.reqid = uint32(spi), uint32(reqid)
			}
		case "if_id":
			if len(fields) != 2 {
				return false, fmt.Errorf("unverifiable legacy IPsec if_id")
			}
			id, err := strconv.ParseUint(string(fields[1]), 0, 32)
			if err != nil {
				return false, fmt.Errorf("unverifiable legacy IPsec if_id")
			}
			row.id, row.hasID = uint32(id), true
		}
	}
	if err := finish(); err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("IPsec SA inspection interrupted")
	}
	return checked.result()
}
