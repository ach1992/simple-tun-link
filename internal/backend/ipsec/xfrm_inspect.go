package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"os/exec"
)

// XFRMRunner uses an internal, secret-safe output seam rather than importing
// the common Linux package (which itself has app integration tests).
// Never expose a subprocess ExitError or raw XFRM state in UI/logs.
type XFRMRunner func(context.Context, string, ...string) ([]byte, error)

// NewXFRMVacancyInspector returns the default read-only iproute2 inspector.
// The binary override is trusted runtime configuration, not URL/user input.
func NewXFRMVacancyInspector(ipBinary string) XFRMVacancyInspector {
	return XFRMVacancyInspector{
		Runner: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, binary, args...).Output()
		},
		IPBinary: ipBinary,
	}
}

// XFRMVacancyInspector is a read-only, fail-closed host collision check.
// It never infers STL ownership from interface names, aliases or XFRM IDs.
// It is a prerequisite for any future Engine-locked activation transaction,
// not an authorization or durable proof of ownership.
type XFRMVacancyInspector struct {
	Runner   XFRMRunner
	IPBinary string
}

// RequireVacant rejects an existing matching interface name, another XFRM
// interface with the same 32-bit ID, or an orphan policy/SA that uses that ID.
// The caller must hold canonical maintenance/Link/resource locks and must
// repeat these inspections inside the future mutation transaction.
func (i XFRMVacancyInspector) RequireVacant(ctx context.Context, p Profile) error {
	if ctx == nil || i.Runner == nil {
		return fmt.Errorf("XFRM vacancy inspection requires context and runner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.validateIdentity(); err != nil {
		return err
	}
	ip := i.IPBinary
	if ip == "" {
		ip = "ip"
	}

	// Inspect ALL device kinds: a foreign non-XFRM interface may occupy our
	// planned name, while an XFRM device under any name may use our if_id.
	raw, err := i.read(ctx, ip, false, "-details", "-json", "link", "show")
	if err != nil {
		return err
	}
	var links []struct {
		IfName   string `json:"ifname"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
			Data struct {
				IfID json.RawMessage `json:"if_id"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(raw, &links); err != nil || links == nil {
		clear(raw)
		return fmt.Errorf("invalid XFRM host link inventory")
	}
	clear(raw)
	seen := map[string]bool{}
	for _, l := range links {
		if l.IfName == "" || seen[l.IfName] {
			return fmt.Errorf("ambiguous host interface inventory")
		}
		seen[l.IfName] = true
		if l.IfName == p.InterfaceName {
			return fmt.Errorf("IPsec interface name already occupied")
		}
		if l.LinkInfo.Kind != "xfrm" {
			continue
		}
		id, err := xfrmIfID(l.LinkInfo.Data.IfID, true)
		if err != nil {
			return fmt.Errorf("cannot verify foreign XFRM interface identity")
		}
		if id == p.InterfaceID {
			return fmt.Errorf("IPsec XFRM interface ID already occupied")
		}
	}

	// A deleted/orphaned interface is not proof that its policies or SAs
	// disappeared. Inspect both, including state IDs; the latter may contain
	// sensitive key data in command output, which must never be logged.
	for _, args := range [][]string{
		{"-json", "xfrm", "policy"},
		{"-json", "xfrm", "state"},
	} {
		raw, err := i.read(ctx, ip, true, args...)
		if err != nil {
			return err
		}
		collides, inspectErr := xfrmInventoryUsesID(raw, p.InterfaceID, args[len(args)-1])
		clear(raw)
		if inspectErr != nil {
			return fmt.Errorf("cannot verify XFRM policy or SA identity")
		}
		if collides {
			return fmt.Errorf("IPsec XFRM policy or SA already uses Link interface ID")
		}
	}
	return nil
}

// Never return raw command output/error text: XFRM state inspection may
// include raw encryption material, even on otherwise read-only commands.
func (i XFRMVacancyInspector) read(ctx context.Context, ip string, allowEmpty bool, args ...string) ([]byte, error) {
	raw, err := i.Runner(ctx, ip, args...)
	if err != nil {
		clear(raw)
		return nil, fmt.Errorf("XFRM inventory inspection unavailable")
	}
	// Kernel iproute2 prints an empty stdout (not "[]") for a successful
	// empty xfrm state/policy inventory. Allow this only after a successful
	// exit and only for policy/state, never for the required link inventory.
	if allowEmpty && len(bytes.TrimSpace(raw)) == 0 {
		clear(raw)
		return []byte("[]"), nil
	}
	// Reject excessive or malformed output instead of trusting partial data.
	if len(raw) == 0 || len(raw) > 4<<20 || (!allowEmpty && !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("["))) {
		clear(raw)
		return nil, fmt.Errorf("invalid XFRM inventory response")
	}
	return raw, nil
}

// Linux iproute2 emits interface IDs as hexadecimal JSON strings, while
// some releases emit decimal numbers. Missing IDs on policy/state mean
// wildcard 0, but an XFRM interface must explicitly report its ID.
func xfrmIfID(raw json.RawMessage, mandatory bool) (uint32, error) {
	if len(raw) == 0 || string(raw) == "null" {
		if !mandatory {
			return 0, nil
		}
		return 0, fmt.Errorf("missing XFRM ID")
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return 0, fmt.Errorf("malformed XFRM ID")
	}
	var number string
	switch n := v.(type) {
	case string:
		number = n
	case json.Number:
		number = n.String()
	default:
		return 0, fmt.Errorf("non-numeric XFRM ID")
	}
	if strings.TrimSpace(number) != number || strings.HasPrefix(number, "-") {
		return 0, fmt.Errorf("invalid XFRM ID")
	}
	base := 10
	if strings.HasPrefix(number, "0x") || strings.HasPrefix(number, "0X") {
		number = number[2:]
		base = 16
	}
	id, err := strconv.ParseUint(number, base, 32)
	if err != nil || (mandatory && id == 0) {
		return 0, fmt.Errorf("invalid XFRM ID")
	}
	return uint32(id), nil
}
