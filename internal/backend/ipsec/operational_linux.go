package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"slices"
)

type xfrmLink struct {
	Exists     bool
	Index      int
	ID         uint32
	Alias      string
	Up         bool
	HasAddress bool
}

func (l xfrmLink) matches(p Profile) bool {
	alias, err := domain.OwnerTag(p.Link.ID)
	return err == nil && l.Exists && l.Index > 0 &&
		l.ID == p.InterfaceID && l.Alias == alias && l.Up && l.HasAddress
}

func (b *OperationalBackend) inspectDevice(ctx context.Context, p Profile) (xfrmLink, error) {
	if err := b.authorize(ctx); err != nil {
		return xfrmLink{}, err
	}
	result, err := b.Runner.RunBounded(ctx,
		CaptureLimits{Stdout: 256 << 10, Stderr: 1024},
		b.IPBinary, "-details", "-json", "link", "show")
	if err != nil {
		return xfrmLink{}, fmt.Errorf("IPsec interface inventory failed")
	}
	defer clear(result.Stdout)
	var entries []json.RawMessage
	if len(result.Stdout) == 0 || len(result.Stdout) > 256<<10 ||
		json.Unmarshal(result.Stdout, &entries) != nil || entries == nil {
		return xfrmLink{}, fmt.Errorf("invalid IPsec interface inventory")
	}
	defer func() {
		for _, entry := range entries {
			clear(entry)
		}
	}()
	var found xfrmLink
	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name, ifid, isXFRM, err := xfrmLinkIdentity(entry)
		if err != nil || name == "" {
			return xfrmLink{}, fmt.Errorf("ambiguous IPsec host interface identity")
		}
		if _, exists := names[name]; exists {
			return xfrmLink{}, fmt.Errorf("duplicate IPsec host interface identity")
		}
		names[name] = struct{}{}
		if name != p.InterfaceName {
			if isXFRM && ifid == p.InterfaceID {
				return xfrmLink{}, fmt.Errorf("another XFRM interface occupies this Link identity")
			}
			continue
		}
		if !isXFRM {
			return xfrmLink{}, fmt.Errorf("planned IPsec interface name is a foreign device")
		}
		row, err := xfrmUniqueJSONObject(entry, "ifname", "linkinfo", "ifindex", "ifalias", "flags")
		if err != nil {
			return xfrmLink{}, fmt.Errorf("IPsec interface metadata is ambiguous")
		}
		var index int
		var alias string
		var flags []string
		indexErr := json.Unmarshal(row["ifindex"], &index)
		aliasErr := error(nil)
		if raw, ok := row["ifalias"]; ok {
			aliasErr = json.Unmarshal(raw, &alias)
		}
		flagsErr := json.Unmarshal(row["flags"], &flags)
		clearXFRMJSONObject(row)
		if indexErr != nil || aliasErr != nil || flagsErr != nil || index <= 0 {
			return xfrmLink{}, fmt.Errorf("incomplete IPsec interface metadata")
		}
		found = xfrmLink{Exists: true, Index: index, ID: ifid, Alias: alias, Up: slices.Contains(flags, "UP")}
	}
	if !found.Exists {
		return xfrmLink{}, nil
	}
	if found.ID != p.InterfaceID {
		return xfrmLink{}, fmt.Errorf("planned IPsec interface ID conflicts with observed interface")
	}
	// Query only the one canonical device. Never trust a kernel address merely
	// because it overlaps the intended subnet on a different host interface.
	addressResult, err := b.Runner.RunBounded(ctx,
		CaptureLimits{Stdout: 32 << 10, Stderr: 1024},
		b.IPBinary, "-json", "address", "show", "dev", p.InterfaceName)
	if err != nil {
		return xfrmLink{}, fmt.Errorf("cannot verify exact IPsec Link Address")
	}
	defer clear(addressResult.Stdout)
	var records []struct {
		Index    int    `json:"ifindex"`
		Name     string `json:"ifname"`
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if len(addressResult.Stdout) == 0 || len(addressResult.Stdout) > 32<<10 ||
		json.Unmarshal(addressResult.Stdout, &records) != nil || len(records) != 1 ||
		records[0].Index != found.Index || records[0].Name != p.InterfaceName {
		return xfrmLink{}, fmt.Errorf("ambiguous exact IPsec address inventory")
	}
	local := p.Link.Addresses.Local
	v4Count := 0
	for _, addr := range records[0].AddrInfo {
		if addr.Family != "inet" {
			continue
		}
		v4Count++
		if addr.Local != local.Addr().String() || addr.PrefixLen != local.Bits() {
			return xfrmLink{}, fmt.Errorf("IPsec interface has different local IPv4 identity")
		}
	}
	found.HasAddress = v4Count == 1
	if v4Count > 1 {
		return xfrmLink{}, fmt.Errorf("IPsec interface has multiple IPv4 addresses")
	}
	// No external command output is ever used in an error, log or status.
	if bytes.IndexByte(addressResult.Stdout, 0) >= 0 {
		return xfrmLink{}, fmt.Errorf("invalid IPsec address inventory")
	}
	return found, nil
}

// hasIPsecSA verifies both directions of the exact owned ESP CHILD association.
// iproute2 state can include encryption key bytes: clear every buffer and
// never relay daemon/kernel output through errors, logs or diagnostics.
func (b *OperationalBackend) hasIPsecSA(ctx context.Context, p Profile) (bool, error) {
	if err := b.authorize(ctx); err != nil {
		return false, err
	}
	ip := b.XFRM.IPBinary
	if ip == "" {
		ip = b.IPBinary
	}
	raw, err := b.XFRM.read(ctx, ip, true, "-json", "xfrm", "state")
	if err != nil {
		return false, fmt.Errorf("cannot read IPsec SA inventory")
	}
	defer clear(raw)
	verified, err := matchingProfileSA(ctx, raw, p)
	if err != nil {
		return false, fmt.Errorf("IPsec peer/CHILD SA inventory unverified")
	}
	return verified, nil
}
