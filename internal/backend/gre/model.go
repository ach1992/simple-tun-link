package gre

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const greProtocol = 47

type encapJSON struct {
	Type  string `json:"type"`
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
}

type linkJSON struct {
	IfIndex  int      `json:"ifindex"`
	IfName   string   `json:"ifname"`
	IfAlias  string   `json:"ifalias"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			Remote string     `json:"remote"`
			Local  string     `json:"local"`
			TTL    uint8      `json:"ttl"`
			TOS    string     `json:"tos"`
			PMTUD  *bool      `json:"pmtudisc"`
			IKey   string     `json:"ikey"`
			OKey   string     `json:"okey"`
			ISeq   bool       `json:"iseq"`
			OSeq   bool       `json:"oseq"`
			ICsum  bool       `json:"icsum"`
			OCsum  bool       `json:"ocsum"`
			Encap  *encapJSON `json:"encap"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

type addressJSON struct {
	IfIndex  int    `json:"ifindex"`
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type observedLink struct {
	Exists        bool
	IfIndex       int
	Name          string
	Alias         string
	Owner         domain.LinkID
	Up            bool
	Local         netip.Addr
	Peer          netip.Addr
	KeyEnabled    bool
	Key           uint32
	TTL           uint8
	TOS           uint8
	PMTUD         bool
	Checksum      bool
	Sequence      bool
	Encapsulation domain.Encapsulation
	UDPPort       uint16
	IPv4Addresses []netip.Prefix
}

func parseGRELinks(raw []byte) ([]observedLink, error) {
	// json.Unmarshal accepts top-level null into a nil slice, but inspection
	// must never treat malformed or absent output as zero GRE interfaces.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("GRE link inspection must be a JSON array")
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, fmt.Errorf("parse GRE link state: %w", err)
	}
	out := make([]observedLink, 0, len(rows))
	for _, item := range rows {
		// iproute2 can emit exact empty JSON objects for unrelated interfaces
		// when filtering by type gre before the GRE module is loaded. Ignore
		// only those placeholders: partially populated observations must still
		// fail closed rather than masking a foreign/corrupted GRE identity.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil || fields == nil {
			return nil, fmt.Errorf("invalid GRE link inspection row")
		}
		if len(fields) == 0 {
			continue
		}
		var row linkJSON
		if err := json.Unmarshal(item, &row); err != nil {
			return nil, fmt.Errorf("invalid GRE link inspection row: %w", err)
		}
		// Only the kernel's genuine gre0 fallback is safely ignorable. Any
		// other wildcard GRE row (or a malformed gre0 identity) must fail
		// closed rather than disappear from conflict/ownership inspection.
		local := strings.TrimSpace(row.LinkInfo.InfoData.Local)
		remote := strings.TrimSpace(row.LinkInfo.InfoData.Remote)
		if local == "any" || remote == "any" {
			if row.IfName != "gre0" || row.IfIndex <= 0 ||
				row.LinkInfo.InfoKind != "gre" || row.IfAlias != "" ||
				local != "any" || remote != "any" ||
				row.LinkInfo.InfoData.IKey != "" || row.LinkInfo.InfoData.OKey != "" ||
				row.LinkInfo.InfoData.Encap != nil ||
				row.LinkInfo.InfoData.ICsum || row.LinkInfo.InfoData.OCsum ||
				row.LinkInfo.InfoData.ISeq || row.LinkInfo.InfoData.OSeq {
				return nil, fmt.Errorf("invalid GRE wildcard fallback inspection row")
			}
			continue
		}
		state, err := parseGRELink(row)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	return out, nil
}

func parseGRELink(row linkJSON) (observedLink, error) {
	if row.IfName == "" || row.LinkInfo.InfoKind != "gre" || row.IfIndex <= 0 {
		return observedLink{}, fmt.Errorf("invalid GRE link inspection row")
	}
	local, err := netip.ParseAddr(strings.TrimSpace(row.LinkInfo.InfoData.Local))
	if err != nil || !local.Is4() {
		return observedLink{}, fmt.Errorf("invalid inspected GRE local underlay")
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(row.LinkInfo.InfoData.Remote))
	if err != nil || !peer.Is4() {
		return observedLink{}, fmt.Errorf("invalid inspected GRE peer underlay")
	}
	state := observedLink{
		Exists: true, IfIndex: row.IfIndex, Name: row.IfName, Alias: row.IfAlias, Local: local,
		Peer: peer, TTL: row.LinkInfo.InfoData.TTL, PMTUD: true, Encapsulation: domain.EncapNative,
	}
	if owner, ok := linux.ParseOwnerTag(row.IfAlias); ok {
		state.Owner = owner
	}
	state.Up = slices.Contains(row.Flags, "UP")
	if row.LinkInfo.InfoData.PMTUD != nil {
		state.PMTUD = *row.LinkInfo.InfoData.PMTUD
	}
	if text := strings.TrimSpace(row.LinkInfo.InfoData.TOS); text != "" {
		value, err := strconv.ParseUint(strings.TrimPrefix(text, "0x"), 16, 8)
		if err != nil {
			return observedLink{}, fmt.Errorf("invalid inspected GRE TOS")
		}
		state.TOS = uint8(value)
	}
	if row.LinkInfo.InfoData.IKey != "" || row.LinkInfo.InfoData.OKey != "" {
		in, err := parseGREKey(row.LinkInfo.InfoData.IKey)
		if err != nil {
			return observedLink{}, err
		}
		out, err := parseGREKey(row.LinkInfo.InfoData.OKey)
		if err != nil || in != out {
			return observedLink{}, fmt.Errorf("asymmetric or invalid inspected GRE key")
		}
		state.KeyEnabled, state.Key = true, in
	}
	if row.LinkInfo.InfoData.ICsum != row.LinkInfo.InfoData.OCsum || row.LinkInfo.InfoData.ISeq != row.LinkInfo.InfoData.OSeq {
		return observedLink{}, fmt.Errorf("asymmetric GRE checksum/sequence state is unsupported")
	}
	state.Checksum = row.LinkInfo.InfoData.ICsum
	state.Sequence = row.LinkInfo.InfoData.ISeq
	if encap := row.LinkInfo.InfoData.Encap; encap != nil {
		switch encap.Type {
		case string(domain.EncapFOU):
			state.Encapsulation = domain.EncapFOU
		case string(domain.EncapGUE):
			state.Encapsulation = domain.EncapGUE
		default:
			return observedLink{}, fmt.Errorf("unsupported inspected GRE UDP encapsulation")
		}
		if encap.Sport == 0 || encap.Sport != encap.Dport {
			return observedLink{}, fmt.Errorf("inspected GRE UDP ports are not symmetric")
		}
		state.UDPPort = encap.Sport
	}
	return state, nil
}

func parseGREKey(text string) (uint32, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("invalid inspected GRE key")
	}
	bytes := addr.As4()
	return binary.BigEndian.Uint32(bytes[:]), nil
}

func parseIPv4Addresses(raw []byte, name string, ifindex int) ([]netip.Prefix, error) {
	var rows []addressJSON
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse GRE address state: %w", err)
	}
	// Address lookup uses a reusable name. The returned kernel ifindex must
	// agree with the earlier link snapshot before combining both observations.
	if len(rows) != 1 || ifindex <= 0 || rows[0].IfIndex != ifindex || rows[0].IfName != name {
		return nil, fmt.Errorf("GRE address observation identity changed; preserving current host state")
	}
	var out []netip.Prefix
	for _, row := range rows {
		for _, info := range row.AddrInfo {
			if info.Family != "inet" {
				continue
			}
			addr, err := netip.ParseAddr(info.Local)
			if err != nil || !addr.Is4() || info.PrefixLen < 0 || info.PrefixLen > 32 {
				return nil, fmt.Errorf("invalid inspected GRE IPv4 address")
			}
			out = append(out, netip.PrefixFrom(addr, info.PrefixLen))
		}
	}
	return out, nil
}

func (g observedLink) matches(link domain.Link, name string) bool {
	if !g.Exists || g.Name != name || g.Owner != link.ID || !g.Up || g.Local != link.Underlay.Local || g.Peer != link.Underlay.Peer {
		return false
	}
	expectedAlias, err := linux.OwnerTag(link.ID)
	if err != nil || g.Alias != expectedAlias {
		return false
	}
	if g.KeyEnabled != link.GRE.KeyEnabled || (g.KeyEnabled && g.Key != link.GRE.Key) ||
		g.TTL != link.GRE.TTL || g.TOS != link.GRE.TOS ||
		g.PMTUD == link.GRE.DisablePMTUD || g.Checksum != link.GRE.Checksum || g.Sequence != link.GRE.Sequence ||
		g.Encapsulation != link.Encapsulation || g.UDPPort != link.GRE.UDPPort {
		return false
	}
	return len(g.IPv4Addresses) == 1 && g.IPv4Addresses[0] == link.Addresses.Local
}

func (g observedLink) matchesConfigurationBeforeOwnership(link domain.Link, name string) bool {
	if !g.Exists || g.Name != name || g.Local != link.Underlay.Local || g.Peer != link.Underlay.Peer {
		return false
	}
	return g.KeyEnabled == link.GRE.KeyEnabled && (!g.KeyEnabled || g.Key == link.GRE.Key) &&
		g.TTL == link.GRE.TTL && g.TOS == link.GRE.TOS &&
		g.PMTUD != link.GRE.DisablePMTUD && g.Checksum == link.GRE.Checksum && g.Sequence == link.GRE.Sequence &&
		g.Encapsulation == link.Encapsulation && g.UDPPort == link.GRE.UDPPort
}

func (g observedLink) receiveIdentity() string {
	if !g.Exists || !g.Local.IsValid() || !g.Peer.IsValid() {
		return ""
	}
	return greReceiveIdentity(g.Local, g.Peer, g.KeyEnabled, g.Key)
}

func validateLink(link domain.Link) error {
	if err := link.Validate(); err != nil {
		return err
	}
	if link.Backend != domain.BackendGRE {
		return fmt.Errorf("GRE backend received %q Link", link.Backend)
	}
	if !link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
		return stlerr.New(stlerr.CodeUnsupported, "gre_plan", string(link.ID), string(link.Backend), "v0.1 GRE requires IPv4 underlay endpoints")
	}
	return nil
}

func InterfaceName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	// 3 byte prefix + 12 hex chars = Linux IFNAMSIZ-1 (15) characters.
	return "stl" + string(id)[4:16], nil
}

func Overhead(link domain.Link) (int, error) {
	if err := validateLink(link); err != nil {
		return 0, err
	}
	overhead := 24 // outer IPv4 (20) + base GRE (4)
	switch link.Encapsulation {
	case domain.EncapFOU:
		overhead += 8 // UDP
	case domain.EncapGUE:
		overhead += 12 // UDP + 4-byte GUE base header
	}
	if link.GRE.Checksum {
		overhead += 4
	}
	if link.GRE.KeyEnabled {
		overhead += 4
	}
	if link.GRE.Sequence {
		overhead += 4
	}
	return overhead, nil
}

func greTypeArgs(link domain.Link) []string {
	args := []string{"type", "gre", "local", link.Underlay.Local.String(), "remote", link.Underlay.Peer.String()}
	if link.GRE.KeyEnabled {
		args = append(args, "key", strconv.FormatUint(uint64(link.GRE.Key), 10))
	}
	if link.GRE.TTL != 0 {
		args = append(args, "ttl", strconv.Itoa(int(link.GRE.TTL)))
	}
	if link.GRE.TOS != 0 {
		args = append(args, "tos", fmt.Sprintf("0x%02x", link.GRE.TOS))
	}
	if link.GRE.DisablePMTUD {
		args = append(args, "nopmtudisc")
	}
	if link.GRE.Checksum {
		args = append(args, "icsum", "ocsum")
	}
	if link.GRE.Sequence {
		args = append(args, "iseq", "oseq")
	}
	if link.Encapsulation == domain.EncapFOU || link.Encapsulation == domain.EncapGUE {
		port := strconv.Itoa(int(link.GRE.UDPPort))
		args = append(args, "encap", string(link.Encapsulation), "encap-sport", port, "encap-dport", port)
	}
	return args
}

// Linux GRE receive lookup can collide across Native/FOU/GUE when the
// underlay endpoint pair and GRE key identity match, regardless of outer
// UDP encapsulation/port. Keep this independent of the existing detailed
// backend identity so older persisted resource claims remain compatible.
func greReceiveIdentity(local, peer netip.Addr, keyed bool, key uint32) string {
	keyText := "absent"
	if keyed {
		keyText = strconv.FormatUint(uint64(key), 10)
	}
	return "gre/rx/" + local.String() + "/" + peer.String() + "/key=" + keyText
}

func greReceiveClaim(link domain.Link) domain.ResourceClaim {
	return domain.ResourceClaim{
		Kind: domain.ResourceBackendID,
		Key:  greReceiveIdentity(link.Underlay.Local, link.Underlay.Peer, link.GRE.KeyEnabled, link.GRE.Key),
	}
}

func backendIdentity(local, peer netip.Addr, keyed bool, key uint32, encap domain.Encapsulation, port uint16) string {
	keyText := "none"
	if keyed {
		keyText = strconv.FormatUint(uint64(key), 10)
	}
	identity := "gre/" + string(encap) + "/" + local.String() + "/" + peer.String() + "/key=" + keyText
	if port != 0 {
		identity += "/udp=" + strconv.Itoa(int(port))
	}
	return identity
}

func desiredResources(link domain.Link, name string, firewall domain.ResourceClaim) []domain.ResourceClaim {
	return append(commonCollisionClaims(link, name),
		domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: backendIdentity(link.Underlay.Local, link.Underlay.Peer, link.GRE.KeyEnabled, link.GRE.Key, link.Encapsulation, link.GRE.UDPPort)},
		greReceiveClaim(link),
		firewall,
	)
}

func commonCollisionClaims(link domain.Link, name string) []domain.ResourceClaim {
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: name},
		{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
	}
	if link.Encapsulation == domain.EncapFOU || link.Encapsulation == domain.EncapGUE {
		claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.GRE.UDPPort))})
	}
	return claims
}
