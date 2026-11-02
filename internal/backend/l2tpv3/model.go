package l2tpv3

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const protocol = 115

type identity struct {
	name                                     string
	tunnel, peerTunnel, session, peerSession uint32
	mac, peerMAC                             string
}

func InterfaceName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "sl2" + string(id)[4:16], nil
}

// Every shared Link has two deterministic, opposite endpoint identities.
// A per-Link random ID is already part of the canonical pairing offer;
// no separate user-maintained tunnel/session IDs or credentials are needed.
func identityFor(l domain.Link) (identity, error) {
	if err := l.Validate(); err != nil {
		return identity{}, err
	}
	if l.Backend != domain.BackendL2TPv3 {
		return identity{}, fmt.Errorf("L2TPv3 backend received %q", l.Backend)
	}
	name, _ := InterfaceName(l.ID)
	h := sha256.Sum256([]byte("stl/l2tpv3/direct-ip/v1/" + string(l.ID)))
	var ids [4]uint32
	for i := range ids {
		ids[i] = binary.BigEndian.Uint32(h[i*4 : i*4+4])
		if ids[i] == 0 {
			ids[i] = uint32(i + 1)
		}
	}
	for i := range ids {
		for j := 0; j < i; j++ {
			if ids[i] == ids[j] {
				return identity{}, fmt.Errorf("derived L2TPv3 resource IDs collide; use a new Link ID")
			}
		}
	}
	a := l.Underlay.Local.Compare(l.Underlay.Peer) < 0
	local, peer := 0, 1
	if !a {
		local, peer = 1, 0
	}
	macs := [2]string{}
	for i := 0; i < 2; i++ {
		b := sha256.Sum256([]byte(fmt.Sprintf("stl/l2tpv3/mac/%d/%s", i, l.ID)))
		macs[i] = fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4])
	}
	return identity{name: name, tunnel: ids[local], peerTunnel: ids[peer], session: ids[local+2], peerSession: ids[peer+2], mac: macs[local], peerMAC: macs[peer]}, nil
}
func Overhead(l domain.Link) (int, error) {
	if _, err := identityFor(l); err != nil {
		return 0, err
	}
	return 42, nil
}

// The default L2TPv3 Ethernet pseudowire uses outer IPv4, the session
// discriminator, optional L2-specific sublayer, and inner Ethernet header.
// Auto MTU uses a conservative 1280 cap rather than claiming measured PMTU.

type tunnel struct {
	TunnelID   uint32 `json:"tunnel_id"`
	PeerTunnel uint32 `json:"peer_tunnel"`
	Encap      string `json:"encap"`
	Local      string `json:"local"`
	Peer       string `json:"peer"`
}

func (t tunnel) valid() bool {
	a, e1 := netip.ParseAddr(t.Local)
	b, e2 := netip.ParseAddr(t.Peer)
	return t.TunnelID != 0 && t.PeerTunnel != 0 && t.TunnelID != t.PeerTunnel &&
		t.Encap == "IP" && e1 == nil && e2 == nil && a.Is4() && b.Is4() && a != b
}

type session struct {
	SessionID     uint32 `json:"session_id"`
	TunnelID      uint32 `json:"tunnel_id"`
	PeerSessionID uint32 `json:"peer_session_id"`
	PeerTunnelID  uint32 `json:"peer_tunnel_id"`
	Interface     string `json:"interface"`
}
type iface struct {
	IfIndex int      `json:"ifindex"`
	IfName  string   `json:"ifname"`
	IfAlias string   `json:"ifalias"`
	Address string   `json:"address"`
	Flags   []string `json:"flags"`
}
type ifaceAddr struct {
	IfIndex  int    `json:"ifindex"`
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
		Protocol  string `json:"protocol"`
	} `json:"addr_info"`
}
type neighbor struct {
	Dst    string          `json:"dst"`
	LLAddr string          `json:"lladdr"`
	State  json.RawMessage `json:"state"`
}

func parseNeighbors(raw []byte) ([]neighbor, error) {
	var rows []neighbor
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse L2TPv3 neighbors: %w", err)
	}
	for _, n := range rows {
		if _, err := netip.ParseAddr(n.Dst); err != nil {
			return nil, fmt.Errorf("invalid L2TPv3 neighbor address")
		}
		if n.LLAddr != "" {
			if _, err := net.ParseMAC(n.LLAddr); err != nil {
				return nil, fmt.Errorf("invalid L2TPv3 neighbor MAC")
			}
		}
	}
	return rows, nil
}
func neighborPermanent(n neighbor) bool {
	var states []string
	if json.Unmarshal(n.State, &states) == nil {
		return slices.Contains(states, "PERMANENT")
	}
	var state string
	return json.Unmarshal(n.State, &state) == nil && strings.EqualFold(state, "PERMANENT")
}
func parseJSON[T any](raw []byte, label string) ([]T, error) {
	var items []T
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("parse L2TPv3 %s inventory: %w", label, err)
	}
	return items, nil
}
func mtuResource(l domain.Link, id identity) []domain.ResourceClaim {
	return []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: id.name},
		{Kind: domain.ResourceLinkAddress, Key: l.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: l.Addresses.Local.Masked().String()},
	}
}
func ownedClaims(l domain.Link, id identity, fw domain.ResourceClaim) []domain.ResourceClaim {
	return append(mtuResource(l, id),
		domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "l2tpv3/tunnel/" + strconv.FormatUint(uint64(id.tunnel), 10)},
		domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "l2tpv3/session/" + strconv.FormatUint(uint64(id.session), 10)},
		fw,
	)
}
func validLink(l domain.Link) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if l.Backend != domain.BackendL2TPv3 || l.Encapsulation != domain.EncapNative || !l.Underlay.Local.Is4() || !l.Underlay.Peer.Is4() {
		return stlerr.New(stlerr.CodeUnsupported, "l2tpv3_validate", string(l.ID), string(l.Backend), "L2TPv3 Direct-IP requires native encapsulation and IPv4 peer endpoints")
	}
	return nil
}
