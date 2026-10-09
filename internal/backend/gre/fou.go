package gre

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type fouMapping struct {
	Port          uint16
	Encapsulation domain.Encapsulation
	IPProto       uint8
	Local         netip.Addr
	Peer          netip.Addr
	PeerPort      uint16
	Device        string
}

func (b *Backend) inspectFOU(ctx context.Context) ([]fouMapping, error) {
	result, err := b.runner.Run(ctx, b.ipBinary, "-json", "fou", "show")
	if err != nil {
		return nil, fmt.Errorf("inspect FOU/GUE receive mappings: %w", err)
	}
	return parseFOUMappings(result.Stdout)
}

func parseFOUMappings(raw []byte) ([]fouMapping, error) {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse FOU/GUE receive mappings: %w", err)
	}
	out := make([]fouMapping, 0, len(rows))
	for _, row := range rows {
		var m fouMapping
		if err := json.Unmarshal(row["port"], &m.Port); err != nil || m.Port == 0 {
			return nil, fmt.Errorf("invalid FOU/GUE receive port")
		}
		if _, isGUE := row["gue"]; isGUE {
			m.Encapsulation = domain.EncapGUE
		} else {
			m.Encapsulation = domain.EncapFOU
			if err := json.Unmarshal(row["ipproto"], &m.IPProto); err != nil || m.IPProto == 0 {
				return nil, fmt.Errorf("invalid FOU receive protocol")
			}
		}
		if value, ok := row["local"]; ok {
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return nil, fmt.Errorf("invalid FOU/GUE local address")
			}
			addr, err := netip.ParseAddr(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("invalid FOU/GUE local address")
			}
			m.Local = addr
		}
		if value, ok := row["peer"]; ok {
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return nil, fmt.Errorf("invalid FOU/GUE peer address")
			}
			addr, err := netip.ParseAddr(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("invalid FOU/GUE peer address")
			}
			m.Peer = addr
		}
		if value, ok := row["peer_port"]; ok {
			if err := json.Unmarshal(value, &m.PeerPort); err != nil {
				return nil, fmt.Errorf("invalid FOU/GUE peer port")
			}
		}
		if value, ok := row["dev"]; ok {
			if err := json.Unmarshal(value, &m.Device); err != nil || strings.TrimSpace(m.Device) == "" {
				return nil, fmt.Errorf("invalid FOU/GUE device")
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func desiredFOUMapping(link domain.Link, route linux.Route) (fouMapping, bool) {
	if link.Encapsulation != domain.EncapFOU && link.Encapsulation != domain.EncapGUE {
		return fouMapping{}, false
	}
	m := fouMapping{
		Port: link.GRE.UDPPort, Encapsulation: link.Encapsulation,
		Local: link.Underlay.Local, Peer: link.Underlay.Peer,
		PeerPort: link.GRE.UDPPort, Device: route.Device,
	}
	if link.Encapsulation == domain.EncapFOU {
		m.IPProto = greProtocol
	}
	return m, true
}

func (m fouMapping) equal(other fouMapping) bool {
	return m.Port == other.Port && m.Encapsulation == other.Encapsulation && m.IPProto == other.IPProto &&
		m.Local == other.Local && m.Peer == other.Peer && m.PeerPort == other.PeerPort && m.Device == other.Device
}

func mappingAtPort(mappings []fouMapping, desired fouMapping) (exact bool, collision bool) {
	for _, existing := range mappings {
		if existing.Port != desired.Port {
			continue
		}
		if existing.equal(desired) {
			exact = true
		} else {
			collision = true
		}
	}
	return exact, collision
}

func (b *Backend) addFOU(ctx context.Context, m fouMapping) (bool, error) {
	before, err := b.inspectFOU(ctx)
	if err != nil {
		return false, err
	}
	exact, collision := mappingAtPort(before, m)
	if collision || exact {
		return false, fmt.Errorf("FOU/GUE receive port changed after planning")
	}
	args := []string{"fou", "add", "port", strconv.Itoa(int(m.Port))}
	if m.Encapsulation == domain.EncapGUE {
		args = append(args, "gue")
	} else {
		args = append(args, "ipproto", strconv.Itoa(int(m.IPProto)))
	}
	args = append(args,
		"local", m.Local.String(), "peer", m.Peer.String(),
		"peer_port", strconv.Itoa(int(m.PeerPort)), "dev", m.Device,
	)
	if _, err := b.runner.Run(ctx, b.ipBinary, args...); err != nil {
		// A failed add is ambiguous. Do not delete a now-present exact mapping:
		// an external actor may have won the race after our absence check.
		return false, fmt.Errorf("create FOU/GUE receive mapping: %w", err)
	}
	after, err := b.inspectFOU(ctx)
	if err != nil {
		return true, fmt.Errorf("verify created FOU/GUE receive mapping: %w", err)
	}
	exact, collision = mappingAtPort(after, m)
	if !exact || collision {
		return true, fmt.Errorf("verify created FOU/GUE receive mapping: expected exact mapping not found")
	}
	return true, nil
}

func (b *Backend) deleteFOU(ctx context.Context, m fouMapping) (bool, error) {
	before, err := b.inspectFOU(ctx)
	if err != nil {
		return false, err
	}
	exact, collision := mappingAtPort(before, m)
	if collision {
		return false, fmt.Errorf("FOU/GUE receive port no longer matches owned mapping")
	}
	if !exact {
		return false, nil
	}
	args := []string{
		"fou", "del", "port", strconv.Itoa(int(m.Port)),
		"local", m.Local.String(), "peer", m.Peer.String(),
		"peer_port", strconv.Itoa(int(m.PeerPort)), "dev", m.Device,
	}
	if _, err := b.runner.Run(ctx, b.ipBinary, args...); err != nil {
		after, inspectErr := b.inspectFOU(context.WithoutCancel(ctx))
		if inspectErr == nil {
			stillExact, nowCollision := mappingAtPort(after, m)
			if !stillExact && !nowCollision {
				return true, fmt.Errorf("remove FOU/GUE receive mapping returned an error after deletion: %w", err)
			}
		}
		return false, fmt.Errorf("remove FOU/GUE receive mapping: %w", err)
	}
	after, err := b.inspectFOU(ctx)
	if err != nil {
		return true, fmt.Errorf("verify removed FOU/GUE receive mapping: %w", err)
	}
	exact, collision = mappingAtPort(after, m)
	if exact || collision {
		return true, fmt.Errorf("verify removed FOU/GUE receive mapping: receive port still exists")
	}
	return true, nil
}

func fouResourceClaim(link domain.Link) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.GRE.UDPPort))}
}
