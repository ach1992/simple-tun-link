package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// diagnosticPacketCounters performs an optional, bounded, read-only kernel
// inspection. Missing, malformed or unverifiable stats never become measured
// zero. The caller has already independently attested admission, exact XFRM
// device ownership and an installed SA. Revalidate device identity here to
// avoid assigning another interface's packets to this Link.
func (b *OperationalBackend) diagnosticPacketCounters(ctx context.Context, profile Profile, ifindex int) (*uint64, *uint64) {
	if b == nil || b.Runner == nil || ctx == nil || ctx.Err() != nil || ifindex <= 0 {
		return nil, nil
	}
	result, err := b.Runner.RunBounded(ctx,
		CaptureLimits{Stdout: 32 << 10, Stderr: 1024},
		b.IPBinary, "-s", "-details", "-json", "link", "show", "dev", profile.InterfaceName)
	if err != nil {
		clear(result.Stdout)
		clear(result.Stderr)
		return nil, nil
	}
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	rx, tx, err := parseIPsecPacketCounters(result.Stdout, profile, ifindex)
	if err != nil {
		return nil, nil
	}
	return &rx, &tx
}

// parseIPsecPacketCounters requires a single exact XFRM link record and
// actual stats64 packet fields. It uses the XFRM duplicate-key-aware parser
// instead of Go's last-key-wins struct unmarshalling. Do not accept an
// unverified interface name, ifindex, if_id or synthesized missing counters.
func parseIPsecPacketCounters(raw []byte, profile Profile, ifindex int) (uint64, uint64, error) {
	if len(raw) == 0 || len(raw) > 32<<10 || bytes.IndexByte(raw, 0) >= 0 {
		return 0, 0, fmt.Errorf("IPsec packet counters unavailable")
	}
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil || len(records) != 1 {
		return 0, 0, fmt.Errorf("IPsec packet counter inventory unverified")
	}
	defer clear(records[0])
	name, ifid, isXFRM, err := xfrmLinkIdentity(records[0])
	if err != nil || !isXFRM || name != profile.InterfaceName || ifid != profile.InterfaceID {
		return 0, 0, fmt.Errorf("IPsec packet counter identity unverified")
	}
	link, err := xfrmUniqueJSONObject(records[0], "ifname", "linkinfo", "ifindex", "ifalias", "stats64")
	if err != nil {
		return 0, 0, fmt.Errorf("IPsec packet counter row ambiguous")
	}
	defer clearXFRMJSONObject(link)
	var index int
	if err := json.Unmarshal(link["ifindex"], &index); err != nil || index <= 0 || index != ifindex {
		return 0, 0, fmt.Errorf("IPsec packet counter ifindex unverified")
	}
	owner, err := domain.OwnerTag(profile.Link.ID)
	if err != nil {
		return 0, 0, fmt.Errorf("IPsec packet counter ownership unavailable")
	}
	var alias string
	if err := json.Unmarshal(link["ifalias"], &alias); err != nil || alias != owner {
		return 0, 0, fmt.Errorf("IPsec packet counter owner tag unverified")
	}
	statsRaw, ok := link["stats64"]
	if !ok {
		return 0, 0, fmt.Errorf("IPsec packet counters not provided by kernel")
	}
	stats, err := xfrmUniqueJSONObject(statsRaw, "rx", "tx")
	if err != nil {
		return 0, 0, fmt.Errorf("IPsec packet counter statistics ambiguous")
	}
	defer clearXFRMJSONObject(stats)
	readPackets := func(key string) (uint64, error) {
		direction, ok := stats[key]
		if !ok {
			return 0, fmt.Errorf("IPsec packet counter direction missing")
		}
		values, err := xfrmUniqueJSONObject(direction, "packets")
		if err != nil {
			return 0, fmt.Errorf("IPsec packet counter direction ambiguous")
		}
		defer clearXFRMJSONObject(values)
		value, ok := values["packets"]
		if !ok {
			return 0, fmt.Errorf("IPsec packet count missing")
		}
		var count uint64
		if err := json.Unmarshal(value, &count); err != nil {
			return 0, fmt.Errorf("IPsec packet count invalid")
		}
		return count, nil
	}
	rx, err := readPackets("rx")
	if err != nil {
		return 0, 0, err
	}
	tx, err := readPackets("tx")
	if err != nil {
		return 0, 0, err
	}
	return rx, tx, nil
}
