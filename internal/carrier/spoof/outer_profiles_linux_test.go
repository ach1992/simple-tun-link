//go:build linux

package spoof

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func testProfileFrame(t *testing.T) []byte {
	t.Helper()
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (Frame{LinkID: id, Kind: KindHandshake1, Payload: []byte("Noise authenticated payload")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestEverySTLRawOuterProfileRoundTripAndStrictFilter(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.11")
	dst := netip.MustParseAddr("10.244.62.198")
	local := netip.AddrPortFrom(dst, 42202)
	frame := testProfileFrame(t)
	for _, name := range AllProfiles() {
		t.Run(name, func(t *testing.T) {
			wire, err := BuildOuterPacket(name, source, dst, 42001, 42202, frame)
			if err != nil {
				t.Fatal(err)
			}
			proto, err := ProfileNumber(name)
			if err != nil || wire[9] != proto {
				t.Fatalf("wrong IPv4 protocol for %s: %d %v", name, wire[9], err)
			}
			if binary.BigEndian.Uint16(wire[2:4]) != uint16(len(wire)) || checksum16(wire[:20]) != 0 {
				t.Fatal("raw IPv4 packet total length or header checksum invalid")
			}
			if !bytes.Equal(wire[12:16], source.AsSlice()) || !bytes.Equal(wire[16:20], dst.AsSlice()) {
				t.Fatal("Spoof source or fixed real peer destination changed")
			}
			if name == ProfileUDP {
				// UDP is received via normal kernel UDP socket and its
				// checked pseudo-header; not via the generic raw decoder.
				src, dest := source.As4(), dst.As4()
				if udpChecksum(src, dest, wire[20:]) != 0xffff {
					t.Fatal("UDP checksum invalid")
				}
				if !bytes.Equal(wire[28:], frame) {
					t.Fatal("UDP frame corrupted")
				}
				return
			}
			payload, seen, detected, err := DecodeOuterPacket(wire, local, ProfileAuto)
			if err != nil {
				t.Fatal(err)
			}
			if seen.Addr() != source || detected != name || !bytes.Equal(payload, frame) {
				t.Fatalf("outer profile decoded incorrectly: got %v %s payload=%x", seen, detected, payload)
			}
			if _, _, _, err = DecodeOuterPacket(wire, netip.AddrPortFrom(netip.MustParseAddr("10.244.62.199"), 42202), ProfileAuto); err == nil {
				t.Fatal("frame accepted for wrong real peer IPv4")
			}
			if _, _, _, err = DecodeOuterPacket(wire, netip.AddrPortFrom(dst, 42203), name); err == nil &&
				(name == ProfileICMP || name == ProfileTCP || name == ProfileProto58Echo || name == ProfileL2TPv3) {
				t.Fatal("frame accepted with wrong receiver port/identifier")
			}
			if _, _, _, err = DecodeOuterPacket(wire, local, ProfileUDP); err == nil {
				t.Fatal("outer packet accepted as another profile")
			}
			changed := append([]byte(nil), wire...)
			changed[len(changed)-1] ^= 0x11
			if _, _, _, err = DecodeOuterPacket(changed, local, ProfileAuto); err == nil &&
				(name == ProfileTCP || name == ProfileICMP || name == ProfileProto58Echo) {
				t.Fatal("checksum-protected outer payload accepted corrupt bytes")
			}
		})
	}
}

func TestExhaustiveCartesianSourcesAndProfiles50k(t *testing.T) {
	const total = 50000
	inv := Inventory{Addresses: make([]netip.Addr, total)}
	for i := range inv.Addresses {
		inv.Addresses[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	c := DiscoveryCursor{}
	if err := c.ReplaceInventory(inv); err != nil {
		t.Fatal(err)
	}
	profiles := AllProfiles()
	seen := make(map[SourcePath]bool, total*len(profiles))
	for len(seen) < total*len(profiles) {
		batch, err := c.NextPathBatch(profiles, 64)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range batch {
			if seen[p] {
				t.Fatalf("same source+profile tested twice before full pass: %v", p)
			}
			seen[p] = true
		}
	}
	if _, _, passes := c.PathProgress(); passes != 1 {
		t.Fatalf("complete matrix didn't finish exactly once: %d", passes)
	}
}
