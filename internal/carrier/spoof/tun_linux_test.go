//go:build linux

package spoof

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSpoofTunNameAndPrivatePacketBoundary(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	name, err := TunnelName(id)
	if err != nil || len(name) > 15 || name != "stls0123456789" {
		t.Fatalf("TUN name %s: %v", name, err)
	}
	local, peer := netip.MustParseAddr("10.99.0.0"), netip.MustParseAddr("10.99.0.1")
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], local.AsSlice())
	copy(packet[16:20], peer.AsSlice())
	if err := validPrivatePacket(packet, local, peer, 1280); err != nil {
		t.Fatal(err)
	}
	if err := validPrivatePacket(packet, peer, local, 1280); err == nil {
		t.Fatal("wrong inner private source accepted")
	}
	packet[0] = 0x65
	if err := validPrivatePacket(packet, local, peer, 1280); err == nil {
		t.Fatal("IPv6 inner packet accepted")
	}
	packet[0] = 0x45
	packet[3] = 0
	if err := validPrivatePacket(packet, local, peer, 1280); err == nil {
		t.Fatal("inconsistent inner IP length accepted")
	}
}

// Receiver MTU is a *local outbound* constraint, not a limit on a
// differently routed authenticated peer's valid incoming private packet.
func TestSpoofAsymmetricLocalMTUDoesNotRejectValidRemoteIPv4(t *testing.T) {
	local, peer := netip.MustParseAddr("10.245.100.2"), netip.MustParseAddr("10.245.100.1")
	packet := make([]byte, 1056) // A negotiated 1100; B negotiated 1024.
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], peer.AsSlice())
	copy(packet[16:20], local.AsSlice())
	if err := validPrivatePacket(packet, peer, local, 1024); err == nil {
		t.Fatal("outgoing size gate incorrectly claims to permit 1056")
	}
	if err := validPrivatePacket(packet, peer, local, maxAuthenticatedIncomingIPv4Bytes); err != nil {
		t.Fatalf("valid authenticated asymmetric incoming packet rejected: %v", err)
	}
	if err := validPrivatePacket(packet, local, peer, maxAuthenticatedIncomingIPv4Bytes); err == nil {
		t.Fatal("wrong remote source or inner destination accepted")
	}
}
