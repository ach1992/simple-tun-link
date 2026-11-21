//go:build linux

package spoof

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildIPv4UDPAuthenticatedFrameCarrierBytes(t *testing.T) {
	src, dst := netip.MustParseAddr("203.0.113.99"), netip.MustParseAddr("198.51.100.20")
	packet, err := BuildIPv4UDP(src, dst, 41001, 42002, []byte("Noise ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	if packet[0] != 0x45 || packet[9] != 17 ||
		binary.BigEndian.Uint16(packet[2:4]) != uint16(len(packet)) ||
		binary.BigEndian.Uint16(packet[20:22]) != 41001 ||
		binary.BigEndian.Uint16(packet[22:24]) != 42002 ||
		binary.BigEndian.Uint16(packet[24:26]) != uint16(len(packet)-20) {
		t.Fatalf("raw packet has inconsistent framing %x", packet)
	}
	if checksum16(packet[:20]) != 0 {
		t.Fatal("IPv4 header checksum invalid")
	}
	src4, dst4 := src.As4(), dst.As4()
	if udpChecksum(src4, dst4, packet[20:]) != 0xffff {
		// When a full UDP datagram includes its checksum, one's-complement
		// checksum computes zero (mapped to ffff by udpChecksum).
		t.Fatal("UDP checksum invalid")
	}
	if string(packet[28:]) != "Noise ciphertext" {
		t.Fatal("UDP payload changed")
	}
}

func TestRawIPv4UDPRejectsInvalidInputs(t *testing.T) {
	if _, err := BuildIPv4UDP(netip.MustParseAddr("::1"), netip.MustParseAddr("192.0.2.1"), 1, 2, nil); err == nil {
		t.Fatal("IPv6 spoof source accepted")
	}
	if _, err := BuildIPv4UDP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 0, 123, nil); err == nil {
		t.Fatal("zero source port accepted")
	}
	if _, err := BuildIPv4UDP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 2, 123, make([]byte, 65508)); err == nil {
		t.Fatal("invalid total IPv4 length accepted")
	}
}
