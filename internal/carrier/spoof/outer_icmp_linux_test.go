//go:build linux

package spoof

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRawICMPFrameUsesIndependentRealDestinationAndReceiveID(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.99")
	destination := netip.MustParseAddr("10.244.62.198")
	wire, err := BuildIPv4ICMP(source, destination, 42202, []byte("private frame"))
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 20+8+len("private frame") || wire[9] != 1 || wire[20] != 0 || wire[21] != 0 {
		t.Fatalf("unexpected ICMP Echo Reply outer framing %x", wire[:28])
	}
	if got, _ := netip.AddrFromSlice(wire[12:16]); got != source {
		t.Fatalf("forged source rewritten: %s", got)
	}
	if got, _ := netip.AddrFromSlice(wire[16:20]); got != destination {
		t.Fatalf("real peer destination rewritten: %s", got)
	}
	if binary.BigEndian.Uint16(wire[24:26]) != 42202 {
		t.Fatal("ICMP id must be intended peer receive ID")
	}
	if checksum16(wire[:20]) != 0 || checksum16(wire[20:]) != 0 {
		t.Fatal("ICMP/IPv4 header checksums invalid")
	}
	if string(wire[28:]) != "private frame" {
		t.Fatal("payload altered")
	}
	if _, err = BuildIPv4ICMP(source, destination, 0, nil); err == nil {
		t.Fatal("zero peer receive ID accepted")
	}
	if _, err = OpenFrameReceiver(netip.MustParseAddrPort("10.244.62.198:42202"), "unvalidated", ""); err == nil {
		t.Fatal("unsupported outer protocol silently degraded to UDP")
	}
}
