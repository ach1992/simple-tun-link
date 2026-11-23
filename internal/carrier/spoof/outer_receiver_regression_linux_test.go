//go:build linux

package spoof

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIPIPReceiverAcceptsPostDNATDestination(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.11")
	advertised := netip.MustParseAddr("203.0.113.10")
	bind := netip.MustParseAddrPort("10.10.0.3:49001")
	frame := testProfileFrame(t)
	wire, err := BuildOuterPacket(ProfileIPIP, source, advertised, 42001, 48001, frame)
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary destination NAT updates the outer IPv4 header only. The
	// experimental nested header still carries the advertised destination.
	copy(wire[16:20], bind.Addr().AsSlice())
	wire[10], wire[11] = 0, 0
	binary.BigEndian.PutUint16(wire[10:12], checksum16(wire[:20]))
	for _, policy := range []string{ProfileIPIP, ProfileAuto} {
		payload, seen, profile, err := DecodeOuterPacket(wire, bind, policy)
		if err != nil {
			t.Fatalf("%s rejected delivered post-DNAT IPIP frame: %v", policy, err)
		}
		if !bytes.Equal(payload, frame) || seen.Addr() != source || profile != ProfileIPIP {
			t.Fatalf("%s changed post-DNAT frame/source/profile", policy)
		}
	}
	wrongBind := netip.MustParseAddrPort("10.10.0.4:49001")
	if _, _, _, err := DecodeOuterPacket(wire, wrongBind, ProfileIPIP); err == nil {
		t.Fatal("accepted IPIP addressed to another outer local destination")
	}
	corrupt := bytes.Clone(wire)
	corrupt[20+10] ^= 1
	if _, _, _, err := DecodeOuterPacket(corrupt, bind, ProfileIPIP); err == nil {
		t.Fatal("accepted a corrupt nested IPv4 header")
	}
}

// Run in a disposable network namespace with loopback UP. This opens only
// namespace-local receive sockets and sends no packets or host mutations.
func TestPrivilegedAutoUDPReceiverHonorsIngressDevice(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("STL_SPOOF_RECEIVER_ACCEPTANCE") != "1" {
		t.Skip("requires explicit root acceptance in a disposable network namespace")
	}
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := probe.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	receiver, err := OpenMultiProfileReceiver(endpoint, "lo")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	for _, part := range receiver.parts {
		udp, ok := part.(*udpFrameReceiver)
		if !ok {
			continue
		}
		raw, err := udp.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var device string
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			device, optionErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		}); err != nil {
			t.Fatal(err)
		}
		if optionErr != nil || device != "lo" {
			t.Fatalf("Auto UDP did not bind the selected ingress device: got %q, err %v", device, optionErr)
		}
		return
	}
	t.Fatal("Auto receiver did not open its UDP listener")
}
