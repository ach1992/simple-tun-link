//go:build linux

package spoof

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	ipv4MinHeader = 20
	udpHeaderSize = 8
	udpProtocol   = 17
)

func checksum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(source, destination [4]byte, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], destination[:])
	pseudo[9] = udpProtocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	result := checksum16(pseudo)
	if result == 0 {
		return 0xffff
	} // RFC768: zero on wire means checksum disabled
	return result
}

// BuildIPv4UDP constructs one exact UDP datagram for a known peer. The
// selected Source is ONLY the outer IPv4 source; it is neither the private
// TUN address nor the destination of replies. Linux may still reject/drop
// it; successful packet construction or send is never proof of a path.
func BuildIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) ([]byte, error) {
	if !source.Is4() || !destination.Is4() || sourcePort == 0 || destinationPort == 0 ||
		len(payload) > 65535-ipv4MinHeader-udpHeaderSize {
		return nil, errors.New("raw IPv4 UDP needs literal source/destination, nonzero ports and a valid IPv4 length")
	}
	total := ipv4MinHeader + udpHeaderSize + len(payload)
	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	var identifier [2]byte
	if _, err := rand.Read(identifier[:]); err != nil {
		return nil, fmt.Errorf("packet identifier: %w", err)
	}
	copy(packet[4:6], identifier[:])
	packet[8] = 64 // TTL
	packet[9] = udpProtocol
	src, dst := source.As4(), destination.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpHeaderSize+len(payload)))
	copy(packet[28:], payload)
	binary.BigEndian.PutUint16(packet[26:28], udpChecksum(src, dst, packet[20:]))
	binary.BigEndian.PutUint16(packet[10:12], checksum16(packet[:20]))
	return packet, nil
}

// RawSender has one pinned real peer destination, one operator-provided
// candidate inventory, and optionally one verified route-selected device.
// It cannot be used to scan other destinations or invent source addresses.
type RawSender struct {
	fd        int
	peer      netip.AddrPort
	localPort uint16
	allowed   map[netip.Addr]struct{}
	mu        sync.Mutex
	icmp      bool
}

func OpenRawSender(peer netip.AddrPort, localPort uint16, sources Inventory, outputInterface string) (*RawSender, error) {
	if !peer.IsValid() || !peer.Addr().Is4() || peer.Addr().IsUnspecified() || peer.Port() == 0 ||
		localPort == 0 || len(sources.Addresses) == 0 {
		return nil, errors.New("spoof source sender requires exact real peer endpoint, listen port and local sources")
	}
	allowed := make(map[netip.Addr]struct{}, len(sources.Addresses))
	for _, source := range sources.Addresses {
		if !source.Is4() {
			return nil, errors.New("spoof source inventory contains a non-IPv4 entry")
		}
		allowed[source] = struct{}{}
	}
	if outputInterface != "" {
		iface, err := net.InterfaceByName(outputInterface)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return nil, errors.New("spoof sending interface must exist and be UP")
		}
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw IPv4 sender (CAP_NET_RAW needed): %w", err)
	}
	fail := func(err error) (*RawSender, error) { unix.Close(fd); return nil, err }
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return fail(fmt.Errorf("enable raw IPv4 header construction: %w", err))
	}
	if outputInterface != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, outputInterface); err != nil {
			return fail(fmt.Errorf("bind sending device %q: %w", outputInterface, err))
		}
	}
	return &RawSender{fd: fd, peer: peer, localPort: localPort, allowed: allowed}, nil
}

// OpenICMPSender uses the same pinned real peer and local user Source
// inventory as raw UDP. The ICMP identifier is the peer's receive ID,
// not a reply destination and not a source of authorization.
func OpenICMPSender(peer netip.AddrPort, localID uint16, sources Inventory, outputInterface string) (*RawSender, error) {
	s, err := OpenRawSender(peer, localID, sources, outputInterface)
	if err != nil {
		return nil, err
	}
	s.icmp = true
	return s, nil
}
func BuildIPv4ICMP(source, destination netip.Addr, receiverID uint16, payload []byte) ([]byte, error) {
	if !source.Is4() || !destination.Is4() || receiverID == 0 ||
		len(payload) > 65535-ipv4MinHeader-8 {
		return nil, errors.New("raw ICMP needs exact IPv4 peers, receive ID and bounded payload")
	}
	length := ipv4MinHeader + 8 + len(payload)
	result := make([]byte, length)
	result[0] = 0x45
	binary.BigEndian.PutUint16(result[2:4], uint16(length))
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("ICMP IPv4 packet ID: %w", err)
	}
	copy(result[4:6], id[:])
	result[8] = 64
	result[9] = 1 // ICMPv4
	copy(result[12:16], source.AsSlice())
	copy(result[16:20], destination.AsSlice())
	result[20] = 0 // Unsolicited Echo Reply: avoid kernel reflexive replies to forged Sources.
	binary.BigEndian.PutUint16(result[24:26], receiverID)
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("ICMP sequence: %w", err)
	}
	copy(result[26:28], id[:])
	copy(result[28:], payload)
	binary.BigEndian.PutUint16(result[22:24], checksum16(result[20:]))
	binary.BigEndian.PutUint16(result[10:12], checksum16(result[:20]))
	return result, nil
}

func (s *RawSender) Send(candidate netip.Addr, frame []byte) error {
	if s == nil {
		return errors.New("raw sender absent")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return errors.New("raw sender closed")
	}
	if _, accepted := s.allowed[candidate]; !accepted {
		return errors.New("source address is not present in this endpoint's current local inventory")
	}
	var packet []byte
	var err error
	if s.icmp {
		packet, err = BuildIPv4ICMP(candidate, s.peer.Addr(), s.peer.Port(), frame)
	} else {
		packet, err = BuildIPv4UDP(candidate, s.peer.Addr(), s.localPort, s.peer.Port(), frame)
	}
	if err != nil {
		return err
	}
	dst := unix.SockaddrInet4{}
	copy(dst.Addr[:], s.peer.Addr().AsSlice())
	if err := unix.Sendto(s.fd, packet, 0, &dst); err != nil {
		return fmt.Errorf("raw send to configured real peer failed (not delivery proof): %w", err)
	}
	return nil
}

func (s *RawSender) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	fd := s.fd
	s.fd = -1
	return unix.Close(fd)
}

// OpenReceiver binds the REAL local receive socket, never any spoofed source.
// Underlay delivery, rp_filter, firewall, local port and NAT remain separately
// observable. Do not reply to the packet's source address from ReadFromUDP.
func OpenReceiver(bind netip.AddrPort) (*net.UDPConn, error) {
	if !bind.IsValid() || !bind.Addr().Is4() || bind.Port() == 0 {
		return nil, errors.New("spoof UDP receiver requires an explicit IPv4 local bind and port")
	}
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(bind))
	if err != nil {
		return nil, fmt.Errorf("bind spoof Link receiver %s: %w", bind, err)
	}
	return conn, nil
}
