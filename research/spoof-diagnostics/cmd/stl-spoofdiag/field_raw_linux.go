//go:build linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// Raw IPv4 is a privileged, bounded research-only adapter. Linux's IPv4
// IP_HDRINCL stack fills the IPv4 checksum and total length; an IPv4 UDP
// checksum of zero is allowed. Only the exact receiver-approved destination,
// port and candidate source list may reach this path via fieldSend.
//
// IMPORTANT: a successful Sendto does not establish that the NIC, provider,
// peer or return path accepted the selected source address.
type rawFieldSocket struct{ fd int }

func openRawFieldSocket(name string) (*rawFieldSocket, error) {
	if name == "" {
		return nil, errors.New("exact sending --interface required")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("selected field interface %q must be UP and non-loopback", name)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw IPv4 socket (CAP_NET_RAW required): %w", err)
	}
	fail := func(err error) (*rawFieldSocket, error) { syscall.Close(fd); return nil, err }
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fail(err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name); err != nil {
		return fail(fmt.Errorf("could not bind raw socket to selected interface: %w", err))
	}
	return &rawFieldSocket{fd: fd}, nil
}

func (s *rawFieldSocket) Close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	fd := s.fd
	s.fd = -1
	return syscall.Close(fd)
}

func makeRawFieldIPv4Packet(source, destination string, port int, payload []byte) ([]byte, syscall.SockaddrInet4, error) {
	if err := validateIP(source, "field_candidates"); err != nil {
		return nil, syscall.SockaddrInet4{}, err
	}
	if err := validateIP(destination, "field_candidates"); err != nil {
		return nil, syscall.SockaddrInet4{}, err
	}
	if port < 1024 || port > 65535 || len(payload) < fieldMinPacket || len(payload) > fieldMaxPacket {
		return nil, syscall.SockaddrInet4{}, errors.New("invalid raw field port/packet size")
	}
	src := net.ParseIP(source).To4()
	dst := net.ParseIP(destination).To4()
	if src == nil || dst == nil {
		return nil, syscall.SockaddrInet4{}, errors.New("invalid raw packet IPv4")
	}
	const ipHeader = 20
	const udpHeader = 8
	total := ipHeader + udpHeader + len(payload)
	if total > 1500 {
		return nil, syscall.SockaddrInet4{}, errors.New("raw IPv4 packet exceeds initial 1500 byte MTU assumption")
	}
	packet := make([]byte, total)
	packet[0] = 0x45 // IPv4, IHL=5
	packet[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, syscall.SockaddrInet4{}, err
	}
	copy(packet[4:6], id[:])
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Don't Fragment
	packet[8] = 64
	packet[9] = 17 // UDP
	copy(packet[12:16], src)
	copy(packet[16:20], dst)
	binary.BigEndian.PutUint16(packet[20:22], 24101)
	binary.BigEndian.PutUint16(packet[22:24], uint16(port))
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpHeader+len(payload)))
	// UDP checksum zero is permitted for IPv4; never for IPv6.
	copy(packet[28:], payload)
	var sockaddr syscall.SockaddrInet4
	copy(sockaddr.Addr[:], dst)
	sockaddr.Port = 0 // Raw IPv4 sockaddr port is ignored on modern Linux; UDP header carries port.
	return packet, sockaddr, nil
}

// The only operating-system send is here; the preceding constructor is pure.
func (s *rawFieldSocket) Send(source, destination string, port int, payload []byte) error {
	if s == nil || s.fd < 0 {
		return errors.New("raw IPv4 socket is closed")
	}
	packet, addr, err := makeRawFieldIPv4Packet(source, destination, port, payload)
	if err != nil {
		return err
	}
	return syscall.Sendto(s.fd, packet, 0, &addr)
}
