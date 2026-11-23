//go:build linux

package spoof

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// These formats are STL's own raw IPv4 carrier framing. For GRE/IPIP/L2TP,
// a protocol-specific wrapper is used, but this is NOT an interoperable GRE,
// IPIP or RFC3931 L2TP pseudowire endpoint: Noise frames remain STL-owned.
const (
	greExperimentalEtherType      = 0x88b5
	ipipInnerExperimentalProtocol = 253
)

func basicIPv4Packet(source, peer netip.Addr, protocol byte, body []byte) ([]byte, error) {
	if !source.Is4() || !peer.Is4() || len(body) > 65535-20 {
		return nil, errors.New("raw carrier requires literal IPv4 source/peer and IPv4-size payload")
	}
	packet := make([]byte, 20+len(body))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	if _, err := rand.Read(packet[4:6]); err != nil {
		return nil, err
	}
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], peer.AsSlice())
	copy(packet[20:], body)
	binary.BigEndian.PutUint16(packet[10:12], checksum16(packet[:20]))
	return packet, nil
}

func BuildOuterPacket(profile string, source, peer netip.Addr, sourcePort, peerPort uint16, frame []byte) ([]byte, error) {
	if sourcePort == 0 || peerPort == 0 {
		return nil, errors.New("raw carrier needs nonzero owned local/peer receive identifiers")
	}
	switch profile {
	case ProfileUDP:
		return BuildIPv4UDP(source, peer, sourcePort, peerPort, frame)
	case ProfileICMP:
		return BuildIPv4ICMP(source, peer, peerPort, frame)
	case ProfileTCP:
		h := make([]byte, 20+len(frame))
		binary.BigEndian.PutUint16(h[0:2], sourcePort)
		binary.BigEndian.PutUint16(h[2:4], peerPort)
		if _, err := rand.Read(h[4:8]); err != nil {
			return nil, err
		}
		h[12] = 5 << 4 // minimum TCP data offset
		h[13] = 4      // RST: no unsolicited SYN/ACK handshake or kernel reflexive response
		copy(h[20:], frame)
		src, dst := source.As4(), peer.As4()
		binary.BigEndian.PutUint16(h[16:18], pseudoChecksum(src, dst, 6, h))
		return basicIPv4Packet(source, peer, 6, h)
	case ProfileGRE:
		h := make([]byte, 4+len(frame))
		binary.BigEndian.PutUint16(h[2:4], greExperimentalEtherType)
		copy(h[4:], frame)
		return basicIPv4Packet(source, peer, 47, h)
	case ProfileIPIP:
		inner, err := basicIPv4Packet(source, peer, ipipInnerExperimentalProtocol, frame)
		if err != nil {
			return nil, err
		}
		return basicIPv4Packet(source, peer, 4, inner)
	case ProfileProto58:
		return basicIPv4Packet(source, peer, 58, frame)
	case ProfileProto58Echo:
		h := make([]byte, 8+len(frame))
		h[0] = 129 // echo-reply-shaped; IPv4 Protocol 58 is NOT real IPv6 ICMP.
		binary.BigEndian.PutUint16(h[4:6], peerPort)
		if _, err := rand.Read(h[6:8]); err != nil {
			return nil, err
		}
		copy(h[8:], frame)
		binary.BigEndian.PutUint16(h[2:4], checksum16(h))
		return basicIPv4Packet(source, peer, 58, h)
	case ProfileL2TPv3:
		// RFC3931 data session header: nonzero 32-bit locally meaningful
		// Session ID, zero-length optional Cookie, then STL's own data.
		// No L2TP control plane/pseudowire is negotiated or claimed.
		h := make([]byte, 4+len(frame))
		binary.BigEndian.PutUint32(h[:4], l2tpSessionID(peerPort))
		copy(h[4:], frame)
		return basicIPv4Packet(source, peer, 115, h)
	default:
		return nil, fmt.Errorf("unsupported raw STL profile %q", profile)
	}
}

func l2tpSessionID(port uint16) uint32 { return (0x5354 << 16) | uint32(port) }

// pseudoChecksum follows IPv4 TCP/UDP one's-complement checksum rules.
func pseudoChecksum(src, dst [4]byte, protocol byte, segment []byte) uint16 {
	b := make([]byte, 12+len(segment))
	copy(b[0:4], src[:])
	copy(b[4:8], dst[:])
	b[9] = protocol
	binary.BigEndian.PutUint16(b[10:12], uint16(len(segment)))
	copy(b[12:], segment)
	return checksum16(b)
}

// DecodeOuterPacket checks the exact LOCAL real destination and receive
// identifier first, then extracts the protocol's authenticated STL frame.
// It does not regard an outer source as identity, authorize a destination,
// or respond to traffic absent successful in-band Noise authentication.
func DecodeOuterPacket(wire []byte, local netip.AddrPort, allowedProfile string) ([]byte, netip.AddrPort, string, error) {
	errInvalid := errors.New("not an STL outer packet for this Link")
	if !local.IsValid() || !local.Addr().Is4() || len(wire) < 20 ||
		wire[0]>>4 != 4 {
		return nil, netip.AddrPort{}, "", errInvalid
	}
	hlen := int(wire[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(wire[2:4]))
	if hlen < 20 || total > len(wire) || total < hlen+frameHeader ||
		!bytes.Equal(wire[16:20], local.Addr().AsSlice()) {
		return nil, netip.AddrPort{}, "", errInvalid
	}
	body := wire[hlen:total]
	profile := ""
	switch wire[9] {
	case 6:
		if len(body) < 20 || int(body[12]>>4)*4 > len(body) ||
			int(body[12]>>4)*4 < 20 || body[13] != 4 ||
			binary.BigEndian.Uint16(body[2:4]) != local.Port() ||
			pseudoChecksum([4]byte{wire[12], wire[13], wire[14], wire[15]}, local.Addr().As4(), 6, body) != 0 {
			return nil, netip.AddrPort{}, "", errInvalid
		}
		body = body[int(body[12]>>4)*4:]
		profile = ProfileTCP
	case 47:
		if len(body) < 4 || binary.BigEndian.Uint16(body[:2]) != 0 ||
			binary.BigEndian.Uint16(body[2:4]) != greExperimentalEtherType {
			return nil, netip.AddrPort{}, "", errInvalid
		}
		body = body[4:]
		profile = ProfileGRE
	case 4:
		// The outer destination was already checked against the local bind.
		// DNAT leaves this experimental nested header addressed to the
		// advertised endpoint, so it need not equal the post-DNAT bind IP.
		// The enclosed STL frame still requires the Link's Noise identity.
		if len(body) < 20 || body[0] != 0x45 || body[9] != ipipInnerExperimentalProtocol ||
			checksum16(body[:20]) != 0 ||
			int(binary.BigEndian.Uint16(body[2:4])) != len(body) {
			return nil, netip.AddrPort{}, "", errInvalid
		}
		body = body[20:]
		profile = ProfileIPIP
	case 58:
		if len(body) >= frameHeader && bytes.Equal(body[:4], frameMagic[:]) {
			profile = ProfileProto58
		} else if len(body) >= 8+frameHeader && body[0] == 129 && body[1] == 0 &&
			binary.BigEndian.Uint16(body[4:6]) == local.Port() && checksum16(body) == 0 &&
			bytes.Equal(body[8:12], frameMagic[:]) {
			body = body[8:]
			profile = ProfileProto58Echo
		}
	case 115:
		if len(body) < 4 || binary.BigEndian.Uint32(body[:4]) != l2tpSessionID(local.Port()) {
			return nil, netip.AddrPort{}, "", errInvalid
		}
		body = body[4:]
		profile = ProfileL2TPv3
	case 1:
		if len(body) < 8 || body[0] != 0 || body[1] != 0 ||
			binary.BigEndian.Uint16(body[4:6]) != local.Port() || checksum16(body) != 0 {
			return nil, netip.AddrPort{}, "", errInvalid
		}
		body = body[8:]
		profile = ProfileICMP
	default:
		return nil, netip.AddrPort{}, "", errInvalid
	}
	if (allowedProfile != ProfileAuto && profile != allowedProfile) || len(body) < frameHeader ||
		!bytes.Equal(body[:4], frameMagic[:]) {
		return nil, netip.AddrPort{}, "", errInvalid
	}
	src, ok := netip.AddrFromSlice(wire[12:16])
	if !ok || !src.Is4() {
		return nil, netip.AddrPort{}, "", errInvalid
	}
	return body, netip.AddrPortFrom(src, local.Port()), profile, nil
}
