// Package masque implements RFC 9484 CONNECT-IP for the optional STL
// MASQUE carrier. Wire codecs are independent of the Link Engine: they
// cannot mutate routes, interfaces, services, or protected credentials.
package masque

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	capsuleDatagram      = uint64(0)
	capsuleAddressAssign = uint64(1)
	maxIPv4Packet        = 65535
	maxCapsule           = maxIPv4Packet + 32
	maxPendingCapsules   = maxCapsule * 2
)

var errIncompleteVarint = errors.New("incomplete MASQUE QUIC varint")

// The RFC 9297/RFC 9484 capsule format uses QUIC variable-length integers,
// even when the outer transport is HTTP/2 over TCP.
func appendVarint(dst []byte, value uint64) ([]byte, error) {
	switch {
	case value < 1<<6:
		return append(dst, byte(value)), nil
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(dst, uint16(value)|0x4000), nil
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(dst, uint32(value)|0x80000000), nil
	case value < 1<<62:
		return binary.BigEndian.AppendUint64(dst, value|0xc000000000000000), nil
	default:
		return nil, fmt.Errorf("MASQUE variable integer exceeds 62-bit maximum")
	}
}

func readVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errIncompleteVarint
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0, errIncompleteVarint
	}
	switch size {
	case 1:
		return uint64(data[0] & 0x3f), 1, nil
	case 2:
		return uint64(binary.BigEndian.Uint16(data[:2]) & 0x3fff), 2, nil
	case 4:
		return uint64(binary.BigEndian.Uint32(data[:4]) & 0x3fffffff), 4, nil
	case 8:
		return binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff, 8, nil
	}
	panic("unreachable QUIC varint size")
}

func datagramCapsule(ip []byte) ([]byte, error) {
	if len(ip) < 20 || len(ip) > maxIPv4Packet || ip[0]>>4 != 4 {
		return nil, errors.New("MASQUE IPv4 datagram is invalid")
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total != len(ip) || total < int(ip[0]&0x0f)*4 || ip[0]&0x0f < 5 {
		return nil, errors.New("MASQUE IPv4 datagram length is inconsistent")
	}
	out, _ := appendVarint(make([]byte, 0, len(ip)+10), capsuleDatagram)
	out, _ = appendVarint(out, uint64(len(ip)+1)) // Context ID is zero
	return append(append(out, 0), ip...), nil
}

type capsuleStream struct {
	pending []byte
}

func (s *capsuleStream) feed(raw []byte, onAddress func(netip.Prefix) error, onPacket func([]byte) error) error {
	if len(raw) > maxPendingCapsules-len(s.pending) {
		return fmt.Errorf("MASQUE capsule pending buffer capacity exceeded")
	}
	s.pending = append(s.pending, raw...)
	consumed := 0
	for consumed < len(s.pending) {
		item := s.pending[consumed:]
		kind, k, err := readVarint(item)
		if errors.Is(err, errIncompleteVarint) {
			break
		}
		if err != nil {
			return err
		}
		plen, n, err := readVarint(item[k:])
		if errors.Is(err, errIncompleteVarint) {
			break
		}
		if err != nil {
			return err
		}
		if plen > maxCapsule {
			return fmt.Errorf("MASQUE capsule length exceeds IP datagram capacity")
		}
		header := k + n
		if uint64(len(item)-header) < plen {
			break
		}
		payload := item[header : header+int(plen)]
		switch kind {
		case capsuleDatagram:
			contextID, prefixLen, err := readVarint(payload)
			if err != nil {
				return fmt.Errorf("invalid MASQUE datagram context: %w", err)
			}
			if contextID != 0 {
				return fmt.Errorf("unsupported MASQUE datagram context ID")
			}
			if onPacket != nil {
				if err := onPacket(payload[prefixLen:]); err != nil {
					return err
				}
			}
		case capsuleAddressAssign:
			if err := decodeAddressAssign(payload, onAddress); err != nil {
				return err
			}
		}
		consumed += header + int(plen)
	}
	if consumed > 0 {
		copy(s.pending, s.pending[consumed:])
		s.pending = s.pending[:len(s.pending)-consumed]
	}
	return nil
}

// ADDRESS_ASSIGN may carry IPv4 and IPv6 identities in the same capsule.
// Pinned IPv4 recipients are enforced by the caller, not by trusting a first
// assignment or silently choosing a new address after reconnect.
func decodeAddressAssign(raw []byte, visit func(netip.Prefix) error) error {
	for len(raw) != 0 {
		_, size, err := readVarint(raw) // request identifier
		if err != nil {
			return fmt.Errorf("invalid MASQUE ADDRESS_ASSIGN request ID: %w", err)
		}
		raw = raw[size:]
		if len(raw) == 0 {
			return errors.New("truncated MASQUE ADDRESS_ASSIGN address family")
		}
		family := raw[0]
		raw = raw[1:]
		var address netip.Addr
		var bytes int
		switch family {
		case 4:
			bytes = 4
		case 6:
			bytes = 16
		default:
			return errors.New("invalid MASQUE ADDRESS_ASSIGN address family")
		}
		if len(raw) < bytes+1 {
			return errors.New("truncated MASQUE ADDRESS_ASSIGN address")
		}
		if family == 4 {
			var v [4]byte
			copy(v[:], raw[:4])
			address = netip.AddrFrom4(v)
		} else {
			var v [16]byte
			copy(v[:], raw[:16])
			address = netip.AddrFrom16(v)
		}
		prefix := int(raw[bytes])
		raw = raw[bytes+1:]
		if prefix > address.BitLen() {
			return errors.New("invalid MASQUE ADDRESS_ASSIGN prefix length")
		}
		if visit != nil {
			if err := visit(netip.PrefixFrom(address, prefix)); err != nil {
				return err
			}
		}
	}
	return nil
}
