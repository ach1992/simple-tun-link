package masque

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestVarintBoundaries(t *testing.T) {
	for _, v := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1} {
		raw, err := appendVarint(nil, v)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := readVarint(raw)
		if err != nil || got != v || n != len(raw) {
			t.Fatalf("value=%d decoded=%d consumed=%d err=%v", v, got, n, err)
		}
		for i := 0; i < len(raw); i++ {
			if _, _, err := readVarint(raw[:i]); !errors.Is(err, errIncompleteVarint) {
				t.Fatalf("prefix length=%d expected incomplete: %v", i, err)
			}
		}
	}
	if _, err := appendVarint(nil, 1<<62); err == nil {
		t.Fatal("accepted 62-bit overflow")
	}
}

func testPacket() []byte {
	v := make([]byte, 52)
	v[0] = 0x45
	binary.BigEndian.PutUint16(v[2:4], uint16(len(v)))
	copy(v[12:16], []byte{10, 251, 95, 2})
	copy(v[16:20], []byte{10, 251, 95, 1})
	for i := 20; i < len(v); i++ {
		v[i] = byte(i)
	}
	return v
}

func TestCapsuleFragmentationAndAddressAssignment(t *testing.T) {
	var addressPayload []byte
	addressPayload, _ = appendVarint(addressPayload, 0)
	addressPayload = append(addressPayload, 4, 10, 251, 95, 2, 32)
	addressPayload, _ = appendVarint(addressPayload, 1)
	addressPayload = append(addressPayload, 6)
	addressPayload = append(addressPayload, netip.MustParseAddr("fdfe:1234:9555::2").AsSlice()...)
	addressPayload = append(addressPayload, 128)
	var wire []byte
	wire, _ = appendVarint(wire, capsuleAddressAssign)
	wire, _ = appendVarint(wire, uint64(len(addressPayload)))
	wire = append(wire, addressPayload...)
	packet := testPacket()
	capsule, err := datagramCapsule(packet)
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, capsule...)
	var addresses []netip.Prefix
	var packets [][]byte
	var stream capsuleStream
	for _, b := range wire {
		if err := stream.feed([]byte{b}, func(p netip.Prefix) error {
			addresses = append(addresses, p)
			return nil
		}, func(p []byte) error {
			packets = append(packets, append([]byte(nil), p...))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(addresses) != 2 || addresses[0].String() != "10.251.95.2/32" ||
		addresses[1].String() != "fdfe:1234:9555::2/128" ||
		len(packets) != 1 || !bytes.Equal(packets[0], packet) || len(stream.pending) != 0 {
		t.Fatalf("addresses=%v packets=%d pending=%d", addresses, len(packets), len(stream.pending))
	}
}

func TestMalformedCapsulesFailClosed(t *testing.T) {
	v := testPacket()
	v[0] = 0x44
	if _, err := datagramCapsule(v); err == nil {
		t.Fatal("accepted invalid IPv4 length")
	}
	oversized, _ := appendVarint(nil, 0)
	oversized, _ = appendVarint(oversized, maxCapsule+1)
	var parser capsuleStream
	if err := parser.feed(oversized, nil, nil); err == nil {
		t.Fatal("accepted oversized capsule")
	}
	parser = capsuleStream{}
	if err := parser.feed([]byte{0, 1, 1}, nil, nil); err == nil {
		t.Fatal("accepted unsupported datagram context")
	}
	parser = capsuleStream{}
	if err := parser.feed([]byte{1, 3, 0, 4, 10}, nil, nil); err == nil {
		t.Fatal("accepted truncated ADDRESS_ASSIGN")
	}
}
