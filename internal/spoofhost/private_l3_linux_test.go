//go:build linux

package spoofhost

import (
	"encoding/binary"
	"testing"
)

func TestPrivateICMPEchoRequiresActualReplyMatchingNonceAndChecksum(t *testing.T) {
	token := []byte("testprivate")
	echo := make([]byte, 8+len(token))
	copy(echo[8:], token)
	binary.BigEndian.PutUint16(echo[4:6], 4200)
	binary.BigEndian.PutUint16(echo[6:8], 3)
	binary.BigEndian.PutUint16(echo[2:4], icmp16Checksum(echo))
	if !privateICMPEchoMatches(echo, 4200, 3, token) {
		t.Fatal("valid ICMP echo reply unrecognized")
	}
	for _, mutated := range []func([]byte){
		func(b []byte) { b[0] = 8 },
		func(b []byte) { b[8] ^= 1 },
		func(b []byte) { b[5] ^= 1 },
		func(b []byte) { b[6] ^= 1 },
		func(b []byte) { b[2] ^= 1 },
	} {
		other := append([]byte(nil), echo...)
		mutated(other)
		if privateICMPEchoMatches(other, 4200, 3, token) {
			t.Fatalf("mutated/non-matching private reply falsely verified: %x", other)
		}
	}
}
