package spoof

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const (
	// An explicit version and scoped Link ID prevent cross-Link packet
	// confusion. AEAD authenticates the entire frame header as AD for data.
	FrameVersion = 1
	frameHeader  = 48 // magic(4) + version(1) + kind(1) + ID(16) + attempt(16) + seq(8) + length(2)
	MaxPayload   = 65535
)

var frameMagic = [4]byte{'S', 'T', 'L', 'S'}

type FrameKind uint8

const (
	KindHandshake1   FrameKind = 1
	KindHandshake2   FrameKind = 2
	KindHandshake3   FrameKind = 3
	KindData         FrameKind = 4
	KindKeepalive    FrameKind = 5
	KindKeepaliveAck FrameKind = 6
)

// Frame is a length-checked envelope for the one explicitly paired Link.
// A forged IPv4 source never enters peer identity or reply destination here.
type Frame struct {
	LinkID  domain.LinkID
	Attempt [16]byte
	Kind    FrameKind
	Seq     uint64
	Payload []byte
}

func NewAttempt() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}

func validKind(kind FrameKind) bool {
	return kind >= KindHandshake1 && kind <= KindKeepaliveAck
}

func (f Frame) Encode() ([]byte, error) {
	if f.LinkID.Validate() != nil || !validKind(f.Kind) || len(f.Payload) > MaxPayload {
		return nil, errors.New("invalid spoof frame identity, kind or payload length")
	}
	identity, _ := hex.DecodeString(string(f.LinkID)[4:])
	out := make([]byte, frameHeader+len(f.Payload))
	copy(out[0:4], frameMagic[:])
	out[4] = FrameVersion
	out[5] = byte(f.Kind)
	copy(out[6:22], identity)
	copy(out[22:38], f.Attempt[:])
	binary.BigEndian.PutUint64(out[38:46], f.Seq)
	binary.BigEndian.PutUint16(out[46:48], uint16(len(f.Payload)))
	copy(out[48:], f.Payload)
	return out, nil
}

func DecodeFrame(encoded []byte) (Frame, error) {
	if len(encoded) < frameHeader || !bytes.Equal(encoded[0:4], frameMagic[:]) || encoded[4] != FrameVersion ||
		!validKind(FrameKind(encoded[5])) {
		return Frame{}, errors.New("invalid spoof frame magic/version/kind")
	}
	length := int(binary.BigEndian.Uint16(encoded[46:48]))
	if len(encoded) != frameHeader+length {
		return Frame{}, fmt.Errorf("spoof frame length mismatch: header %d vs datagram %d", length, len(encoded)-frameHeader)
	}
	var attempt [16]byte
	copy(attempt[:], encoded[22:38])
	id := domain.LinkID("lnk_" + hex.EncodeToString(encoded[6:22]))
	return Frame{
		LinkID: id, Attempt: attempt, Kind: FrameKind(encoded[5]),
		Seq: binary.BigEndian.Uint64(encoded[38:46]), Payload: append([]byte(nil), encoded[48:]...),
	}, nil
}
