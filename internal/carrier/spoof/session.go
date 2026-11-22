package spoof

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

const noiseTagBytes = 16

// replayWindow accepts authenticated datagrams with ordinary UDP reordering
// while rejecting duplicates and packets outside the most recent 64 nonces.
// A candidate is marked only AFTER AEAD successfully authenticates it.
type replayWindow struct {
	newest uint64
	mask   uint64
	active bool
}

func (w *replayWindow) alreadySeen(nonce uint64) bool {
	if !w.active || nonce > w.newest {
		return false
	}
	delta := w.newest - nonce
	return delta >= 64 || w.mask&(uint64(1)<<delta) != 0
}

func (w *replayWindow) mark(nonce uint64) {
	if !w.active {
		w.newest, w.mask, w.active = nonce, 1, true
		return
	}
	if nonce > w.newest {
		delta := nonce - w.newest
		if delta >= 64 {
			w.mask = 1
		} else {
			w.mask = (w.mask << delta) | 1
		}
		w.newest = nonce
		return
	}
	w.mask |= uint64(1) << (w.newest - nonce)
}

// Seal encrypts a private IPv4 datagram or authenticated control message.
// The whole Link/session/kind/sequence envelope is associated data.
// Every session starts with fresh Noise keys, including after reboot.
func (s *Session) Seal(kind FrameKind, plaintext []byte) ([]byte, error) {
	if s == nil || (kind != KindData && kind != KindKeepalive && kind != KindKeepaliveAck) {
		return nil, errors.New("invalid session frame kind")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.send == nil || s.sendSeq >= math.MaxUint64-1 ||
		len(plaintext)+noiseTagBytes > MaxPayload {
		return nil, errors.New("Noise session rehandshake or smaller packet required")
	}
	header, err := (Frame{LinkID: s.linkID, Attempt: s.attempt, Kind: kind,
		Seq: s.sendSeq, Payload: make([]byte, len(plaintext)+noiseTagBytes)}).Encode()
	if err != nil {
		return nil, err
	}
	ad := header[:frameHeader]
	s.send.SetNonce(s.sendSeq)
	encrypted, err := s.send.Encrypt(nil, ad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("Noise transport encrypt: %w", err)
	}
	if len(encrypted) != len(header)-frameHeader {
		return nil, errors.New("Noise transport ciphertext length mismatch")
	}
	copy(header[frameHeader:], encrypted)
	s.sendSeq++
	return header, nil
}

// Open enforces link identity, fresh session ID, AEAD and anti-replay before
// exposing a private IPv4 packet to the TUN. Forged outer source headers are
// never trusted as authentication or used as reply destinations.
func (s *Session) Open(encoded []byte) (FrameKind, []byte, error) {
	if s == nil {
		return 0, nil, errors.New("Noise session absent")
	}
	frame, err := DecodeFrame(encoded)
	if err != nil {
		return 0, nil, err
	}
	if frame.LinkID != s.linkID || frame.Attempt != s.attempt ||
		(frame.Kind != KindData && frame.Kind != KindKeepalive && frame.Kind != KindKeepaliveAck) {
		return 0, nil, errors.New("Noise session envelope mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receive == nil || frame.Seq >= math.MaxUint64-1 ||
		s.replay.alreadySeen(frame.Seq) || len(frame.Payload) < noiseTagBytes {
		return 0, nil, errors.New("stale, duplicate or malformed Noise datagram")
	}
	s.receive.SetNonce(frame.Seq)
	plaintext, err := s.receive.Decrypt(nil, encoded[:frameHeader], frame.Payload)
	if err != nil {
		return 0, nil, errors.New("Noise authenticated frame failed integrity verification")
	}
	// Do not mutate the replay window before successful verification.
	s.replay.mark(frame.Seq)
	return frame.Kind, bytes.Clone(plaintext), nil
}

// VerifiedPeerIdentity exposes only the identity established by the Noise
// transcript. An arbitrary caller cannot manufacture a valid Session using
// public fields alone because its cipher states are package-private.
func (s *Session) VerifiedPeerIdentity() (string, [32]byte, [32]byte, bool) {
	if s == nil || s.send == nil || s.receive == nil ||
		len(s.binding) != 32 || s.linkID.Validate() != nil {
		return "", [32]byte{}, [32]byte{}, false
	}
	return string(s.linkID), s.localPublic, s.peerPublic, ValidPublicKey(s.localPublic[:]) && ValidPublicKey(s.peerPublic[:])
}

// PeerPublicKey returns the authenticated static peer identity, never a
// writable pointer into the session's security boundary.
func (s *Session) PeerPublicKey() [32]byte { return s.peerPublic }

// ChannelBinding returns a copy of the unique authenticated Noise transcript.
func (s *Session) ChannelBinding() []byte { return bytes.Clone(s.binding) }
