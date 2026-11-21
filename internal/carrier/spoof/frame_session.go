package spoof

// OpenEncoded consumes a decoded, untrusted datagram, preserving the exact
// authenticated header through canonical re-encoding before AEAD verification.
func (s *Session) OpenEncoded(frame Frame) (FrameKind, []byte, error) {
	raw, err := frame.Encode()
	if err != nil {
		return 0, nil, err
	}
	return s.Open(raw)
}
