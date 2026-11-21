package spoof

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/flynn/noise"
)

const (
	RoleCreator   Role = "creator"   // A: Noise XKpsk0 responder, static identity in Setup Code
	RoleRecipient Role = "recipient" // B: Noise XKpsk0 initiator, static identity generated on B
)

type Role string

// HandshakeConfig uses the single-transfer BootstrapSecret and the creator's
// pinned public key. Nothing here assumes the underlay uses an ordinary source
// IP or that either side has a pre-existing control connection.
type HandshakeConfig struct {
	Role               Role
	LinkID             domain.LinkID
	Attempt            [16]byte
	CreatorEndpoint    netip.AddrPort
	RecipientEndpoint  netip.AddrPort
	CreatorPrivateIP   netip.Addr
	RecipientPrivateIP netip.Addr
	LocalPrivateKey    [32]byte
	PeerPublicKey      []byte // required for recipient; optional bound peer on creator
	BootstrapSecret    [32]byte
}

type Handshake struct {
	state        *noise.HandshakeState
	role         Role
	config       HandshakeConfig
	stage        int
	expectedPeer []byte
}

type Session struct {
	linkID      domain.LinkID
	attempt     [16]byte
	localPublic [32]byte
	peerPublic  [32]byte
	binding     []byte // hash of the authenticated Noise transcript
	send        *noise.CipherState
	receive     *noise.CipherState
	sendSeq     uint64
	replay      replayWindow
	mu          sync.Mutex
}

// GenerateIdentity creates a local-only long-lived X25519 identity. A's
// private key must never travel in the Setup Code; B generates its own key.
func GenerateIdentity() (private [32]byte, public [32]byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return private, public, err
	}
	copy(private[:], key.Bytes())
	copy(public[:], key.PublicKey().Bytes())
	return private, public, nil
}

func publicFromPrivate(secret [32]byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

func ValidPublicKey(value []byte) bool {
	if len(value) != 32 {
		return false
	}
	// An all-zero X25519 point never authenticates a peer.
	var empty [32]byte
	return !bytes.Equal(value, empty[:])
}

func (c HandshakeConfig) validate() error {
	if c.Role != RoleCreator && c.Role != RoleRecipient {
		return errors.New("invalid Noise endpoint role")
	}
	if err := c.LinkID.Validate(); err != nil {
		return err
	}
	for _, endpoint := range []netip.AddrPort{c.CreatorEndpoint, c.RecipientEndpoint} {
		if !endpoint.IsValid() || !endpoint.Addr().Is4() ||
			endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Port() == 0 {
			return errors.New("Noise transcript requires the two real reachable IPv4 endpoints and ports")
		}
	}
	if c.CreatorEndpoint == c.RecipientEndpoint {
		return errors.New("Noise endpoints must be distinct")
	}
	for _, private := range []netip.Addr{c.CreatorPrivateIP, c.RecipientPrivateIP} {
		if !private.Is4() || private.IsUnspecified() || private.IsMulticast() || private.IsLoopback() {
			return errors.New("Noise transcript requires both valid private IPv4 Link addresses")
		}
	}
	if c.CreatorPrivateIP == c.RecipientPrivateIP {
		return errors.New("Noise private Link addresses must be distinct")
	}
	if c.Attempt == ([16]byte{}) || c.BootstrapSecret == ([32]byte{}) || c.LocalPrivateKey == ([32]byte{}) {
		return errors.New("Noise attempt, bootstrap and local identity must be random nonzero secrets")
	}
	if c.Role == RoleRecipient && !ValidPublicKey(c.PeerPublicKey) {
		return errors.New("recipient requires creator's authentic public key from the Setup Code")
	}
	if c.Role == RoleCreator && len(c.PeerPublicKey) != 0 && !ValidPublicKey(c.PeerPublicKey) {
		return errors.New("bound creator peer identity must be a canonical X25519 public key")
	}
	return nil
}

func (c HandshakeConfig) prologue() []byte {
	// Link identity, agreed physical endpoints, private topology and attempt
	// are unambiguous, role-invariant Noise protocol transcript context.
	return []byte(fmt.Sprintf("STL-SPOOF-XKpsk0-v1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%x",
		c.LinkID, c.CreatorEndpoint, c.RecipientEndpoint,
		c.CreatorPrivateIP, c.RecipientPrivateIP, c.Attempt))
}

// NewHandshake instantiates Noise_XKpsk0_25519_ChaChaPoly_SHA256 (Noise
// Protocol Framework) rather than a novel key-exchange scheme. The creator
// pins B's public identity only after the authenticated final message.
func NewHandshake(c HandshakeConfig) (*Handshake, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	pub, err := publicFromPrivate(c.LocalPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid local Noise identity: %w", err)
	}
	c.PeerPublicKey = append([]byte(nil), c.PeerPublicKey...)
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXK, PresharedKeyPlacement: 0,
		PresharedKey:  c.BootstrapSecret[:],
		Prologue:      c.prologue(),
		Initiator:     c.Role == RoleRecipient,
		StaticKeypair: noise.DHKey{Private: append([]byte(nil), c.LocalPrivateKey[:]...), Public: pub},
		PeerStatic: func() []byte {
			if c.Role == RoleRecipient {
				return c.PeerPublicKey
			}
			return nil
		}(),
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Noise XKpsk0: %w", err)
	}
	return &Handshake{state: state, role: c.Role, config: c,
		expectedPeer: append([]byte(nil), c.PeerPublicKey...)}, nil
}

// Start sends the first Noise message only from the Setup Code recipient.
// The creator already knows B's real destination but must not try an
// unauthenticated XK initiation pretending to know B's static identity.
func (h *Handshake) Start() ([]byte, error) {
	if h == nil || h.role != RoleRecipient || h.stage != 0 {
		return nil, errors.New("only a fresh recipient initiates Noise XKpsk0")
	}
	msg, _, _, err := h.state.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	h.stage = 1
	return msg, nil
}

// Handle processes exactly the next Noise frame. The returned Session is
// cryptographically authenticated, NOT proof that private L3 traffic works.
// Runtime must verify bilateral authenticated path and TUN data separately.
func (h *Handshake) Handle(msg []byte) (reply []byte, connected *Session, err error) {
	if h == nil || len(msg) == 0 {
		return nil, nil, errors.New("Noise handshake message missing")
	}
	switch h.role {
	case RoleCreator:
		switch h.stage {
		case 0:
			if _, _, _, err := h.state.ReadMessage(nil, msg); err != nil {
				return nil, nil, err
			}
			next, _, _, err := h.state.WriteMessage(nil, nil)
			if err != nil {
				return nil, nil, err
			}
			h.stage = 2
			return next, nil, nil
		case 2:
			_, send, receive, err := h.state.ReadMessage(nil, msg)
			if err != nil {
				return nil, nil, err
			}
			peer := h.state.PeerStatic()
			if !ValidPublicKey(peer) ||
				(len(h.expectedPeer) != 0 && !bytes.Equal(peer, h.expectedPeer)) {
				return nil, nil, errors.New("Noise peer identity differs from already-bound creator peer")
			}
			h.stage = 3
			// Noise Split returns initiator-to-responder then responder-to-initiator.
			// The creator is the responder; its directions must be reversed.
			return nil, newSession(h, peer, receive, send), nil
		}
	case RoleRecipient:
		if h.stage == 1 {
			if _, _, _, err := h.state.ReadMessage(nil, msg); err != nil {
				return nil, nil, err
			}
			next, send, receive, err := h.state.WriteMessage(nil, nil)
			if err != nil {
				return nil, nil, err
			}
			h.stage = 3
			return next, newSession(h, h.expectedPeer, send, receive), nil
		}
	}
	return nil, nil, errors.New("unexpected or duplicate Noise handshake transition")
}

func newSession(h *Handshake, peer []byte, send, receive *noise.CipherState) *Session {
	var pinned [32]byte
	copy(pinned[:], peer)
	local, _ := publicFromPrivate(h.config.LocalPrivateKey)
	var localPublic [32]byte
	copy(localPublic[:], local)
	return &Session{
		linkID: h.config.LinkID, attempt: h.config.Attempt,
		localPublic: localPublic, peerPublic: pinned, binding: append([]byte(nil), h.state.ChannelBinding()...),
		send: send, receive: receive,
	}
}
