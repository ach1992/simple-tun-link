package pairing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const (
	SpoofSetupVersion = 1
	spoofCodePrefix   = "stl-spoof-v1."
	maxSpoofCodeSize  = 4096
)

// SpoofSetup is the ONE confidential A->B manual handoff. Its unexported
// secrets never enter ordinary JSON/diagnostics via generic marshaling. The
// recipient generates its private X25519 identity locally; the creator's
// private identity is never placed in the Setup Code.
type SpoofSetup struct {
	id            domain.LinkID
	creator       netip.AddrPort
	recipient     netip.AddrPort
	creatorIP     netip.Addr
	recipientIP   netip.Addr
	creatorPublic [32]byte
	secret        [32]byte
	outer         string // empty = original UDP profile; ICMP is explicit
}

func (s SpoofSetup) String() string {
	return fmt.Sprintf("SpoofSetup<secret redacted LinkID=%s>", s.id)
}
func (s SpoofSetup) GoString() string { return s.String() }

func (s SpoofSetup) LinkID() domain.LinkID             { return s.id }
func (s SpoofSetup) CreatorEndpoint() netip.AddrPort   { return s.creator }
func (s SpoofSetup) RecipientEndpoint() netip.AddrPort { return s.recipient }
func (s SpoofSetup) CreatorPrivateIPv4() netip.Addr    { return s.creatorIP }
func (s SpoofSetup) RecipientPrivateIPv4() netip.Addr  { return s.recipientIP }
func (s SpoofSetup) CreatorPublicKey() [32]byte        { return s.creatorPublic }

// Secret returns a copy for the protected local material writer, not for
// logging, generic status, desired State or CLI machine output.
func (s SpoofSetup) Secret() [32]byte { return s.secret }
func (s SpoofSetup) OuterProtocol() string {
	if s.outer == "icmp" {
		return "icmp"
	}
	return "udp"
}

// WithOuterProtocol chooses one immutable outer packet format in the single
// offline Setup Code. No control-channel negotiation or carrier hopping.
func (s SpoofSetup) WithOuterProtocol(profile string) (SpoofSetup, error) {
	if profile == "udp" {
		profile = ""
	}
	s.outer = profile
	return s, s.Validate()
}

func (s SpoofSetup) Validate() error {
	if err := s.id.Validate(); err != nil {
		return err
	}
	if s.outer != "" && s.outer != "icmp" {
		return errors.New("Spoof Setup Code outer profile must be udp or icmp")
	}

	for _, endpoint := range []netip.AddrPort{s.creator, s.recipient} {
		if !endpoint.IsValid() || !endpoint.Addr().Is4() ||
			endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Port() == 0 {
			return errors.New("spoof setup requires exact reachable IPv4 endpoint and receive port on each side")
		}
	}
	if s.creator == s.recipient {
		return errors.New("spoof creator and recipient real endpoints must differ")
	}
	for _, ip := range []netip.Addr{s.creatorIP, s.recipientIP} {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
			return errors.New("spoof setup requires valid private IPv4 Link addresses")
		}
	}
	if s.creatorIP == s.recipientIP || s.creatorIP == s.creator.Addr() || s.recipientIP == s.recipient.Addr() ||
		s.creatorIP == s.recipient.Addr() || s.recipientIP == s.creator.Addr() {
		return errors.New("private Spoof Link addresses must be distinct from each other and underlay real endpoints")
	}
	if s.creatorPublic == ([32]byte{}) || s.secret == ([32]byte{}) {
		return errors.New("spoof setup requires nonzero creator identity and bootstrap secret")
	}
	return nil
}

func NewSpoofSetup(
	id domain.LinkID, creator, recipient netip.AddrPort,
	creatorIP, recipientIP netip.Addr, creatorPublic [32]byte,
) (SpoofSetup, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return SpoofSetup{}, err
	}
	s := SpoofSetup{
		id: id, creator: creator, recipient: recipient, creatorIP: creatorIP,
		recipientIP: recipientIP, creatorPublic: creatorPublic, secret: secret,
	}
	if err := s.Validate(); err != nil {
		return SpoofSetup{}, err
	}
	return s, nil
}

type spoofCodeV1 struct {
	Version       int           `json:"schema_version"`
	ID            domain.LinkID `json:"link_id"`
	Creator       string        `json:"creator_endpoint"`
	Recipient     string        `json:"recipient_endpoint"`
	CreatorIP     string        `json:"creator_private_ip"`
	RecipientIP   string        `json:"recipient_private_ip"`
	CreatorPublic string        `json:"creator_public_key"`
	Secret        string        `json:"bootstrap_secret"`
	OuterProtocol string        `json:"outer_protocol,omitempty"`
}

// EncodeSensitive is the *only* explicit secret-bearing serialization and
// must go only to a protected output/clipboard under operator consent.
func (s SpoofSetup) EncodeSensitive() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(spoofCodeV1{
		Version: SpoofSetupVersion, ID: s.id,
		Creator: s.creator.String(), Recipient: s.recipient.String(),
		CreatorIP: s.creatorIP.String(), RecipientIP: s.recipientIP.String(),
		CreatorPublic: base64.RawURLEncoding.EncodeToString(s.creatorPublic[:]),
		Secret:        base64.RawURLEncoding.EncodeToString(s.secret[:]),
		OuterProtocol: s.outer,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return spoofCodePrefix + base64.RawURLEncoding.EncodeToString(raw) + "." + hex.EncodeToString(sum[:8]), nil
}

func DecodeSensitiveSpoofSetup(code string) (SpoofSetup, error) {
	code = strings.TrimSpace(code)
	if len(code) > maxSpoofCodeSize || !strings.HasPrefix(code, spoofCodePrefix) {
		return SpoofSetup{}, errors.New("invalid or oversized confidential Spoof Setup Code")
	}
	body, check, ok := strings.Cut(strings.TrimPrefix(code, spoofCodePrefix), ".")
	if !ok || strings.Contains(check, ".") || len(check) != 16 {
		return SpoofSetup{}, errors.New("invalid Spoof Setup Code checksum")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(raw) == 0 || len(raw) > maxSpoofCodeSize {
		return SpoofSetup{}, errors.New("invalid Spoof Setup Code encoding")
	}
	want, err := hex.DecodeString(check)
	sum := sha256.Sum256(raw)
	if err != nil || subtle.ConstantTimeCompare(want, sum[:8]) != 1 {
		return SpoofSetup{}, errors.New("Spoof Setup Code checksum mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value spoofCodeV1
	if err := decoder.Decode(&value); err != nil || value.Version != SpoofSetupVersion {
		return SpoofSetup{}, errors.New("invalid Spoof Setup Code schema")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return SpoofSetup{}, errors.New("trailing Spoof Setup Code data")
	}
	creator, err := netip.ParseAddrPort(value.Creator)
	if err != nil {
		return SpoofSetup{}, errors.New("invalid creator endpoint in Spoof Setup Code")
	}
	recipient, err := netip.ParseAddrPort(value.Recipient)
	if err != nil {
		return SpoofSetup{}, errors.New("invalid recipient endpoint in Spoof Setup Code")
	}
	a, err := netip.ParseAddr(value.CreatorIP)
	if err != nil {
		return SpoofSetup{}, errors.New("invalid creator private IP in Spoof Setup Code")
	}
	b, err := netip.ParseAddr(value.RecipientIP)
	if err != nil {
		return SpoofSetup{}, errors.New("invalid recipient private IP in Spoof Setup Code")
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(value.CreatorPublic)
	if err != nil || len(pub) != 32 {
		return SpoofSetup{}, errors.New("invalid creator identity in Spoof Setup Code")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(value.Secret)
	if err != nil || len(secret) != 32 {
		return SpoofSetup{}, errors.New("invalid bootstrap secret in Spoof Setup Code")
	}
	s := SpoofSetup{id: value.ID, creator: creator, recipient: recipient, creatorIP: a, recipientIP: b, outer: value.OuterProtocol}
	copy(s.creatorPublic[:], pub)
	copy(s.secret[:], secret)
	if err := s.Validate(); err != nil {
		return SpoofSetup{}, err
	}
	// All encoded fields are canonical: reject duplicate keys, ambiguous JSON
	// or semantically equivalent alternative spellings.
	reencoded, err := s.EncodeSensitive()
	if err != nil || reencoded != code {
		return SpoofSetup{}, errors.New("noncanonical or ambiguous Spoof Setup Code")
	}
	return s, nil
}
