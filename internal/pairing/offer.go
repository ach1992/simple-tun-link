// Package pairing owns the backend-neutral, versioned setup-link contract.
//
// Setup links are data, never commands. The in-memory Offer intentionally
// keeps recipient credentials private from ordinary JSON, formatting and
// previews. Only the explicitly named export and recipient-credential methods
// may expose secret-bearing data.
package pairing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const (
	SchemaVersion       = 2
	legacySchemaVersion = 1

	// MaxPayloadBytes bounds both untrusted decoded JSON and deliberate export.
	MaxPayloadBytes = 16 * 1024
	// MaxLinkBytes bounds the encoded setup URL including its checksum.
	MaxLinkBytes = 24 * 1024
	maxPSKBytes  = 4096
)

type ExchangeMode string

const ModeQuick ExchangeMode = "quick"

// CredentialKind describes only recipient-directed secret transport.
// Backends #4–#7 own generation, configuration and protected persistence.
type CredentialKind string

const (
	CredentialNone                CredentialKind = ""
	CredentialWireGuardPrivateKey CredentialKind = "wireguard_private_key"
	CredentialIPsecPSK            CredentialKind = "ipsec_psk"
)

// Offer contains the creator-oriented Link and optionally a recipient-only
// credential. Its fields are intentionally not exported: generic JSON
// marshaling or struct formatting must not serialize credentials.
type Offer struct {
	link            domain.Link
	mode            ExchangeMode
	schemaVersion   int
	recipientSecret []byte
}

// NewQuickOffer validates an independent backend-neutral Link and the
// recipient credential for a one-step Quick Link. For plaintext GRE/IPIP,
// credential must be nil. WireGuard expects its 32-byte private key in
// canonical standard base64 text; IPsec expects a nonempty high-entropy PSK.
// The caller must not persist a generated recipient private key on the sender.
func NewQuickOffer(link domain.Link, credential []byte) (Offer, error) {
	offer := Offer{
		link:            link,
		mode:            ModeQuick,
		schemaVersion:   SchemaVersion,
		recipientSecret: append([]byte(nil), credential...),
	}
	if err := offer.validate(); err != nil {
		return Offer{}, stlerr.Wrap(stlerr.CodeInvalid, "pairing_create", "", "", "invalid pairing data", err)
	}
	return offer, nil
}

func (o Offer) validate() error {
	version := o.effectiveSchemaVersion()
	if version != legacySchemaVersion && version != SchemaVersion {
		return fmt.Errorf("unsupported pairing schema version")
	}
	if version == legacySchemaVersion && o.link.GRE != (domain.GREOptions{}) {
		return fmt.Errorf("pairing schema v1 cannot carry GRE backend options")
	}
	if o.mode != ModeQuick {
		return fmt.Errorf("unsupported pairing exchange mode")
	}
	if err := o.link.Validate(); err != nil {
		return err
	}
	if !utf8.ValidString(o.link.DisplayName) || utf8.RuneCountInString(o.link.DisplayName) > 64 {
		return fmt.Errorf("invalid Link display-name length or UTF-8 encoding")
	}
	for _, r := range o.link.DisplayName {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("Link display name contains control or formatting characters")
		}
	}
	// Strict backend/encapsulation compatibility is intentionally centralized
	// here rather than delegated to the future CLI or individual backends.
	switch o.link.Backend {
	case domain.BackendGRE, domain.BackendIPIP:
		if o.link.Encapsulation != domain.EncapNative && o.link.Encapsulation != domain.EncapFOU && o.link.Encapsulation != domain.EncapGUE {
			return fmt.Errorf("unsupported GRE/IPIP encapsulation")
		}
		if len(o.recipientSecret) != 0 {
			return fmt.Errorf("plaintext backend cannot accept recipient credentials")
		}
	case domain.BackendWireGuard:
		if o.link.Encapsulation != domain.EncapUDP {
			return fmt.Errorf("unsupported WireGuard encapsulation")
		}
		if len(o.recipientSecret) != 44 {
			return fmt.Errorf("WireGuard Quick Link requires a canonical encoded recipient private key")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(string(o.recipientSecret))
		if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != string(o.recipientSecret) {
			return fmt.Errorf("invalid WireGuard recipient private key encoding")
		}
	case domain.BackendIPsec:
		if o.link.Encapsulation != domain.EncapESP && o.link.Encapsulation != domain.EncapNATT {
			return fmt.Errorf("unsupported IPsec encapsulation")
		}
		// Credential entropy is the backend's responsibility. Avoid exporting
		// trivial PSKs through the default one-step pairing workflow.
		if len(o.recipientSecret) < 16 || len(o.recipientSecret) > maxPSKBytes {
			return fmt.Errorf("IPsec Quick Link requires a bounded recipient PSK")
		}
	default:
		return fmt.Errorf("unsupported pairing backend")
	}
	if !o.link.Underlay.Local.IsValid() || !o.link.Underlay.Peer.IsValid() {
		return fmt.Errorf("invalid underlay address")
	}
	// IPv6 zone identifiers are local interface names, not portable peer
	// addresses. Reject them before exporting untrusted address text in a
	// human-readable block, including otherwise ordinary zones such as eth0.
	if o.link.Underlay.Local.Zone() != "" || o.link.Underlay.Peer.Zone() != "" {
		return fmt.Errorf("IPv6 underlay zones are unsupported in pairing links")
	}
	if !o.link.Underlay.Local.Is4() && !o.link.Underlay.Local.Is6() {
		return fmt.Errorf("invalid local underlay family")
	}
	if o.link.Underlay.Local.Is4() != o.link.Underlay.Peer.Is4() {
		return fmt.Errorf("underlay endpoints must have matching address families")
	}
	if err := validateLinkPrefixes(o.link.Addresses); err != nil {
		return err
	}
	return nil
}

func validateLinkPrefixes(a domain.LinkAddresses) error {
	for _, prefix := range []netip.Prefix{a.Local, a.Peer} {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 {
			return fmt.Errorf("invalid IPv4 Link Address prefix")
		}
	}
	if a.Local.Bits() != a.Peer.Bits() {
		return fmt.Errorf("Link Address prefix lengths must agree on both peers")
	}
	return nil
}

func (o Offer) effectiveSchemaVersion() int {
	if o.schemaVersion == 0 {
		return SchemaVersion
	}
	return o.schemaVersion
}

func (o Offer) Link() domain.Link  { return o.link }
func (o Offer) Mode() ExchangeMode { return o.mode }
func (o Offer) IsSensitive() bool  { return len(o.recipientSecret) != 0 }

// RecipientCredential returns a defensive copy of the recipient's credential.
// This is a deliberate secret-access API for the future backend-specific
// import/secure-storage adapter, NOT an observability or JSON accessor.
func (o Offer) RecipientCredential() []byte {
	return append([]byte(nil), o.recipientSecret...)
}

func (o Offer) CredentialKind() CredentialKind {
	switch o.link.Backend {
	case domain.BackendWireGuard:
		return CredentialWireGuardPrivateKey
	case domain.BackendIPsec:
		return CredentialIPsecPSK
	default:
		return CredentialNone
	}
}

// ReceiverLink performs the only peer-side inversion of the backend-neutral
// Link. The stable Link ID/backend/encapsulation remain unchanged.
func (o Offer) ReceiverLink() domain.Link {
	return Invert(o.link)
}

func Invert(link domain.Link) domain.Link {
	inverted := link
	inverted.Underlay.Local, inverted.Underlay.Peer = link.Underlay.Peer, link.Underlay.Local
	inverted.Addresses.Local, inverted.Addresses.Peer = link.Addresses.Peer, link.Addresses.Local
	return inverted
}

// Preview is a redacted, versioned, recipient-oriented import preview.
// Its JSON representation never contains secret values or setup URLs.
type Preview struct {
	SchemaVersion int            `json:"schema_version"`
	Mode          ExchangeMode   `json:"mode"`
	Link          domain.Link    `json:"link"`
	HasCredential bool           `json:"has_credential"`
	Credential    CredentialKind `json:"credential_kind,omitempty"`
	Sensitive     bool           `json:"sensitive"`
}

func (o Offer) Preview() Preview {
	return Preview{
		SchemaVersion: o.effectiveSchemaVersion(),
		Mode:          o.mode,
		Link:          o.ReceiverLink(),
		HasCredential: o.IsSensitive(),
		Credential:    o.CredentialKind(),
		Sensitive:     o.IsSensitive(),
	}
}

// String/GoString are intentionally redacted even for fmt.Printf("%+v"/"%#v").
func (o Offer) String() string {
	if o.IsSensitive() {
		return fmt.Sprintf("STL pairing offer [SENSITIVE, backend=%s, recipient credential redacted]", o.link.Backend)
	}
	return fmt.Sprintf("STL pairing offer [backend=%s, no recipient credential]", o.link.Backend)
}

func (o Offer) GoString() string { return o.String() }

// MarshalJSON deliberately emits only a redacted preview. The secret-bearing
// on-wire format is produced exclusively by EncodeSetupLink.
func (o Offer) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.Preview())
}

// HumanReadableBlock intentionally exposes a credential-bearing setup link
// when the caller deliberately asks for a copy/export artifact. It is never
// used for preview, logging, status or generic JSON; the entire returned
// string must be treated as SENSITIVE when IsSensitive() is true.
func (o Offer) HumanReadableBlock() (string, error) {
	setup, err := o.EncodeSetupLink()
	if err != nil {
		return "", err
	}
	recipient := o.ReceiverLink()
	var b strings.Builder
	if o.IsSensitive() {
		b.WriteString("SENSITIVE — STL SETUP / CREDENTIAL MATERIAL\n")
		b.WriteString("Do not share publicly or store in ordinary logs/history.\n")
	} else {
		b.WriteString("STL SETUP — no included recipient credential\n")
	}
	fmt.Fprintf(&b, "Version: %d\nExchange mode: %s\nLink ID: %s\nBackend: %s\nEncapsulation: %s\n",
		o.effectiveSchemaVersion(), o.mode, recipient.ID, recipient.Backend, recipient.Encapsulation)
	fmt.Fprintf(&b, "Receiver underlay: %s\nPeer underlay: %s\nReceiver Link Address: %s\nPeer Link Address: %s\n",
		recipient.Underlay.Local, recipient.Underlay.Peer, recipient.Addresses.Local, recipient.Addresses.Peer)
	if o.IsSensitive() {
		fmt.Fprintf(&b, "Recipient credential: %s (present; protected within SENSITIVE setup link)\n", o.CredentialKind())
	}
	b.WriteString("Setup link: ")
	b.WriteString(setup)
	b.WriteString("\n")
	return b.String(), nil
}
