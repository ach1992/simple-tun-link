package pairing

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const setupPrefix = "stl://1."

// wireOffer is the only intentionally credential-bearing JSON structure.
// Never expose it from generic status, preview, String or ordinary MarshalJSON.
type wireOffer struct {
	SchemaVersion int          `json:"schema_version"`
	Mode          ExchangeMode `json:"mode"`
	Link          domain.Link  `json:"link"`
	Recipient     *wireSecret  `json:"recipient_secret,omitempty"`
}

type wireSecret struct {
	Kind CredentialKind `json:"kind"`
	Data string         `json:"data"`
}

// EncodeSetupLink returns a deliberately exportable payload. It is
// SENSITIVE when Offer.IsSensitive is true; Base64 and SHA-256 are not
// encryption, authentication, or a confidentiality guarantee.
//
// Wire shape:
//
//	stl://1.<unpadded base64url canonical JSON>.<lowercase sha256 of JSON>
func (o Offer) EncodeSetupLink() (string, error) {
	if err := o.validate(); err != nil {
		return "", stlerr.Wrap(stlerr.CodeInvalid, "pairing_export", "", "", "invalid pairing data", err)
	}
	wire := wireOffer{SchemaVersion: SchemaVersion, Mode: o.mode, Link: o.link}
	if o.IsSensitive() {
		wire.Recipient = &wireSecret{
			Kind: o.CredentialKind(),
			Data: base64.RawURLEncoding.EncodeToString(o.recipientSecret),
		}
	}
	jsonData, err := json.Marshal(wire)
	if err != nil {
		return "", stlerr.Wrap(stlerr.CodeInvalid, "pairing_export", "", "", "cannot encode pairing data", err)
	}
	if len(jsonData) > MaxPayloadBytes {
		return "", stlerr.New(stlerr.CodeInvalid, "pairing_export", "", "", "pairing payload exceeds size limit")
	}
	sum := sha256.Sum256(jsonData)
	link := setupPrefix + base64.RawURLEncoding.EncodeToString(jsonData) + "." + hex.EncodeToString(sum[:])
	if len(link) > MaxLinkBytes {
		return "", stlerr.New(stlerr.CodeInvalid, "pairing_export", "", "", "setup link exceeds size limit")
	}
	return link, nil
}

// DecodeSetupLink validates the untrusted wire envelope but DOES NOT apply
// a Link or write any secret to local state. Importers must call Preview()
// before a separate explicit operator-approved apply action. Use ReceiverLink
// for the receiving endpoint, not the sender-oriented Offer.Link().
func DecodeSetupLink(input string) (Offer, error) {
	invalid := func(detail string, cause error) (Offer, error) {
		return Offer{}, stlerr.Wrap(stlerr.CodeInvalid, "pairing_decode", "", "", detail, cause)
	}
	if len(input) > MaxLinkBytes {
		return invalid("setup link exceeds size limit", nil)
	}
	if !strings.HasPrefix(input, setupPrefix) {
		return invalid("invalid or unsupported setup-link scheme/version", nil)
	}
	body := input[len(setupPrefix):]
	dot := strings.IndexByte(body, '.')
	if dot <= 0 || dot == len(body)-1 || strings.IndexByte(body[dot+1:], '.') >= 0 {
		return invalid("invalid setup-link envelope", nil)
	}
	encoded, hexSum := body[:dot], body[dot+1:]
	if len(hexSum) != 64 || len(encoded) > base64.RawURLEncoding.EncodedLen(MaxPayloadBytes) {
		return invalid("invalid setup-link integrity or payload size", nil)
	}
	if strings.ToLower(hexSum) != hexSum {
		return invalid("setup-link checksum is not canonical", nil)
	}
	checksum, err := hex.DecodeString(hexSum)
	if err != nil {
		return invalid("invalid setup-link checksum", err)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > MaxPayloadBytes || len(raw) == 0 {
		return invalid("invalid or oversized setup-link data encoding", err)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return invalid("noncanonical setup-link data encoding", nil)
	}
	// encoding/json tolerates invalid UTF-8 by substituting replacement
	// characters. Strict pairing refuses that silent semantic mutation.
	if !utf8.Valid(raw) {
		return invalid("invalid UTF-8 in setup-link data", nil)
	}
	got := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(got[:], checksum) != 1 {
		return invalid("setup-link integrity check failed", nil)
	}
	// Explicit field-shape and duplicate-key rejection prevents a malformed
	// JSON object from being interpreted differently by distinct consumers.
	if err := validateWireJSONShape(raw); err != nil {
		return invalid("invalid or ambiguous setup-link fields", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var wire wireOffer
	if err := dec.Decode(&wire); err != nil {
		return invalid("invalid setup-link fields", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return invalid("setup-link contains additional JSON values", err)
	}
	if wire.SchemaVersion != SchemaVersion {
		return Offer{}, stlerr.New(stlerr.CodeUnsupported, "pairing_decode", "", "", "unsupported pairing schema version")
	}
	if wire.Mode != ModeQuick {
		return Offer{}, stlerr.New(stlerr.CodeUnsupported, "pairing_decode", "", "", "unsupported pairing exchange mode")
	}
	var credential []byte
	if wire.Recipient != nil {
		if wire.Recipient.Kind == CredentialNone {
			return invalid("recipient credential kind is required", nil)
		}
		if wire.Recipient.Kind != CredentialWireGuardPrivateKey && wire.Recipient.Kind != CredentialIPsecPSK {
			return invalid("unknown recipient credential kind", nil)
		}
		credential, err = base64.RawURLEncoding.Strict().DecodeString(wire.Recipient.Data)
		if err != nil || base64.RawURLEncoding.EncodeToString(credential) != wire.Recipient.Data {
			return invalid("invalid recipient credential encoding", err)
		}
		switch wire.Link.Backend {
		case domain.BackendWireGuard:
			if wire.Recipient.Kind != CredentialWireGuardPrivateKey {
				return invalid("recipient credential/backend mismatch", nil)
			}
		case domain.BackendIPsec:
			if wire.Recipient.Kind != CredentialIPsecPSK {
				return invalid("recipient credential/backend mismatch", nil)
			}
		default:
			return invalid("plaintext backend cannot carry a recipient credential", nil)
		}
	}
	offer, err := NewQuickOffer(wire.Link, credential)
	if err != nil {
		return invalid("invalid backend, addresses or recipient credential", err)
	}
	return offer, nil
}

// PreviewSetupLink is the safe read-only entrypoint for an import-preview UI.
// It never returns a credential-bearing Offer to callers that only need to
// display receiver-facing, redacted configuration before explicit apply.
func PreviewSetupLink(input string) (Preview, error) {
	offer, err := DecodeSetupLink(input)
	if err != nil {
		return Preview{}, err
	}
	return offer.Preview(), nil
}

// validateWireJSONShape rejects duplicate keys, unexpected nested objects,
// arrays, null, case-variant key spellings and unknown fields before Go's
// permissive struct mapping can resolve a conflicting field.
func validateWireJSONShape(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := validateWireValue(dec, "root", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

var wireAllowedFields = map[string]map[string]string{
	"root": {
		"schema_version":   "number",
		"mode":             "string",
		"link":             "link",
		"recipient_secret": "credential",
	},
	"link": {
		"id":            "string",
		"display_name":  "string",
		"underlay":      "underlay",
		"addresses":     "addresses",
		"backend":       "string",
		"encapsulation": "string",
	},
	"underlay": {
		"local": "string",
		"peer":  "string",
	},
	"addresses": {
		"local": "string",
		"peer":  "string",
	},
	"credential": {
		"kind": "string",
		"data": "string",
	},
}

func validateWireValue(dec *json.Decoder, expected string, depth int) error {
	if depth > 8 {
		return fmt.Errorf("excessive JSON nesting")
	}
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("cannot inspect JSON value: %w", err)
	}
	if allowed, ok := wireAllowedFields[expected]; ok {
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
			return fmt.Errorf("expected JSON object")
		}
		seen := make(map[string]struct{}, len(allowed))
		for dec.More() {
			nameValue, err := dec.Token()
			if err != nil {
				return fmt.Errorf("cannot inspect JSON field name: %w", err)
			}
			name, ok := nameValue.(string)
			if !ok {
				return fmt.Errorf("invalid JSON field name")
			}
			fieldType, ok := allowed[name]
			if !ok {
				return fmt.Errorf("unknown JSON field")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON field")
			}
			seen[name] = struct{}{}
			if err := validateWireValue(dec, fieldType, depth+1); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("unclosed JSON object")
		}
		return nil
	}
	if expected == "string" {
		if _, ok := token.(string); !ok {
			return fmt.Errorf("expected JSON string")
		}
		return nil
	}
	if expected == "number" {
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("expected JSON number")
		}
		return nil
	}
	return fmt.Errorf("unsupported JSON schema field")
}
