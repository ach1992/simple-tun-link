package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	keyBytes       = 32
	wireKeyTextLen = 44
)

// PrivateKey is sensitive X25519 material. Generic formatting and JSON
// serialization do not reveal the bytes.
type PrivateKey struct{ material [keyBytes]byte }

func GenerateKeyPair() (PrivateKey, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, "", fmt.Errorf("generate WireGuard key material: %w", err)
	}
	var private PrivateKey
	copy(private.material[:], key.Bytes())
	// Match the canonical clamped scalar emitted by wg genkey, rather
	// than exporting the raw randomness used by crypto/ecdh.GenerateKey.
	private.material[0] &= 248
	private.material[31] &= 127
	private.material[31] |= 64
	return private, base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func DecodePrivateKey(encoded string) (PrivateKey, error) {
	if len(encoded) != wireKeyTextLen {
		return PrivateKey{}, fmt.Errorf("invalid WireGuard key encoding")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != keyBytes || base64.StdEncoding.EncodeToString(raw) != encoded {
		return PrivateKey{}, fmt.Errorf("invalid WireGuard key encoding")
	}
	var out PrivateKey
	copy(out.material[:], raw)
	clear(raw)
	return out, nil
}

func (k PrivateKey) PublicKey() (string, error) {
	key, err := ecdh.X25519().NewPrivateKey(k.material[:])
	if err != nil {
		return "", fmt.Errorf("invalid WireGuard private key")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// SecretWireValue is only for explicit credential-handling operations,
// never generic status, logging or diagnostics.
func (k PrivateKey) SecretWireValue() string {
	return base64.StdEncoding.EncodeToString(k.material[:])
}

func (PrivateKey) String() string     { return "[WireGuard private key REDACTED]" }
func (k PrivateKey) GoString() string { return k.String() }
func (PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal("[WireGuard private key REDACTED]")
}
