package wireguard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestWireGuardKeyGenerationIsCanonicalAndNeverGenericOutput(t *testing.T) {
	key, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw := key.material
	if raw[0]&7 != 0 || raw[31]&0x80 != 0 || raw[31]&0x40 == 0 {
		t.Fatal("generated WireGuard scalar must follow wg genkey clamping")
	}
	if len(public) != wireKeyTextLen {
		t.Fatal("expected standard 32-byte public key")
	}
	if decodedPub, err := base64.StdEncoding.Strict().DecodeString(public); err != nil || len(decodedPub) != keyBytes {
		t.Fatal("invalid generated WireGuard public key")
	}
	derived, err := key.PublicKey()
	if err != nil || derived != public {
		t.Fatal("public key does not derive from generated private key")
	}
	encoded := key.SecretWireValue()
	decoded, err := DecodePrivateKey(encoded)
	if err != nil || decoded != key {
		t.Fatal("generated private key failed canonical round trip")
	}
	other, _, err := GenerateKeyPair()
	if err != nil || other == key {
		t.Fatal("independent generated private key did not differ")
	}
	ordinaryJSON, err := json.Marshal(struct {
		Name string     `json:"name"`
		Key  PrivateKey `json:"key"`
	}{Name: "safe", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{encoded, base64.RawURLEncoding.EncodeToString(raw[:])} {
		for _, ordinary := range []string{string(ordinaryJSON), fmt.Sprintf("%v", key),
			fmt.Sprintf("%+v", key), fmt.Sprintf("%#v", key), fmt.Sprintf("%+v", struct{ K PrivateKey }{key})} {
			if strings.Contains(ordinary, value) {
				t.Fatal("generic formatting exposed private key")
			}
		}
	}
}

func TestPrivateKeyDecoderStrictCanonicalEncoding(t *testing.T) {
	key, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	value := key.SecretWireValue()
	for _, tc := range []string{
		"", strings.TrimSuffix(value, "="), value + "=", value[:42] + "??",
		strings.Repeat("a", 44), strings.Repeat("x", 100),
		"my-secret", value + "\n",
	} {
		if _, err := DecodePrivateKey(tc); err == nil {
			t.Fatalf("malformed WireGuard private key was accepted, length=%d", len(tc))
		}
	}
}
