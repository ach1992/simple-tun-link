package pairing

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func encodeRawForTest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return setupPrefix + base64.RawURLEncoding.EncodeToString(raw) + "." + hex.EncodeToString(sum[:])
}
func TestRejectMalformedTruncatedOversizedAndTamperedLinks(t *testing.T) {
	offer, err := NewQuickOffer(testLink(idOne, domain.BackendWireGuard, domain.EncapUDP), wgTestKey())
	if err != nil {
		t.Fatal(err)
	}
	valid, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid[len(setupPrefix):], ".")
	if len(parts) != 2 {
		t.Fatal("invalid test fixture")
	}
	cases := []string{
		"", "example://1." + parts[0] + "." + parts[1], "stl://2." + parts[0] + "." + parts[1],
		"stl://1.", valid[:len(valid)-5], valid + ".extra", valid + "\nsecret",
		valid[:len(valid)-1] + "0", setupPrefix + "not_base64!." + parts[1],
		setupPrefix + parts[0] + "." + strings.ToUpper(parts[1]), setupPrefix + "a." + parts[1],
		strings.Repeat("x", MaxLinkBytes+1),
	}
	for i, raw := range cases {
		_, err := DecodeSetupLink(raw)
		if err == nil {
			t.Fatalf("malformed case %d accepted", i)
		}
		if strings.Contains(err.Error(), string(wgTestKey())) {
			t.Fatalf("secret leaked in malformed case %d", i)
		}
	}
}
func TestMalformedSchemasRejectedEvenWithCorrectIntegrityHash(t *testing.T) {
	linkJSON, err := json.Marshal(testLink(idOne, domain.BackendGRE, domain.EncapNative))
	if err != nil {
		t.Fatal(err)
	}
	link := string(linkJSON)
	tests := []struct {
		name, raw string
		code      stlerr.Code
	}{
		{"trailing JSON", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s} true`, link), stlerr.CodeInvalid},
		{"unknown root key", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s,"command":"rm -rf /"}`, link), stlerr.CodeInvalid},
		{"unknown nested key", strings.Replace(fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s}`, link), `"underlay":{`, `"underlay":{"command":"execute",`, 1), stlerr.CodeInvalid},
		{"duplicate exchange mode", fmt.Sprintf(`{"schema_version":1,"mode":"quick","mode":"secure_exchange","link":%s}`, link), stlerr.CodeInvalid},
		{"duplicate nested local", strings.Replace(fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s}`, link), `"underlay":{`, `"underlay":{"local":"198.51.100.3",`, 1), stlerr.CodeInvalid},
		{"wrong key case", fmt.Sprintf(`{"schema_version":1,"Mode":"quick","link":%s}`, link), stlerr.CodeInvalid},
		{"array instead of link", `{"schema_version":1,"mode":"quick","link":[]}`, stlerr.CodeInvalid},
		{"null recipient credential", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s,"recipient_secret":null}`, link), stlerr.CodeInvalid},
		{"unsupported schema version", fmt.Sprintf(`{"schema_version":2,"mode":"quick","link":%s}`, link), stlerr.CodeUnsupported},
		{"unsupported exchange mode", fmt.Sprintf(`{"schema_version":1,"mode":"secure_exchange","link":%s}`, link), stlerr.CodeUnsupported},
		{"missing schema version", fmt.Sprintf(`{"mode":"quick","link":%s}`, link), stlerr.CodeUnsupported},
		{"plaintext backend with credential", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s,"recipient_secret":{"kind":"ipsec_psk","data":"YQ"}}`, link), stlerr.CodeInvalid},
		{"unknown nested credential field", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s,"recipient_secret":{"kind":"ipsec_psk","data":"YQ","path":"/etc/passwd"}}`, link), stlerr.CodeInvalid},
		{"unknown credential kind", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s,"recipient_secret":{"kind":"shell","data":"YQ"}}`, link), stlerr.CodeInvalid},
		{"duplicate credential data", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s,"recipient_secret":{"kind":"ipsec_psk","data":"YQ","data":"Yg"}}`, link), stlerr.CodeInvalid},
		{"malformed JSON", fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s`, link), stlerr.CodeInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeSetupLink(encodeRawForTest([]byte(tt.raw)))
			if err == nil || stlerr.CodeOf(err) != tt.code {
				t.Fatalf("incorrect code/accepted schema: %v", err)
			}
			if strings.Contains(err.Error(), "rm -rf") || strings.Contains(err.Error(), "/etc/passwd") {
				t.Fatal("rejected payload leaked in error")
			}
		})
	}
}
func TestCredentialBackendKindAndEncodingTampering(t *testing.T) {
	linkJSON, err := json.Marshal(testLink(idOne, domain.BackendWireGuard, domain.EncapUDP))
	if err != nil {
		t.Fatal(err)
	}
	link := string(linkJSON)
	base := `{"schema_version":1,"mode":"quick","link":%s,"recipient_secret":{"kind":%s,"data":%s}}`
	cases := []struct{ name, kind, data string }{
		{"wrong kind", `"ipsec_psk"`, fmt.Sprintf("%q", base64.RawURLEncoding.EncodeToString(wgTestKey()))},
		{"missing kind", `""`, fmt.Sprintf("%q", base64.RawURLEncoding.EncodeToString(wgTestKey()))},
		{"invalid base64", `"wireguard_private_key"`, `"not-base64!"`},
		{"empty data", `"wireguard_private_key"`, `""`},
		{"unrelated command-like field", `"other"`, `"/bin/sh"`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			raw := fmt.Sprintf(base, link, tt.kind, tt.data)
			if _, err := DecodeSetupLink(encodeRawForTest([]byte(raw))); err == nil {
				t.Fatal("malformed recipient credential accepted")
			}
		})
	}
}
func TestRejectMalformedEscapedUTF16Surrogates(t *testing.T) {
	linkJSON, err := json.Marshal(testLink(idOne, domain.BackendGRE, domain.EncapNative))
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s}`, linkJSON)
	original := `"display_name":"Production Link / Test"`
	for _, tc := range []struct{ name, literal string }{
		{"lone_high", `"\uD83D"`},
		{"lone_low", `"\uDE00"`},
		{"nonpair_second_escape", `"\uD83D\u0061"`},
		{"two_high_surrogates", `"\uD83D\uD83D"`},
		{"nonadjacent_surrogates", `"\uD83Dx\uDE00"`},
		{"high_then_escaped_backslash", `"\uD83D\\uDE00"`},
		{"invalid_second_hex_quad", `"\uD83D\uDE0Z"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(base, original, `"display_name":`+tc.literal, 1)
			if raw == base {
				t.Fatal("test fixture did not replace display name")
			}
			pairingLink := encodeRawForTest([]byte(raw))
			if _, err := DecodeSetupLink(pairingLink); err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid {
				t.Fatalf("malformed surrogate accepted: %v", err)
			}
			if _, err := PreviewSetupLink(pairingLink); err == nil {
				t.Fatal("malformed surrogate accepted by redacted preview")
			}
		})
	}
}

func TestValidJSONUnicodeEscapesPreservePairingMetadata(t *testing.T) {
	linkJSON, err := json.Marshal(testLink(idOne, domain.BackendGRE, domain.EncapNative))
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf(`{"schema_version":1,"mode":"quick","link":%s}`, linkJSON)
	for _, tc := range []struct{ name, literal, want string }{
		{"surrogate_pair", `"\uD83D\uDE00"`, "😀"},
		{"literal_replacement_character", `"�"`, "�"},
		{"escaped_replacement_character", `"\uFFFD"`, "�"},
		{"persian_display_name", `"نمونه"`, "نمونه"},
		{"escaped_literal_backslash", `"\\uD800"`, `\uD800`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(base, `"display_name":"Production Link / Test"`, `"display_name":`+tc.literal, 1)
			if raw == base {
				t.Fatal("test fixture did not replace display name")
			}
			decoded, err := DecodeSetupLink(encodeRawForTest([]byte(raw)))
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Link().DisplayName != tc.want {
				t.Fatalf("metadata changed: got %q want %q", decoded.Link().DisplayName, tc.want)
			}
			reencoded, err := decoded.EncodeSetupLink()
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := DecodeSetupLink(reencoded)
			if err != nil || roundtrip.Link().DisplayName != tc.want {
				t.Fatalf("unicode pairing round-trip failed: %v", err)
			}
		})
	}
}

func TestInvalidUTF8IsNotSilentlyRewritten(t *testing.T) {
	raw := []byte("{\"schema_version\":1,\"mode\":\"quick\",\"link\":{\"display_name\":\"")
	raw = append(raw, 0xff)
	raw = append(raw, []byte("\"}}")...)
	_, err := DecodeSetupLink(encodeRawForTest(raw))
	if err == nil || stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("invalid UTF-8 accepted: %v", err)
	}
}

func TestStrictSchemaRawSizeLimitPreventsLargeAllocations(t *testing.T) {
	blob := bytes.Repeat([]byte{' '}, MaxPayloadBytes+1)
	if _, err := DecodeSetupLink(encodeRawForTest(blob)); err == nil {
		t.Fatal("oversize raw data accepted")
	}
}
func FuzzDecodeSetupLink(f *testing.F) {
	offer, _ := NewQuickOffer(testLink(idOne, domain.BackendGRE, domain.EncapNative), nil)
	valid, _ := offer.EncodeSetupLink()
	f.Add(valid)
	f.Add("stl://1.")
	f.Add("stl://2.some.bad")
	f.Add("stl://1.some.")
	f.Fuzz(func(t *testing.T, input string) {
		offer, err := DecodeSetupLink(input)
		if err == nil {
			if _, err := offer.EncodeSetupLink(); err != nil {
				t.Fatalf("accepted invalid offer: %v", err)
			}
		}
	})
}
