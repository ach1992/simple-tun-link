//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestQUICCreatorVersionedObfuscationAndPlainIdentity(t *testing.T) {
	original := testQUICCreateRequest()
	plain, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version int
		mode    string
		ok      bool
		want    string
	}{
		{1, "", false, ""}, {1, "plain", false, ""}, {1, "salamander", false, ""},
		{2, "", true, ""}, {2, "plain", true, ""}, {2, "salamander", true, "salamander"},
		{2, "gecko", false, ""}, {2, "Salamander", false, ""}, {2, " salamander", false, ""}, {3, "plain", false, ""},
	} {
		raw := bytes.Replace(plain, []byte(`"schema_version":1`), []byte(`"schema_version":`+strconv.Itoa(tc.version)), 1)
		mode, _ := json.Marshal(tc.mode)
		raw = append(append([]byte(nil), raw[:len(raw)-1]...), append([]byte(`,"obfuscation":`), append(mode, '}')...)...)
		request, err := decodeQUICCreateRequest(raw)
		if (err == nil) != tc.ok {
			t.Fatalf("creator version=%d mode=%q accepted=%t: %v", tc.version, tc.mode, err == nil, err)
		}
		if tc.ok && request.Obfuscation != tc.want {
			t.Fatal("public mode did not normalize to canonical identity")
		}
	}
	decoded, err := decodeQUICCreateRequest(plain)
	if err != nil || decoded != original {
		t.Fatal("original creator v1 Plain identity changed", err)
	}
	// Rejection happens before key generation or publication in the command path.
	root := filepath.Join(t.TempDir(), "absent-state")
	raw := bytes.Replace(plain, []byte(`"schema_version":1`), []byte(`"schema_version":2,"obfuscation":"unknown"`), 1)
	var out, stderr bytes.Buffer
	if code := createQUIC(bytes.NewReader(raw), filepath.Join(t.TempDir(), "offer"), &out, &stderr, true, &runtimeOptions{stateRoot: root}); code != 2 {
		t.Fatalf("invalid mode exit=%d", code)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("invalid mode touched State")
	}
}

func TestQUICDesiredV5IsExplicitAndLegacyV4StaysPlain(t *testing.T) {
	offer, _ := testQUICOffer(t)
	encode := func(version int, link domain.Link) []byte {
		raw, err := json.Marshal(struct {
			SchemaVersion int         `json:"schema_version"`
			Link          domain.Link `json:"link"`
		}{version, link})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, mode := range []string{"", "plain", "salamander", "gecko"} {
		for _, version := range []int{4, 5} {
			raw := encode(version, offer.Sender)
			field, _ := json.Marshal(mode)
			raw = bytes.Replace(raw, []byte(`"quic":{`), append([]byte(`"quic":{"obfuscation":`), append(field, ',')...), 1)
			got, err := decodeDesiredLink(bytes.NewReader(raw))
			wantOK := version == 5 && mode != "gecko"
			if (err == nil) != wantOK {
				t.Fatalf("desired version=%d mode=%q accepted=%t", version, mode, err == nil)
			}
			if wantOK {
				expected := offer.Sender
				if mode == "salamander" {
					expected.QUIC.Obfuscation = mode
				}
				if got != expected {
					t.Fatal("desired canonical identity differs")
				}
			}
		}
	}
	native := offer.Sender
	native.Backend, native.QUIC = domain.BackendWireGuard, domain.QUICOptions{}
	if _, err := decodeDesiredLink(bytes.NewReader(encode(5, native))); err == nil {
		t.Fatal("new QUIC schema accepted another backend")
	}
}

func TestSalamanderOfferV2AndSafePreview(t *testing.T) {
	offer, raw := testQUICOfferWithMode(t, "salamander")
	decoded, exact, err := decodeQUICOffer(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.clear()
	defer clear(exact)
	if decoded.SchemaVersion != 2 || decoded.Sender != offer.Sender || decoded.Receiver != offer.Receiver || !bytes.Equal(exact, raw) {
		t.Fatal("private v2 handoff changed")
	}
	var out, stderr bytes.Buffer
	if code := linkQUICCommand([]string{"preview-quic", "--stdin", "--json"}, bytes.NewReader(raw), &out, &stderr, nil); code != 0 {
		t.Fatal("Salamander preview failed")
	}
	var view struct {
		Obfuscation string `json:"obfuscation"`
		Confirm     string `json:"confirmation_sha256"`
	}
	if json.Unmarshal(out.Bytes(), &view) != nil || view.Obfuscation != "salamander" || view.Confirm != setupLinkConfirmation(string(raw)) {
		t.Fatal("safe preview did not bind mode and exact offer")
	}
	for _, secret := range offer.ReceiverTLS {
		if bytes.Contains(out.Bytes(), secret) || bytes.Contains(out.Bytes(), []byte(base64.StdEncoding.EncodeToString(secret))) {
			t.Fatal("private material in public preview")
		}
	}
	for name, mutate := range map[string]func(*quicOffer){
		"legacy schema":   func(o *quicOffer) { o.SchemaVersion = 1 },
		"mismatched mode": func(o *quicOffer) { o.Sender.QUIC.Obfuscation = "" },
		"missing secret":  func(o *quicOffer) { delete(o.ReceiverTLS, "obfs-secret") },
		"unknown mode":    func(o *quicOffer) { o.Receiver.QUIC.Obfuscation = "gecko" },
	} {
		t.Run(name, func(t *testing.T) {
			var bad quicOffer
			if json.Unmarshal(raw, &bad) != nil {
				t.Fatal("fixture")
			}
			defer bad.clear()
			mutate(&bad)
			payload, _ := json.Marshal(bad)
			defer clear(payload)
			rejected, _, err := decodeQUICOffer(bytes.NewReader(payload))
			rejected.clear()
			if err == nil {
				t.Fatal("invalid mode/material pairing accepted")
			}
		})
	}
	_, legacy := testQUICOffer(t)
	for _, value := range []string{`""`, `"plain"`, `"salamander"`} {
		bad := bytes.Replace(legacy, []byte(`"quic":{`), []byte(`"quic":{"obfuscation":`+value+`,`), 1)
		decoded, contents, err := decodeQUICOffer(bytes.NewReader(bad))
		decoded.clear()
		clear(contents)
		if err == nil {
			t.Fatal("legacy handoff accepted a new field")
		}
	}
}

func TestSalamanderSavedOfferBindsBothSharedSecrets(t *testing.T) {
	offer, raw := testQUICOfferWithMode(t, "salamander")
	record := state.LinkRecord{Desired: offer.Sender, QUICGeneration: quicUITestGeneration(offer)}
	if !quicOfferMatchesSenderGeneration(offer, record) {
		t.Fatal("original paired material refused")
	}
	var changed quicOffer
	if json.Unmarshal(raw, &changed) != nil {
		t.Fatal("fixture")
	}
	defer changed.clear()
	changed.ReceiverTLS["obfs-secret"] = []byte(strings.Repeat("0", 64) + "\n")
	if quicOfferMatchesSenderGeneration(changed, record) {
		t.Fatal("changed obfuscation secret gained sender re-export authority")
	}
}

func TestQUICMenuObfuscationChoiceUsesCanonicalModes(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		ok          bool
	}{{"\n", "", true}, {"1\n", "", true}, {"2\n", "salamander", true}, {"3\n", "", false}, {"", "", false}} {
		var out bytes.Buffer
		got, err := askQUICObfuscation(createPrompts{reader: bufio.NewReader(strings.NewReader(tc.input)), out: &out, errOut: io.Discard})
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("input=%q got=%q err=%v", tc.input, got, err)
		}
		if !strings.Contains(out.String(), "Plain") || !strings.Contains(out.String(), "Salamander") {
			t.Fatal("mode choices omitted")
		}
	}
}
