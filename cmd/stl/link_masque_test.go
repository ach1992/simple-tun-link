package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/masquehost"
)

func masqueInputTestRequest() masqueCreateRequestV1 {
	return masqueCreateRequestV1{
		SchemaVersion: 1,
		LinkID:        "lnk_0123456789abcdef0123456789abcdef",
		Underlay: desiredUnderlayV1{
			Local: netip.MustParseAddr("2a10:ed40::1"),
			Peer:  netip.MustParseAddr("2a01:4f8::2"),
		},
		Addresses: desiredLinkAddressesV1{
			Local: netip.MustParsePrefix("10.251.95.2/32"),
			Peer:  netip.MustParsePrefix("10.251.95.1/32"),
		},
		Role: "dial", TCPPort: 443, TLSServerName: "masque.example.org",
	}
}

func TestMASQUECreatorPairAndOfferExactConfirmation(t *testing.T) {
	request := masqueInputTestRequest()
	sender, receiver, err := request.makePair(request.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	if sender.MASQUE.Role != "dial" || receiver.MASQUE.Role != "listen" ||
		sender.Underlay.Local != receiver.Underlay.Peer || sender.Addresses.Local != receiver.Addresses.Peer {
		t.Fatal("MASQUE receiver endpoints did not invert exactly")
	}
	pair, err := masque.GeneratePair(sender.ID, sender.MASQUE.TLSServerName, 365)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	root := t.TempDir()
	sender, own, err := masquehost.BuildMaterial(root, sender, pair)
	if err != nil {
		t.Fatal(err)
	}
	defer masquehost.ClearFiles(own)
	receiver, other, err := masquehost.BuildMaterial(root, receiver, pair)
	if err != nil {
		t.Fatal(err)
	}
	offer := masqueOfferV1{SchemaVersion: 1, Sender: sender, Receiver: receiver, ReceiverMaterial: other}
	defer offer.Clear()
	if err := offer.Validate(root); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	received, raw, err := decodeMASQUEOffer(bytes.NewReader(encoded), root)
	if err != nil {
		t.Fatal(err)
	}
	defer received.Clear()
	if received.Receiver != receiver || !bytes.Equal(encoded, raw) {
		t.Fatal("offer decoding lost peer identity")
	}
	var out, errOut bytes.Buffer
	opts := &runtimeOptions{stateRoot: root}
	if code := linkMASQUECommand([]string{"preview-masque", "--stdin", "--json"},
		bytes.NewReader(encoded), &out, &errOut, opts); code != 0 {
		t.Fatalf("MASQUE preview failed %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), setupLinkConfirmation(string(encoded))) ||
		strings.Contains(out.String(), "PRIVATE KEY") ||
		strings.Contains(out.String(), string(other["server-key.pem"])) {
		t.Fatal("preview missing exact confirmation or leaked secret")
	}
	out.Reset()
	errOut.Reset()
	if code := linkMASQUECommand([]string{"import-masque", "--stdin", "--confirm", strings.Repeat("f", 64)},
		bytes.NewReader(encoded), &out, &errOut, opts); code == 0 {
		t.Fatal("unconfirmed MASQUE handoff was imported")
	}
	// Reject an active-link swap even if the attacker recomputes the
	// overall handoff confirmation hash.
	receiver.MASQUE.TCPPort++
	offer.Receiver = receiver
	bad, _ := json.Marshal(offer)
	if _, _, err := decodeMASQUEOffer(bytes.NewReader(bad), root); err == nil {
		t.Fatal("accepted mismatched protected MASQUE recipient topology")
	}
}

func TestMASQUECreatorRejectsUnsupportedInputWithoutHostEffects(t *testing.T) {
	request := masqueInputTestRequest()
	for _, mutation := range []func(*masqueCreateRequestV1){
		func(r *masqueCreateRequestV1) { r.Role = "invalid" },
		func(r *masqueCreateRequestV1) { r.TCPPort = 0 },
		func(r *masqueCreateRequestV1) { r.Addresses.Local = netip.MustParsePrefix("10.251.95.2/24") },
		func(r *masqueCreateRequestV1) { r.Underlay.Peer = netip.MustParseAddr("127.0.0.1") },
		func(r *masqueCreateRequestV1) { r.SchemaVersion = 2 },
		func(r *masqueCreateRequestV1) {
			r.Underlay.Local, r.Underlay.Peer = netip.MustParseAddr("10.251.95.2"), netip.MustParseAddr("10.251.95.1")
		},
	} {
		v := request
		mutation(&v)
		if _, _, err := v.makePair(request.LinkID); err == nil {
			t.Fatalf("invalid MASQUE creator accepted: %+v", v)
		}
	}
}

func TestMASQUEDesiredV6DoesNotWidenLegacySchemas(t *testing.T) {
	l := masqueInputTestRequest()
	desired, _, err := l.makePair(l.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	desired.MASQUE.MaterialSHA256 = strings.Repeat("b", 64)
	payload := map[string]any{
		"schema_version": desiredMASQUESchemaVersion,
		"link": map[string]any{
			"id": desired.ID, "backend": domain.BackendMASQUE, "encapsulation": domain.EncapTLS,
			"underlay": desired.Underlay, "addresses": desired.Addresses, "masque": desired.MASQUE,
		},
	}
	data, _ := json.Marshal(payload)
	got, err := decodeDesiredLink(bytes.NewReader(data))
	if err != nil || got != desired {
		t.Fatalf("MASQUE v6 failed exact roundtrip: %v", err)
	}
	payload["schema_version"] = 1
	old, _ := json.Marshal(payload)
	if _, err := decodeDesiredLink(bytes.NewReader(old)); err == nil {
		t.Fatal("legacy schema v1 silently gained MASQUE authority")
	}
	payload["schema_version"] = desiredMASQUESchemaVersion
	payload["link"].(map[string]any)["wireguard"] = map[string]any{"listen_port": 1337}
	extra, _ := json.Marshal(payload)
	if _, err := decodeDesiredLink(bytes.NewReader(extra)); err == nil {
		t.Fatal("MASQUE v6 accepted WireGuard-specific fields")
	}
}

// Invalid private offers and confirmation errors require actionable, secret-
// safe machine guidance instead of the generic "check Link ID" fallback.
func TestMASQUECLIPrivateInputErrorsAreActionable(t *testing.T) {
	root := t.TempDir()
	var out, errOut bytes.Buffer
	rc := linkMASQUECommand([]string{"preview-masque", "--stdin", "--json"},
		strings.NewReader("{"), &out, &errOut, &runtimeOptions{stateRoot: root})
	if rc != 2 {
		t.Fatalf("malformed preview exit=%d stderr=%s", rc, errOut.String())
	}
	var body lifecycleFailureResponse
	if err := json.Unmarshal(out.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error == nil || body.Error.ReasonCode != "masque_offer_invalid" ||
		!strings.Contains(body.Error.NextStep, "original private MASQUE receiver file") {
		t.Fatalf("wrong malformed handoff guidance: %+v", body.Error)
	}
	out.Reset()
	errOut.Reset()
	rc = linkMASQUECommand([]string{"import-masque", "--stdin", "--confirm", strings.Repeat("f", 64), "--json"},
		strings.NewReader("{"), &out, &errOut, &runtimeOptions{stateRoot: root})
	if rc != 2 {
		t.Fatalf("malformed import exit=%d", rc)
	}
	if err := json.Unmarshal(out.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error == nil || body.Error.ReasonCode != "masque_offer_invalid" {
		t.Fatalf("import guidance: %+v", body.Error)
	}
}

// The exact selected TLS authentication mode travels through both peers,
// protected receiver handoff and nonsecret preview; only explicit opt-in
// removes the TLS client-certificate requirement.
func TestMASQUEPublicTLSCreatePreviewAndReceiverOffer(t *testing.T) {
	request := masqueInputTestRequest()
	request.PublicTLS = true
	sender, receiver, err := request.makePair(request.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	if !sender.MASQUE.PublicTLS || !receiver.MASQUE.PublicTLS {
		t.Fatal("creator/receiver lost public TLS choice")
	}
	pair, err := masque.GeneratePair(sender.ID, sender.MASQUE.TLSServerName, 365)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	root := t.TempDir()
	sender, senderFiles, err := masquehost.BuildMaterial(root, sender, pair)
	if err != nil {
		t.Fatal(err)
	}
	defer masquehost.ClearFiles(senderFiles)
	receiver, receiverFiles, err := masquehost.BuildMaterial(root, receiver, pair)
	if err != nil {
		t.Fatal(err)
	}
	offer := masqueOfferV1{SchemaVersion: 1, Sender: sender, Receiver: receiver, ReceiverMaterial: receiverFiles}
	defer offer.Clear()
	if err := offer.Validate(root); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := linkMASQUECommand([]string{"preview-masque", "--stdin", "--json"}, bytes.NewReader(raw),
		&out, &errOut, &runtimeOptions{stateRoot: root}); code != 0 {
		t.Fatalf("public receiver preview failed: code %d: %s", code, errOut.String())
	}
	var preview struct {
		PublicTLS bool   `json:"public_tls"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || !preview.PublicTLS ||
		preview.Role != receiver.MASQUE.Role {
		t.Fatalf("public receiver preview lost TLS mode: %v %+v", err, preview)
	}
	if bytes.Contains(out.Bytes(), pair.BearerToken) ||
		bytes.Contains(out.Bytes(), pair.ClientPrivateKey) ||
		bytes.Contains(out.Bytes(), pair.ServerPrivateKey) {
		t.Fatal("public receiver preview leaked protected material")
	}
	offer.Receiver.MASQUE.PublicTLS = false
	if err := offer.Validate(root); err == nil {
		t.Fatal("accepted a sender/receiver TLS authentication mode mismatch")
	}
}

// The explicit public-TLS flag is a typed, nonsecret MASQUE v6 desired Link
// field. It must round-trip without changing any legacy schema contract.
func TestPublicMASQUEDesiredV6RoundTripsMode(t *testing.T) {
	request := masqueInputTestRequest()
	request.PublicTLS = true
	link, _, err := request.makePair(request.LinkID)
	if err != nil {
		t.Fatal(err)
	}
	link.MASQUE.MaterialSHA256 = strings.Repeat("a", 64)
	input := map[string]any{"schema_version": desiredMASQUESchemaVersion, "link": map[string]any{
		"id": link.ID, "backend": domain.BackendMASQUE, "encapsulation": domain.EncapTLS,
		"underlay": link.Underlay, "addresses": link.Addresses, "masque": link.MASQUE,
	}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := decodeDesiredLink(bytes.NewReader(raw))
	if err != nil || actual != link || !actual.MASQUE.PublicTLS {
		t.Fatalf("MASQUE public TLS desired v6 roundtrip: %v actual=%+v", err, actual)
	}
}
