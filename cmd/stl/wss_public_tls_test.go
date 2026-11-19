//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/composition"
)

func TestPublicTLSWSSPairCommandsPreviewAndRejection(t *testing.T) {
	r := testWSSCreateRequest()
	r.PublicTLS = true
	key, local, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()
	peerKey, peer, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer peerKey.Zeroize()
	sender, receiver, err := makeWSSPair(r, r.LinkID, local, peer)
	if err != nil {
		t.Fatal(err)
	}
	if !sender.WSS.PublicTLS || !receiver.WSS.PublicTLS {
		t.Fatal("peer mode dropped")
	}
	for _, l := range []bool{true, false} {
		link := sender
		if !l {
			link = receiver
		}
		cmd, err := wss.Build(link, composition.CarrierForLink(link), "/opt/stl/wstunnel", "/var/lib/simple-tun-link", strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		if !link.WSS.PublicTLS || slices.Contains(cmd.Args, "--tls-client-ca-certs") {
			t.Fatal("public TLS still requires a client CA")
		}

		if slices.Contains(cmd.Args, "--insecure") || !slices.Contains(cmd.Args, "--restrict-config") && link.WSS.Role == "listen" {
			t.Fatal("invalid public TLS admission")
		}
		if link.WSS.Role == "dial" {
			if slices.Contains(cmd.Args, "--tls-certificate") || slices.Contains(cmd.Args, "--tls-private-key") {
				t.Fatal("public TLS dialer unexpectedly supplies a client certificate")
			}
			if !slices.Contains(cmd.Args, "--tls-verify-certificate") ||
				!slices.Contains(cmd.Args, "--http-upgrade-path-prefix") ||
				!slices.Contains(cmd.Args, "--http-headers-file") ||
				len(cmd.Env) != 1 || !strings.HasPrefix(cmd.Env[0], "SSL_CERT_FILE=") {
				t.Fatal("public TLS dialer lacks server trust or request-level path/bearer")
			}
		} else {
			if !slices.Contains(cmd.Args, "--tls-certificate") || !slices.Contains(cmd.Args, "--tls-private-key") {
				t.Fatal("public TLS server must retain its own server certificate")
			}
			if !slices.Contains(cmd.Args, "--restrict-config") ||
				!bytes.Contains(cmd.ServerRestrictions, []byte("!Authorization")) ||
				!bytes.Contains(cmd.ServerRestrictions, []byte("!PathPrefix")) ||
				!bytes.Contains(cmd.ServerRestrictions, []byte("127.0.0.1")) ||
				bytes.Contains(cmd.ServerRestrictions, []byte("0.0.0.0/0")) {
				t.Fatal("public TLS server lost exact restricted private destination")
			}
		}
	}
	original := receiver
	receiver.WSS.PublicTLS = false
	if err := composition.ValidateWSSPeerPair(original, composition.CarrierForLink(original),
		sender, composition.CarrierForLink(sender)); err != nil {
		t.Fatal(err)
	}
	if err := composition.ValidateWSSPeerPair(receiver, composition.CarrierForLink(receiver),
		sender, composition.CarrierForLink(sender)); err == nil {
		t.Fatal("peer public TLS mismatch admitted")
	}
	receiver = original
	listen, dial, err := wss.GeneratePair(r.LinkID, "198.51.100.21")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	offer := wssOffer{SchemaVersion: 1, Sender: sender, Receiver: receiver,
		ReceiverWGKey: peerKey.SecretWireValue(), ReceiverTLS: dial}
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	decoded, copied, err := decodeWSSOffer(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.clear()
	defer clear(copied)
	if !decoded.Receiver.WSS.PublicTLS || !decoded.Sender.WSS.PublicTLS {
		t.Fatal("protected offer lost public TLS")
	}
	var view bytes.Buffer
	if code := linkWSSCommand([]string{"preview-wss", "--stdin", "--json"}, bytes.NewReader(raw), &view, io.Discard, nil); code != 0 {
		t.Fatal("preview refused valid public TLS offer")
	}
	var result struct {
		PublicTLS bool   `json:"public_tls"`
		Confirm   string `json:"confirmation_sha256"`
	}
	if json.Unmarshal(view.Bytes(), &result) != nil || !result.PublicTLS || result.Confirm != setupLinkConfirmation(string(raw)) {
		t.Fatal("public TLS preview did not bind selected mode")
	}
	for _, private := range offer.ReceiverTLS {
		if len(private) > 0 && bytes.Contains(view.Bytes(), private) {
			t.Fatal("preview exposed private TLS material")
		}
	}
}

func TestWSSPublicTLSGuidedChoice(t *testing.T) {
	for _, tc := range []struct {
		input    string
		expected bool
		ok       bool
	}{
		{"\n", false, true}, {"1\n", false, true}, {"2\n", true, true}, {"3\n", false, false}, {"", false, false},
	} {
		var out bytes.Buffer
		got, err := askWSSPublicTLS(createPrompts{reader: bufio.NewReader(strings.NewReader(tc.input)), out: &out, errOut: io.Discard})
		if (err == nil) != tc.ok || got != tc.expected || !strings.Contains(out.String(), "HTTP GET returns 400") {
			t.Fatalf("choice %q: got=%t err=%v", tc.input, got, err)
		}
	}
}
