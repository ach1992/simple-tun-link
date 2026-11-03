package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
)

func testProtectedWSSReceiverOffer(t *testing.T) ([]byte, string) {
	t.Helper()
	req := testWSSCreateRequest()
	senderKey, senderPublic, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer senderKey.Zeroize()
	receiverKey, receiverPublic, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer receiverKey.Zeroize()
	sender, receiver, err := makeWSSPair(req, req.LinkID, senderPublic, receiverPublic)
	if err != nil {
		t.Fatal(err)
	}
	listen, dial, err := wss.GeneratePair(req.LinkID, req.Underlay.Local.String())
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	offer := wssOffer{SchemaVersion: 1, Sender: sender, Receiver: receiver,
		ReceiverWGKey: receiverKey.SecretWireValue(), ReceiverTLS: dial}
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(raw) })
	return raw, receiver.Underlay.Local.String()
}

// Real protected WSS/QUIC menu preview and recipient preflight must reject
// a Link for another host BEFORE asking approval or staging any credentials.
func TestProtectedImportMenusRejectWrongRecipientBeforeApproval(t *testing.T) {
	for _, mode := range []string{"wss", "quic"} {
		t.Run(mode, func(t *testing.T) {
			var raw []byte
			var receiver string
			if mode == "wss" {
				raw, receiver = testProtectedWSSReceiverOffer(t)
			} else {
				offer, payload := testQUICOffer(t)
				raw, receiver = payload, offer.Receiver.Underlay.Local.String()
			}
			root := filepath.Join(t.TempDir(), "no-state")
			probe := &greReceiverProbe{inventory: greReceiverInventory("eth0", "203.0.113.197")}
			pipe := strings.NewReader(string(raw) + "\nYES\n")
			reader := bufio.NewReader(pipe)
			var out, errOut bytes.Buffer
			opts := &runtimeOptions{stateRoot: root, probeRunner: probe}
			var code int
			if mode == "wss" {
				code = menuImportWSS(pipe, reader, &out, &errOut, opts)
			} else {
				code = menuImportQUIC(pipe, reader, &out, &errOut, opts)
			}
			if code != 2 || probe.calls != 1 ||
				!strings.Contains(out.String(), "not assigned to THIS server") ||
				!strings.Contains(out.String(), "No import was attempted") ||
				strings.Contains(out.String(), "Import and start this authenticated") ||
				errOut.Len() != 0 || strings.Contains(out.String(), string(raw)) ||
				strings.Contains(out.String(), "PRIVATE KEY") {
				t.Fatalf("protected wrong-receiver import not safely refused: mode=%s receiver=%s code=%d out=%q err=%q",
					mode, receiver, code, out.String(), errOut.String())
			}
			if _, err := os.Lstat(filepath.Join(root, "state.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("wrong receiver committed protected state: %v", err)
			}
		})
	}
}
