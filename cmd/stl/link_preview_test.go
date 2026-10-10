package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func previewCLI(args []string, input string) (int, string, string) {
	var out, errOut strings.Builder
	code := runWithRuntimeInput(args, strings.NewReader(input), &out, &errOut, nil)
	return code, out.String(), errOut.String()
}

func TestCLIPreviewReceiverOrientationWithoutApplying(t *testing.T) {
	link := fixtureReadLink("lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "10.80.70.0/31", "10.80.70.1/31", domain.BackendGRE)
	offer, err := pairing.NewQuickOffer(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	code, out, stderr := previewCLI([]string{"link", "preview", "--stdin", "--json"}, setup+"\n")
	if code != 0 || stderr != "" || strings.Contains(out, "private_key") {
		t.Fatalf("preview leaked or failed: %d %q %q", code, out, stderr)
	}
	var got ImportPreviewResponse
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != jsonSchemaVersion || got.PairingSchemaVersion != pairing.SchemaVersion ||
		got.LinkID != link.ID || got.Mode != pairing.ModeQuick || got.Sensitive ||
		got.LocalUnderlay != link.Underlay.Peer.String() || got.PeerUnderlay != link.Underlay.Local.String() ||
		got.LocalAddress != link.Addresses.Peer.String() || got.PeerAddress != link.Addresses.Local.String() {
		t.Fatalf("receiver orientation/schema failed: %+v", got)
	}
	code, out, stderr = previewCLI([]string{"link", "preview", "--stdin"}, setup+"\n")
	if code != 0 || stderr != "" || !strings.Contains(out, "not applied") || strings.Contains(out, setup) ||
		strings.Contains(out, "private_key") {
		t.Fatalf("unsafe human preview: %d %q %q", code, out, stderr)
	}
}

func TestCLIPreviewRedactsReceiverPrivateKeyAndUnknownDisplayName(t *testing.T) {
	link := fixtureReadLink("lnk_dddddddddddddddddddddddddddddddd", "10.80.40.0/31", "10.80.40.1/31", domain.BackendWireGuard)
	link.Encapsulation = domain.EncapUDP
	link.DisplayName = "credential-should-not-appear"
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	completeWireGuardFixture(t, &link, secret)
	offer, err := pairing.NewQuickOffer(link, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	url, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"link", "preview", "--stdin"},
		{"link", "preview", "--stdin", "--json"},
	} {
		code, out, stderr := previewCLI(args, url+"\n")
		if code != 0 || stderr != "" || strings.Contains(out, url) || strings.Contains(out, secret) ||
			strings.Contains(out, "credential-should-not-appear") {
			t.Fatalf("sensitive preview leaked: %v code=%d out=%q err=%q", args, code, out, stderr)
		}
		if !strings.Contains(out, "wireguard_private_key") || !strings.Contains(out, "sensitive") && args[len(args)-1] == "--json" {
			t.Fatalf("credential presence/kind omitted: %v out=%q", args, out)
		}
		if args[len(args)-1] == "--json" {
			var got ImportPreviewResponse
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			if !got.HasCredential || !got.Sensitive || got.CredentialKind != pairing.CredentialWireGuardPrivateKey {
				t.Fatalf("recipient redacted flag/metadata wrong: %+v", got)
			}
		}
	}
}

func TestCLIPreviewFailsClosedOnMalformedOversizeAndInvalidFlags(t *testing.T) {
	inputs := []struct {
		name  string
		args  []string
		input string
		code  int
	}{
		{"bad scheme", []string{"link", "preview", "--stdin", "--json"}, "secret://do-not-leak\n", 2},
		{"tampered checksum", []string{"link", "preview", "--stdin", "--json"}, "stl://2.abc.deadbeef\n", 2},
		{"oversized", []string{"link", "preview", "--stdin", "--json"}, strings.Repeat("DO_NOT_EXPOSE_", pairing.MaxLinkBytes), 2},
		{"missing stdin flag", []string{"link", "preview", "--json"}, "some-secret", 2},
		{"invalid flags", []string{"link", "preview", "--stdin", "--json", "--unknown"}, "some-secret", 2},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := previewCLI(tc.args, tc.input)
			if code != tc.code || stderr != "" || strings.Contains(out, "DO_NOT_EXPOSE") ||
				strings.Contains(out, "some-secret") || strings.Contains(out, "secret://") {
				t.Fatalf("untrusted input leaked or accepted: code=%d out=%q err=%q", code, out, stderr)
			}
			if tc.args[len(tc.args)-1] == "--json" {
				var response linkReadErrorResponse
				if err := json.Unmarshal([]byte(out), &response); err != nil || response.SchemaVersion != 1 ||
					response.Error == nil || response.Error.Code != stlerr.CodeInvalid {
					t.Fatalf("invalid preview does not have structured error: %q", out)
				}
			}
		})
	}
}

func TestCLIPreviewInputNeverAppearsOnArgvOrUsesBackendRuntime(t *testing.T) {
	// No pairing URL appears in argv, no stateRoot or backend is supplied,
	// and the only new code path uses pairing.PreviewSetupLink.
	args := []string{"link", "preview", "--stdin", "--json"}
	code, out, _ := previewCLI(args, "not-a-setup-url")
	if code != 2 || strings.Contains(out, "not-a-setup-url") {
		t.Fatalf("failed setup link was exposed: %d %q", code, out)
	}
}

func TestCLIPreviewIncludesNonsecretFOUSettingsBeforeAnyImport(t *testing.T) {
	link := fixtureReadLink("lnk_ffffffffffffffffffffffffffffffff",
		"10.80.80.0/31", "10.80.80.1/31", domain.BackendGRE)
	link.Encapsulation = domain.EncapFOU
	link.GRE = domain.GREOptions{KeyEnabled: true, Key: 0, UDPPort: 4500, Checksum: true}
	offer, err := pairing.NewQuickOffer(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	url, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	code, body, stderr := previewCLI([]string{"link", "preview", "--stdin", "--json"}, url+"\n")
	if code != 0 || stderr != "" {
		t.Fatalf("cannot preview GRE FOU: %d %q %q", code, body, stderr)
	}
	var got ImportPreviewResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.GRE == nil || !got.GRE.KeyEnabled || got.GRE.Key != 0 ||
		got.GRE.UDPPort != 4500 || !got.GRE.Checksum || got.Sensitive {
		t.Fatalf("important non-secret backend config omitted: %+v", got)
	}
	code, body, stderr = previewCLI([]string{"link", "preview", "--stdin"}, url+"\n")
	if code != 0 || stderr != "" || !strings.Contains(body, "udp_port=4500") ||
		!strings.Contains(body, "key_enabled=true key=0") || strings.Contains(body, url) {
		t.Fatalf("human backend-specific preview incomplete: %d %q %q", code, body, stderr)
	}
}
