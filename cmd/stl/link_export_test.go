package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func runExport(t *testing.T, root string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runWithRuntime(args, &out, &errOut, &runtimeOptions{stateRoot: root})
	return code, out.String(), errOut.String()
}

func exportLinkFixture(id string, subnet string) domain.Link {
	return domain.Link{
		ID:          domain.LinkID("lnk_" + strings.Repeat(id, 32)),
		DisplayName: "private_label=encoded_not_plain",
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.5"), Peer: netip.MustParseAddr("198.51.100.10"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix(subnet),
			Peer:  netip.MustParsePrefix(strings.Replace(subnet, ".0/31", ".1/31", 1)),
		},
		Backend: domain.BackendGRE, Encapsulation: domain.EncapNative,
	}
}

func TestCLIExportCreatesCanonicalRecipientSetupLinkByStableID(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	first := exportLinkFixture("1", "10.80.50.0/31")
	second := exportLinkFixture("2", "10.80.51.0/31")
	second.Encapsulation = domain.EncapFOU
	second.GRE = domain.GREOptions{UDPPort: 4500, KeyEnabled: true, Key: 0, Checksum: true}
	storeReadLinks(t, root, second, first)
	ipipNative := exportLinkFixture("4", "10.80.52.0/31")
	ipipNative.Backend = domain.BackendIPIP
	ipipFOU := exportLinkFixture("5", "10.80.53.0/31")
	ipipFOU.Backend, ipipFOU.Encapsulation = domain.BackendIPIP, domain.EncapFOU
	ipipGUE := exportLinkFixture("6", "10.80.54.0/31")
	ipipGUE.Backend, ipipGUE.Encapsulation = domain.BackendIPIP, domain.EncapGUE
	storeReadLinks(t, root, ipipNative, ipipFOU, ipipGUE)
	before, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	links := []domain.Link{first, second, ipipNative, ipipFOU, ipipGUE}
	for _, link := range links {
		code, out, stderr := runExport(t, root, "link", "export", string(link.ID), "--json")
		if code != 0 || stderr != "" || strings.Contains(out, "private_label") {
			t.Fatalf("failed or leaked explicit export: %d %q %q", code, out, stderr)
		}
		var response SetupLinkExport
		if err := json.Unmarshal([]byte(out), &response); err != nil {
			t.Fatal(err)
		}
		if response.SchemaVersion != jsonSchemaVersion || response.PairingSchemaVersion != pairing.SchemaVersion ||
			response.LinkID != link.ID || response.Backend != link.Backend ||
			response.Encapsulation != link.Encapsulation || response.Mode != pairing.ModeQuick ||
			response.HasCredential || response.Sensitive || !strings.HasPrefix(response.SetupLink, "stl://2.") {
			t.Fatalf("invalid versioned plaintext pairing export: %+v", response)
		}
		offer, err := pairing.DecodeSetupLink(response.SetupLink)
		if err != nil {
			t.Fatal(err)
		}
		receiver := offer.ReceiverLink()
		if receiver.ID != link.ID || receiver.Backend != link.Backend ||
			receiver.Addresses.Local != link.Addresses.Peer ||
			receiver.Addresses.Peer != link.Addresses.Local ||
			receiver.Underlay.Local != link.Underlay.Peer ||
			receiver.Underlay.Peer != link.Underlay.Local ||
			receiver.GRE != link.GRE {
			t.Fatalf("Setup Link does not recreate same peer/inverse/options: %+v", receiver)
		}
		if offer.IsSensitive() || len(offer.RecipientCredential()) != 0 {
			t.Fatal("plaintext backend unexpectedly included recipient credentials")
		}
		humanCode, human, errorsOut := runExport(t, root, "link", "export", string(link.ID))
		if humanCode != 0 || errorsOut != "" || !strings.Contains(human, "not encrypted") ||
			!strings.Contains(human, response.SetupLink) || !strings.Contains(human, string(link.ID)) ||
			!strings.Contains(human, "Receiver Link Address: "+link.Addresses.Peer.String()) {
			t.Fatalf("human block drifted from actual pairing model: %d %q %q", humanCode, human, errorsOut)
		}
	}
	after, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("read-only pairing export changed stored Links: %v", err)
	}
}

func TestCLIExportRejectsSecretBackendWithoutInventingKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := exportLinkFixture("3", "10.80.60.0/31")
	for _, tc := range []struct {
		kind  domain.Backend
		encap domain.Encapsulation
	}{
		{domain.BackendWireGuard, domain.EncapUDP},
		{domain.BackendIPsec, domain.EncapESP},
	} {
		link.Backend = tc.kind
		link.Encapsulation = tc.encap
		seedRestoreState(t, root, link)
		code, out, stderr := runExport(t, root, "link", "export", string(link.ID), "--json")
		if code != 4 || stderr != "" || strings.Contains(out, "private_label") ||
			strings.Contains(out, "setup_link") {
			t.Fatalf("unsupported backend returned fabricated/unsafe export: %s => %d %q %q",
				tc.kind, code, out, stderr)
		}
		var got linkReadErrorResponse
		if err := json.Unmarshal([]byte(out), &got); err != nil ||
			got.Error == nil || got.Error.Code != stlerr.CodeUnsupported {
			t.Fatalf("unsupported backend machine result wrong: %+v %v", got, err)
		}
	}
}

func TestCLIExportRequiresExistingCanonicalLinkAndNoRuntimeMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	tests := [][]string{
		{"link", "export", "lnk_bad", "--json"},
		{"link", "export", "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--json"},
		{"link", "export", "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--json", "--bogus"},
	}
	for _, args := range tests {
		code, out, stderr := runExport(t, root, args...)
		if code != 2 || stderr != "" || strings.Contains(out, "setup_link") {
			t.Fatalf("invalid export unexpectedly succeeded: %v %d %q %q", args, code, out, stderr)
		}
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only export created state directory: %v", err)
	}
}

func TestCLIExportNeverSerializesRawCorruptStateErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte("private_key=DO_NOT_EXPOSE"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runExport(t, root, "link", "export", "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--json")
	if code != 1 || stderr != "" || strings.Contains(out, "private_key") || strings.Contains(out, "DO_NOT_EXPOSE") {
		t.Fatalf("export leaked a corrupted state file: %d %q %q", code, out, stderr)
	}
}
