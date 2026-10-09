package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func testQuickSetupLink(t *testing.T, link domain.Link, credential []byte) string {
	t.Helper()
	offer, err := pairing.NewQuickOffer(link, credential)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPlaintextImportRequiresExactPreviewAndUsesOwnedEngine(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := newLifecycleFake()
	source, _ := makeLifecycleDesired(t, "a", "10.70.8.0/31")
	source.Encapsulation = domain.EncapFOU
	source.GRE = domain.GREOptions{KeyEnabled: true, Key: 0, UDPPort: 35555, TOS: 12}
	encoded := testQuickSetupLink(t, source, nil)

	code, out, errOut := runLifecycleTest(t, root, fake, []string{"link", "preview", "--stdin", "--json"}, encoded+"\r\n")
	if code != 0 || errOut != "" {
		t.Fatalf("preview failed: code=%d output=%q stderr=%q", code, out, errOut)
	}
	var preview ImportPreviewResponse
	if err := json.Unmarshal([]byte(out), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SchemaVersion != jsonSchemaVersion ||
		preview.ImportConfirmation != setupLinkConfirmation(encoded) ||
		preview.LinkID != source.ID || preview.HasCredential ||
		preview.GRE == nil || *preview.GRE != source.GRE ||
		preview.LocalUnderlay != source.Underlay.Peer.String() {
		t.Fatalf("unsafe or wrong receiver preview: %+v", preview)
	}
	if strings.Contains(out, encoded) || strings.Contains(out, source.DisplayName) {
		t.Fatal("preview leaked setup URL or arbitrary display name")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only preview created a state root: %v", err)
	}

	incorrect := strings.Repeat("0", 64)
	code, out, errOut = runLifecycleTest(t, root, fake,
		[]string{"link", "import", "--stdin", "--confirm", incorrect, "--json"}, encoded)
	if code != 2 || !strings.Contains(out, "invalid") || errOut != "" || len(fake.applies) != 0 {
		t.Fatalf("wrong preview token changed execution: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfirmed import created a state root: %v", err)
	}

	args := []string{"link", "import", "--stdin", "--confirm", preview.ImportConfirmation, "--json"}
	for n := range 2 {
		code, out, errOut = runLifecycleTest(t, root, fake, args, encoded+"\n")
		if code != 0 || errOut != "" || strings.Contains(out, source.DisplayName) ||
			strings.Contains(out, encoded) {
			t.Fatalf("import[%d] unsafe outcome: code=%d output=%q stderr=%q", n, code, out, errOut)
		}
		var result lifecycleResultResponse
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.SchemaVersion != jsonSchemaVersion || result.Operation != "link_import" ||
			result.LinkID != source.ID || result.Removed || result.Changed != (n == 0) {
			t.Fatalf("import[%d] incorrect idempotency: %+v", n, result)
		}
	}
	if len(fake.applies) != 1 {
		t.Fatalf("idempotent import unexpectedly reapplied: %+v", fake.applies)
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 {
		t.Fatalf("import did not commit one Link: %+v %v", snapshot, err)
	}
	if got, want := snapshot.Links[0].Desired, pairing.Invert(source); got != want {
		t.Fatalf("recipient link differed from central inversion: got=%+v want=%+v", got, want)
	}
	if len(snapshot.Links[0].OwnedResources) == 0 {
		t.Fatal("import did not use the resource-owning canonical Engine")
	}

	sibling, _ := makeLifecycleDesired(t, "b", "10.70.9.0/31")
	siblingURL := testQuickSetupLink(t, sibling, nil)
	code, _, errOut = runLifecycleTest(t, root, fake,
		[]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(siblingURL)},
		siblingURL)
	if code != 0 || errOut != "" {
		t.Fatalf("same-peer sibling import failed: %d %s", code, errOut)
	}
	code, _, errOut = runLifecycleTest(t, root, fake,
		[]string{"link", "remove", string(source.ID), "--confirm", string(source.ID)}, "")
	if code != 0 || errOut != "" || fake.present[source.ID] || !fake.present[sibling.ID] {
		t.Fatalf("removed or disturbed wrong same-peer Link: %d %s %+v", code, errOut, fake.present)
	}
}

type ipipImportFake struct{ *lifecycleFakeBackend }

func (ipipImportFake) Kind() domain.Backend { return domain.BackendIPIP }

func TestPlaintextIPIPImportAllEncapsulations(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			source, _ := makeLifecycleDesired(t, "c", "10.70.10.0/31")
			source.Backend, source.Encapsulation = domain.BackendIPIP, encap
			encoded := testQuickSetupLink(t, source, nil)
			fake := &ipipImportFake{newLifecycleFake()}
			options := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}}
			var out, errOut bytes.Buffer
			code := runWithRuntimeInput(
				[]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(encoded), "--json"},
				strings.NewReader(encoded), &out, &errOut, options,
			)
			if code != 0 || errOut.Len() > 0 {
				t.Fatalf("IPIP %s import failed: code=%d stdout=%q stderr=%q", encap, code, out.String(), errOut.String())
			}
			snap, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || len(snap.Links) != 1 || snap.Links[0].Desired != pairing.Invert(source) {
				t.Fatalf("IPIP %s recipient/commit mismatch: %+v %v", encap, snap, err)
			}
		})
	}
}

func TestPlaintextImportRejectsSecretsAndUnreviewedChangesWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	fake := newLifecycleFake()
	source, _ := makeLifecycleDesired(t, "d", "10.70.11.0/31")
	source.Backend, source.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	secretURL := testQuickSetupLink(t, source, []byte(key))

	code, previewJSON, errOut := runLifecycleTest(t, root, fake,
		[]string{"link", "preview", "--stdin", "--json"}, secretURL)
	var preview ImportPreviewResponse
	if err := json.Unmarshal([]byte(previewJSON), &preview); err != nil {
		t.Fatal(err)
	}
	if code != 0 || errOut != "" || preview.ImportConfirmation != "" || !preview.HasCredential ||
		strings.Contains(previewJSON, key) || strings.Contains(previewJSON, secretURL) {
		t.Fatalf("credentialed preview was not redacted: %d %q %q", code, previewJSON, errOut)
	}
	cases := []struct {
		name  string
		args  []string
		input string
		exit  int
	}{
		{"secret rejected", []string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(secretURL), "--json"}, secretURL, 4},
		{"wrong confirmation", []string{"link", "import", "--stdin", "--confirm", strings.Repeat("f", 64), "--json"}, secretURL, 4},
		{"invalid confirmation shape", []string{"link", "import", "--stdin", "--confirm", "not-a-token", "--json"}, secretURL, 2},
		{"oversize", []string{"link", "import", "--stdin", "--confirm", strings.Repeat("0", 64), "--json"}, strings.Repeat("X", pairing.MaxLinkBytes+2), 2},
		{"missing confirmation", []string{"link", "import", "--stdin", "--json"}, secretURL, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, out, errOut := runLifecycleTest(t, root, fake, tc.args, tc.input)
			if c != tc.exit || errOut != "" || len(fake.applies) != 0 {
				t.Fatalf("unsafe preflight: exit=%d stdout=%q stderr=%q", c, out, errOut)
			}
			for _, value := range []string{key, secretURL, source.DisplayName} {
				if strings.Contains(out+errOut, value) {
					t.Fatalf("secret or untrusted payload escaped to ordinary output")
				}
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe rejected import created state: %v", err)
			}
		})
	}
}

func TestPlaintextImportEngineFailureIsUnconfirmedAndRedacted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := newLifecycleFake()
	fake.failApply = true
	source, _ := makeLifecycleDesired(t, "e", "10.70.12.0/31")
	encoded := testQuickSetupLink(t, source, nil)
	code, out, errOut := runLifecycleTest(t, root, fake,
		[]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(encoded), "--json"},
		encoded)
	if code != 1 || errOut != "" {
		t.Fatalf("failed engine reported success/printed stderr: %d %q %q", code, out, errOut)
	}
	var result lifecycleFailureResponse
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != jsonSchemaVersion || !result.ReconciliationRequired ||
		result.Outcome != "unconfirmed" || result.Error == nil ||
		result.Error.Operation != "link_import" {
		t.Fatalf("failure did not preserve reconciliation contract: %+v", result)
	}
	for _, value := range []string{"VERY_SECRET_NOT_FOR_OUTPUT", source.DisplayName, encoded} {
		if strings.Contains(out, value) {
			t.Fatal("failed import leaked backend or untrusted payload")
		}
	}
}
