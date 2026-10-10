package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
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

func TestCredentialedImportRejectsUnregisteredBackendAndUnreviewedChangesWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	fake := newLifecycleFake()
	source, _ := makeLifecycleDesired(t, "d", "10.70.11.0/31")
	source.Backend, source.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	completeWireGuardFixture(t, &source, key)
	secretURL := testQuickSetupLink(t, source, []byte(key))

	code, previewJSON, errOut := runLifecycleTest(t, root, fake,
		[]string{"link", "preview", "--stdin", "--json"}, secretURL)
	var preview ImportPreviewResponse
	if err := json.Unmarshal([]byte(previewJSON), &preview); err != nil {
		t.Fatal(err)
	}
	if code != 0 || errOut != "" || preview.ImportConfirmation != setupLinkConfirmation(secretURL) || !preview.HasCredential ||
		strings.Contains(previewJSON, key) || strings.Contains(previewJSON, secretURL) {
		t.Fatalf("credentialed preview was not redacted: %d %q %q", code, previewJSON, errOut)
	}
	cases := []struct {
		name  string
		args  []string
		input string
		exit  int
	}{
		{"missing WireGuard backend", []string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(secretURL), "--json"}, secretURL, 4},
		{"wrong confirmation", []string{"link", "import", "--stdin", "--confirm", strings.Repeat("f", 64), "--json"}, secretURL, 2},
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

// A matching setup URL token authorizes only a new Link or re-ensure of
// identical saved intent. It never grants a silent right to replace another
// configuration that already owns the same stable Link ID.
func TestPlaintextImportRefusesExistingLinkReconfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := newLifecycleFake()
	original, _ := makeLifecycleDesired(t, "a", "10.70.14.0/31")
	sibling, _ := makeLifecycleDesired(t, "b", "10.70.15.0/31")
	for _, link := range []domain.Link{original, sibling} {
		url := testQuickSetupLink(t, link, nil)
		code, out, errOut := runLifecycleTest(t, root, fake,
			[]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(url), "--json"}, url)
		if code != 0 || errOut != "" {
			t.Fatalf("failed to import initial/sibling link: code=%d out=%q err=%q", code, out, errOut)
		}
	}
	before, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	priorApplies := len(fake.applies)

	greChanged := original
	greChanged.GRE.TOS = 12
	underlayChanged := original
	underlayChanged.Underlay.Peer = netip.MustParseAddr("192.0.2.35")
	nameChanged := original
	nameChanged.DisplayName = "UNTRUSTED_DIFFERENT_DISPLAY_NAME_DO_NOT_PRINT"
	backendChanged := original
	backendChanged.Backend = domain.BackendIPIP

	for _, tc := range []struct {
		name string
		link domain.Link
	}{
		{"different GRE options", greChanged},
		{"different underlay", underlayChanged},
		{"different display name", nameChanged},
		{"different backend", backendChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := testQuickSetupLink(t, tc.link, nil)
			token := setupLinkConfirmation(url)
			code, jsonOut, errOut := runLifecycleTest(t, root, fake,
				[]string{"link", "import", "--stdin", "--confirm", token, "--json"}, url)
			if code != 1 || errOut != "" {
				t.Fatalf("conflicting import not rejected: code=%d out=%q err=%q", code, jsonOut, errOut)
			}
			var response lifecycleFailureResponse
			if err := json.Unmarshal([]byte(jsonOut), &response); err != nil {
				t.Fatal(err)
			}
			if response.SchemaVersion != jsonSchemaVersion || response.Error == nil ||
				response.Error.Code != stlerr.CodeConflict || response.Error.Operation != "link_import" {
				t.Fatalf("conflict lost safe machine classification: %+v", response)
			}
			humanCode, humanOut, humanErr := runLifecycleTest(t, root, fake,
				[]string{"link", "import", "--stdin", "--confirm", token}, url)
			if humanCode != 1 || humanOut != "" || !strings.Contains(humanErr, "conflict") {
				t.Fatalf("human import did not surface conflict: code=%d out=%q err=%q", humanCode, humanOut, humanErr)
			}
			for _, raw := range []string{url, token, tc.link.DisplayName} {
				if strings.Contains(jsonOut+errOut+humanOut+humanErr, raw) {
					t.Fatal("conflict leaked untrusted payload or confirmation")
				}
			}
			after, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("conflict overwrote committed state/ownership: got=%+v err=%v", after, err)
			}
			if len(fake.applies) != priorApplies || !fake.present[original.ID] || !fake.present[sibling.ID] {
				t.Fatalf("conflict mutated existing backend or sibling: applies=%+v present=%+v", fake.applies, fake.present)
			}
		})
	}
}

type wireguardImportFake struct{ *lifecycleFakeBackend }

func (wireguardImportFake) Kind() domain.Backend { return domain.BackendWireGuard }

func (wireguardImportFake) DiagnosticState(_ context.Context, link domain.Link) (wireguard.DiagnosticState, error) {
	name, err := wireguard.InterfaceName(link.ID)
	if err != nil {
		return wireguard.DiagnosticState{}, err
	}
	return wireguard.DiagnosticState{Interface: name, IfIndex: 82, LocalPublicKey: link.WireGuard.LocalPublicKey,
		PeerPublicKey: link.WireGuard.PeerPublicKey, ListenPort: link.WireGuard.ListenPort,
		LatestHandshakeUnix: 1700000000, RXBytes: 128, TXBytes: 256}, nil
}

func TestWireGuardV3ImportProtectedIdempotentAndRedacted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &wireguardImportFake{newLifecycleFake()}
	source, _ := makeLifecycleDesired(t, "f", "10.71.80.0/31")
	source.Backend, source.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	receiverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	completeWireGuardFixture(t, &source, receiverKey)
	url := testQuickSetupLink(t, source, []byte(receiverKey))
	options := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}}
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runWithRuntimeInput(args, strings.NewReader(url), &out, &errOut, options)
		return code, out.String(), errOut.String()
	}
	code, previewJSON, stderr := run("link", "preview", "--stdin", "--json")
	var preview ImportPreviewResponse
	if err := json.Unmarshal([]byte(previewJSON), &preview); err != nil {
		t.Fatal(err)
	}
	if code != 0 || stderr != "" || preview.WireGuard == nil || !preview.Sensitive ||
		preview.ImportConfirmation != setupLinkConfirmation(url) ||
		*preview.WireGuard != pairing.Invert(source).WireGuard ||
		strings.Contains(previewJSON, receiverKey) || strings.Contains(previewJSON, url) {
		t.Fatalf("unsafe/incomplete WireGuard recipient preview: code=%d body=%s err=%s", code, previewJSON, stderr)
	}
	wrong, out, errOut := run("link", "import", "--stdin", "--confirm", strings.Repeat("0", 64), "--json")
	if wrong != 2 || errOut != "" || strings.Contains(out, url) || len(fake.applies) != 0 {
		t.Fatalf("unreviewed import changed state: %d %s %s", wrong, out, errOut)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview/unconfirmed import created credential storage: %v", err)
	}
	for round := 0; round < 2; round++ {
		code, out, errOut = run("link", "import", "--stdin", "--confirm", preview.ImportConfirmation, "--json")
		if code != 0 || errOut != "" || strings.Contains(out, receiverKey) || strings.Contains(out, url) {
			t.Fatalf("protected import %d failed or leaked: %d %q %q", round, code, out, errOut)
		}
		var result lifecycleResultResponse
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.Changed != (round == 0) || result.LinkID != source.ID {
			t.Fatalf("bad replay: %+v", result)
		}
	}
	if len(fake.applies) != 1 {
		t.Fatalf("replay reapplied WireGuard: %+v", fake.applies)
	}
	var statusOut, statusErr bytes.Buffer
	statusCode := runWithRuntimeInput([]string{"link", "status", string(source.ID), "--json"}, strings.NewReader(""), &statusOut, &statusErr, options)
	var status linkStatusResponse
	if err := json.Unmarshal(statusOut.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if statusCode != 0 || statusErr.Len() != 0 || !status.InterfaceVerified || status.Connectivity != "not_measured" ||
		status.WireGuardState == nil || status.WireGuardState.RXBytes != 128 ||
		status.GREState != nil || status.IPIPState != nil ||
		strings.Contains(statusOut.String(), receiverKey) || strings.Contains(statusOut.String(), url) {
		t.Fatalf("WireGuard status leaked or lost backend projection: code=%d status=%+v", statusCode, status)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := keys.Load(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if protected.SecretWireValue() != receiverKey {
		t.Fatal("receiver credential not provisioned exactly")
	}
	stat, err := os.Stat(filepath.Join(root, "credentials", string(source.ID)+".wgkey"))
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("credential permission mismatch: %v %v", stat, err)
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.Links) != 1 || snap.Links[0].Desired != pairing.Invert(source) {
		t.Fatalf("receiver Link commit mismatch: %+v %v", snap, err)
	}
	stateText, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateText, []byte(receiverKey)) || bytes.Contains(stateText, []byte(url)) {
		t.Fatal("receiver private key persisted in ordinary state")
	}

	changed := source
	changed.DisplayName = "attacker-controlled-metadata"
	alternate := testQuickSetupLink(t, changed, []byte(receiverKey))
	var out2, err2 bytes.Buffer
	code = runWithRuntimeInput([]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(alternate), "--json"}, strings.NewReader(alternate), &out2, &err2, options)
	if code != 1 || len(fake.applies) != 1 || strings.Contains(out2.String()+err2.String(), alternate) {
		t.Fatalf("reconfiguration accepted/leaked: %d", code)
	}
	updated, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || updated.Links[0].Desired != pairing.Invert(source) {
		t.Fatal("rejected import mutated committed Link")
	}
}

func TestWireGuardImportFailedActivationKeepsRetryableCredential(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &wireguardImportFake{newLifecycleFake()}
	fake.failApply = true
	source, _ := makeLifecycleDesired(t, "a", "10.71.82.0/31")
	source.Backend, source.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	completeWireGuardFixture(t, &source, secret)
	url := testQuickSetupLink(t, source, []byte(secret))
	options := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}}
	invoke := func() (int, string) {
		var out, errOut bytes.Buffer
		code := runWithRuntimeInput([]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(url), "--json"}, strings.NewReader(url), &out, &errOut, options)
		if errOut.Len() != 0 {
			t.Fatalf("unsafe error channel: %s", errOut.String())
		}
		return code, out.String()
	}
	code, body := invoke()
	if code != 1 || strings.Contains(body, secret) || strings.Contains(body, url) {
		t.Fatalf("failed import leaked or succeeded: %d %s", code, body)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(source.ID); err != nil {
		t.Fatalf("failed apply lost credential required for reconciliation: %v", err)
	}
	fake.failApply = false
	code, body = invoke()
	if code != 0 || strings.Contains(body, secret) {
		t.Fatalf("idempotent recovery failed: %d %s", code, body)
	}
}
