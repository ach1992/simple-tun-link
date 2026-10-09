package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func fixtureReadLink(id string, local, peer string, backendKind domain.Backend) domain.Link {
	return domain.Link{
		ID: domain.LinkID(id), DisplayName: "private_key=DO_NOT_EXPOSE_OR_LOG",
		Backend: backendKind, Encapsulation: domain.EncapNative,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.1"), Peer: netip.MustParseAddr("192.0.2.2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix(local), Peer: netip.MustParsePrefix(peer)},
	}
}

func storeReadLinks(t *testing.T, root string, links ...domain.Link) {
	t.Helper()
	if err := state.NewFileStore(root).Update(context.Background(), func(snapshot *state.Snapshot) error {
		for _, link := range links {
			snapshot.Upsert(state.LinkRecord{Desired: link})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func readCLI(t *testing.T, root string, backends []backend.Backend, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWithRuntime(args, &stdout, &stderr, &runtimeOptions{stateRoot: root, backends: backends})
	return code, stdout.String(), stderr.String()
}

type readTestBackend struct {
	backend.Backend
	state grebackend.DiagnosticState
	err   error
	calls int
}

func (*readTestBackend) Kind() domain.Backend { return domain.BackendGRE }

func (b *readTestBackend) DiagnosticState(_ context.Context, link domain.Link) (grebackend.DiagnosticState, error) {
	b.calls++
	if b.err != nil {
		return grebackend.DiagnosticState{}, b.err
	}
	return b.state, nil
}

func TestLinkListReportsConfiguredMultipleLinksWithoutSecrets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	first := fixtureReadLink("lnk_11111111111111111111111111111111", "10.80.20.0/31", "10.80.20.1/31", domain.BackendGRE)
	second := fixtureReadLink("lnk_22222222222222222222222222222222", "10.80.30.0/31", "10.80.30.1/31", domain.BackendIPIP)
	storeReadLinks(t, root, second, first)
	code, stdout, stderr := readCLI(t, root, nil, "link", "list", "--json")
	if code != 0 || stderr != "" || strings.Contains(stdout, "private_key") || strings.Contains(stdout, "DO_NOT_EXPOSE") {
		t.Fatalf("leaked desired state or failed list: code=%d output=%q error=%q", code, stdout, stderr)
	}
	var payload linkListResponse
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != jsonSchemaVersion || len(payload.Links) != 2 || payload.Links[0].ID != first.ID ||
		payload.Links[1].ID != second.ID || payload.Links[0].LocalAddress != first.Addresses.Local.String() {
		t.Fatalf("incorrect ordered list: %+v", payload)
	}
	code, stdout, stderr = readCLI(t, root, nil, "link", "list")
	if code != 0 || stderr != "" || strings.Contains(stdout, "private_key") ||
		!strings.Contains(stdout, "Configured Links (not a live connectivity check)") {
		t.Fatalf("unsafe list human output: code=%d output=%q err=%q", code, stdout, stderr)
	}
}

func TestLinkListEmptyDoesNotCreateStateDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "no-state")
	code, stdout, stderr := readCLI(t, root, nil, "link", "list", "--json")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "\"links\":[]") {
		t.Fatalf("empty state list: %d %q %q", code, stdout, stderr)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only command created state dir: %v", err)
	}
}

func TestLinkStatusProvesLiveGREBeforeClaimingOperational(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_33333333333333333333333333333333", "10.80.40.0/31", "10.80.40.1/31", domain.BackendGRE)
	storeReadLinks(t, root, link)
	name, _ := grebackend.InterfaceName(link.ID)
	inspector := &readTestBackend{state: grebackend.DiagnosticState{
		Interface: name, IfIndex: 77, Encapsulation: domain.EncapNative, RXPackets: 5, TXPackets: 6,
	}}
	code, stdout, stderr := readCLI(t, root, []backend.Backend{inspector}, "link", "status", string(link.ID), "--json")
	if code != 0 || stderr != "" || inspector.calls != 1 || strings.Contains(stdout, "private_key") {
		t.Fatalf("failed or leaked live status: code=%d stdout=%q stderr=%q calls=%d", code, stdout, stderr, inspector.calls)
	}
	var got linkStatusResponse
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || !got.InterfaceVerified || got.Link.ID != link.ID || got.GREState == nil ||
		got.GREState.Interface != name || got.GREState.TXPackets != 6 || got.Connectivity != "not_measured" {
		t.Fatalf("unverified operational claim: %+v", got)
	}
	code, stdout, stderr = readCLI(t, root, []backend.Backend{inspector}, "link", "status", string(link.ID))
	if code != 0 || stderr != "" || !strings.Contains(stdout, "connectivity not measured") || strings.Contains(stdout, "private_key") {
		t.Fatalf("bad human status: %d %q %q", code, stdout, stderr)
	}
}

func TestLinkStatusUnavailableIsNonzeroAndSecretSafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_44444444444444444444444444444444", "10.80.50.0/31", "10.80.50.1/31", domain.BackendGRE)
	storeReadLinks(t, root, link)
	inspector := &readTestBackend{err: errors.New("private_key=DO_NOT_EXPOSE_OR_LOG")}
	code, stdout, stderr := readCLI(t, root, []backend.Backend{inspector}, "link", "status", string(link.ID), "--json")
	if code != 1 || stderr != "" || strings.Contains(stdout, "private_key") || strings.Contains(stdout, "DO_NOT_EXPOSE") {
		t.Fatalf("error path leaked or silently passed: %d %q %q", code, stdout, stderr)
	}
	var got linkReadErrorResponse
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.Error.Code != stlerr.CodeInspect || got.Error.Detail == "" {
		t.Fatalf("unstructured status failure: %+v", got)
	}
}

func TestLinkReadInvalidAndUnsupportedAreNotFalseSuccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_55555555555555555555555555555555", "10.80.60.0/31", "10.80.60.1/31", domain.BackendIPIP)
	storeReadLinks(t, root, link)
	for _, tc := range []struct {
		args     []string
		code     int
		category stlerr.Code
	}{
		{[]string{"link", "status", string(link.ID), "--json"}, 4, stlerr.CodeUnsupported},
		{[]string{"link", "status", "lnk_invalid", "--json"}, 2, stlerr.CodeInvalid},
		{[]string{"link", "status", "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--json"}, 2, stlerr.CodeInvalid},
		{[]string{"link", "list", "bad", "--json"}, 2, stlerr.CodeInvalid},
		{[]string{"link", "status", "--json"}, 2, stlerr.CodeInvalid},
	} {
		code, stdout, stderr := readCLI(t, root, nil, tc.args...)
		if code != tc.code || stderr != "" || strings.Contains(stdout, "private_key") {
			t.Fatalf("bad status error code/safety: args=%v code=%d out=%q err=%q", tc.args, code, stdout, stderr)
		}
		if strings.HasSuffix(strings.Join(tc.args, " "), "--json") && len(tc.args) >= 3 && tc.args[len(tc.args)-1] == "--json" {
			var payload linkReadErrorResponse
			if json.Unmarshal([]byte(stdout), &payload) != nil || payload.SchemaVersion != 1 ||
				payload.Error == nil || payload.Error.Code != tc.category {
				t.Fatalf("bad JSON error schema: %q", stdout)
			}
		}
	}
}

func TestLinkListUnreadableStateDoesNotExposeRawBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte("private_key=DO_NOT_EXPOSE"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := readCLI(t, root, nil, "link", "list", "--json")
	if code != 1 || stderr != "" || strings.Contains(stdout, "private_key") {
		t.Fatalf("corrupted state error leaked raw content: %d %q %q", code, stdout, stderr)
	}
}

func TestLinkStatusRejectsInconsistentBackendIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_66666666666666666666666666666666", "10.80.70.0/31", "10.80.70.1/31", domain.BackendGRE)
	storeReadLinks(t, root, link)
	name, _ := grebackend.InterfaceName(link.ID)
	for _, tc := range []struct {
		name   string
		mutate func(*grebackend.DiagnosticState)
	}{
		{"foreign interface", func(s *grebackend.DiagnosticState) { s.Interface = "foreign0" }},
		{"missing ifindex", func(s *grebackend.DiagnosticState) { s.IfIndex = 0 }},
		{"wrong encapsulation", func(s *grebackend.DiagnosticState) { s.Encapsulation = domain.EncapGUE }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := grebackend.DiagnosticState{Interface: name, IfIndex: 77, Encapsulation: domain.EncapNative}
			tc.mutate(&observed)
			inspector := &readTestBackend{state: observed}
			code, stdout, stderr := readCLI(t, root, []backend.Backend{inspector}, "link", "status", string(link.ID), "--json")
			if code != 1 || stderr != "" || strings.Contains(stdout, "interface_verified") && strings.Contains(stdout, "true") {
				t.Fatalf("trusted mismatched backend: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			var response linkReadErrorResponse
			if err := json.Unmarshal([]byte(stdout), &response); err != nil ||
				response.Error == nil || response.Error.Code != stlerr.CodeInspect {
				t.Fatalf("mismatched identity was not a structured inspection error: %q %v", stdout, err)
			}
		})
	}
}
