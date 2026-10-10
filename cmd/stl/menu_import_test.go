package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func runMenuImportTest(t *testing.T, root string, backends []backend.Backend, transcript string) (int, string, string) {
	t.Helper()
	var output, errorsOut bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(transcript),
		&output, &errorsOut, &runtimeOptions{stateRoot: root, backends: backends})
	return code, output.String(), errorsOut.String()
}

func TestMenuImportConfirmedGREAndIdempotency(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := newLifecycleFake()
	source, _ := makeLifecycleDesired(t, "a", "10.70.91.0/31")
	source.Encapsulation = domain.EncapFOU
	source.GRE = domain.GREOptions{KeyEnabled: true, Key: 0, UDPPort: 35555, TOS: 12}
	url := testQuickSetupLink(t, source, nil)
	input := "2\n" + url + "\n" + string(source.ID) + "\n" +
		"2\n" + url + "\n" + string(source.ID) + "\n8\n"
	code, output, errOut := runMenuImportTest(t, root, []backend.Backend{fake}, input)
	if code != 0 || errOut != "" {
		t.Fatalf("menu import failed: code=%d output=%q errors=%q", code, output, errOut)
	}
	for _, item := range []string{
		"PREVIEW ONLY", string(source.ID), "Receiver underlay", "GRE:",
		"udp_port=35555", "key_enabled=true", "peer-authenticated",
		"changes applied and verified", "already matches desired state",
	} {
		if !strings.Contains(output, item) {
			t.Fatalf("menu omitted necessary review or result %q", item)
		}
	}
	for _, forbidden := range []string{url, source.DisplayName, setupLinkConfirmation(url)} {
		if strings.Contains(output+errOut, forbidden) {
			t.Fatal("menu leaked setup URL, confirmation digest or untrusted display name")
		}
	}
	if len(fake.applies) != 1 {
		t.Fatalf("repeated confirmed import reapplied backend: %+v", fake.applies)
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 || snapshot.Links[0].Desired != pairing.Invert(source) ||
		len(snapshot.Links[0].OwnedResources) == 0 {
		t.Fatalf("canonical Engine did not persist owned receiver Link: %+v %v", snapshot, err)
	}
}

func TestMenuImportCancelledDoesNotMutateOrRevealOffer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "no-state")
	fake := newLifecycleFake()
	source, _ := makeLifecycleDesired(t, "b", "10.70.93.0/31")
	url := testQuickSetupLink(t, source, nil)
	for _, confirmation := range []string{"", "another-link", string(source.ID) + "bad"} {
		code, out, errOut := runMenuImportTest(t, root, []backend.Backend{fake},
			"2\n"+url+"\n"+confirmation+"\n8\n")
		if code != 0 || errOut != "" || !strings.Contains(out, "Import cancelled") ||
			strings.Contains(out+errOut, url) || strings.Contains(out+errOut, source.DisplayName) {
			t.Fatalf("cancelled import did not fail closed: code=%d out=%q err=%q", code, out, errOut)
		}
	}
	if len(fake.applies) != 0 {
		t.Fatal("unconfirmed menu selection applied backend")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled menu created local state: %v", err)
	}
}

func TestMenuImportRejectsOversizeAndMalformedWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "no-state")
	fake := newLifecycleFake()
	for _, badURL := range []string{strings.Repeat("SENSITIVE_BAD", pairing.MaxLinkBytes/10), "not-a-setup-link"} {
		code, out, errOut := runMenuImportTest(t, root, []backend.Backend{fake}, "2\n"+badURL+"\n8\n")
		if code != 2 || errOut == "" || strings.Contains(out+errOut, badURL) || len(fake.applies) != 0 {
			t.Fatalf("bad import was not rejected before backend: code=%d err=%q", code, errOut)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("bad input created state root: %v", err)
		}
	}
}

func TestMenuImportCredentialedQuickLinkIsRedactedAndCannotApply(t *testing.T) {
	root := filepath.Join(t.TempDir(), "no-state")
	fake := newLifecycleFake()
	link, _ := makeLifecycleDesired(t, "c", "10.70.95.0/31")
	link.Backend, link.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	completeWireGuardFixture(t, &link, key)
	url := testQuickSetupLink(t, link, []byte(key))
	code, output, errOut := runMenuImportTest(t, root, []backend.Backend{fake},
		"2\n"+url+"\n8\n")
	if code != 0 || errOut != "" || !strings.Contains(output, "SENSITIVE") ||
		!strings.Contains(output, "Protected credential import is not available") {
		t.Fatalf("credentialed input was not safely declined: code=%d err=%q", code, errOut)
	}
	for _, forbidden := range []string{url, key, link.DisplayName, setupLinkConfirmation(url)} {
		if strings.Contains(output+errOut, forbidden) {
			t.Fatal("secret-bearing payload appeared in menu output")
		}
	}
	if len(fake.applies) != 0 {
		t.Fatal("secret-bearing Quick Link applied without protected importer")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret-bearing preview created persisted state: %v", err)
	}
}

func TestMenuImportConflictDoesNotReconfigureExistingLink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := newLifecycleFake()
	source, _ := makeLifecycleDesired(t, "d", "10.70.97.0/31")
	original := testQuickSetupLink(t, source, nil)
	code, _, errOut := runMenuImportTest(t, root, []backend.Backend{fake},
		"2\n"+original+"\n"+string(source.ID)+"\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("initial menu import failed: %d %q", code, errOut)
	}
	before, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changed := source
	changed.GRE.TOS = 14
	different := testQuickSetupLink(t, changed, nil)
	code, output, errOut := runMenuImportTest(t, root, []backend.Backend{fake},
		"2\n"+different+"\n"+string(source.ID)+"\n")
	if code != 1 || !strings.Contains(errOut, "conflict") ||
		strings.Contains(output+errOut, different) || strings.Contains(output+errOut, source.DisplayName) {
		t.Fatalf("conflicting menu import was not safe: %d %q %q", code, output, errOut)
	}
	after, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) || len(fake.applies) != 1 {
		t.Fatal("conflict changed saved intent or backend ownership")
	}
}

func TestMenuImportIPIPUsesExistingImporter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &ipipImportFake{newLifecycleFake()}
	source, _ := makeLifecycleDesired(t, "e", "10.70.99.0/31")
	source.Backend, source.Encapsulation = domain.BackendIPIP, domain.EncapGUE
	url := testQuickSetupLink(t, source, nil)
	code, _, errOut := runMenuImportTest(t, root, []backend.Backend{fake},
		"2\n"+url+"\n"+string(source.ID)+"\n8\n")
	if code != 0 || errOut != "" || !fake.present[source.ID] {
		t.Fatalf("IPIP menu import did not delegate to canonical import: code=%d err=%q", code, errOut)
	}
}

func TestMenuURLConsumesOneBoundedLineWithoutWaitingForEOF(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("setup\r\nnext\n"))
	encoded, err := readMenuURL(reader)
	if err != nil || encoded != "setup" {
		t.Fatalf("bounded line normalization: %q %v", encoded, err)
	}
	next, err := readMenuURL(reader)
	if err != nil || next != "next" {
		t.Fatalf("line reader unexpectedly consumed next menu choice: %q %v", next, err)
	}
}
