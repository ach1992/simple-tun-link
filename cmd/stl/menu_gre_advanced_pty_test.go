package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Drive the actual Linux PTY through Advanced GRE and the canonical Engine.
// A custom key/port must survive state, Setup Link, inversion and confirmed
// offline Import; no dummy preview-only acceptance is sufficient.
func TestAdvancedGREFOUGUERealPTYCustomBoundaryAndConfirmedPeerImport(t *testing.T) {
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "1")
	for _, tc := range []struct {
		name, advancedChoice, invalidKey, key, invalidTTL, ttl, invalidTOS, tos string
		disablePMTU, checksum, sequence                                         bool
		invalidPort, port                                                       string
		expectedKey                                                             uint32
		expectedTTL, expectedTOS                                                uint8
	}{
		{name: "FOU", advancedChoice: "1", invalidKey: "4294967296", key: "0",
			invalidTTL: "256", ttl: "64", invalidTOS: "256", tos: "255", checksum: true, sequence: true,
			invalidPort: "0", port: "1", expectedKey: 0, expectedTTL: 64, expectedTOS: 255},
		{name: "GUE", advancedChoice: "2", invalidKey: "-1", key: "4294967295",
			invalidTTL: "256", ttl: "", invalidTOS: "-1", tos: "0", disablePMTU: true, sequence: true,
			invalidPort: "65536", port: "65535", expectedKey: 4294967295, expectedTTL: 0, expectedTOS: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "creator")
			fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
			master, slave := openMenuPTY(t)
			done := make(chan int, 1)
			go func() { done <- runWithRuntimeInput([]string{"menu"}, slave, slave, slave, opts) }()
			send := func(marker, answer string) string {
				t.Helper()
				output := readMenuPTYUntil(t, master, marker)
				if _, err := io.WriteString(master, answer+"\n"); err != nil {
					t.Fatal(err)
				}
				return output
			}
			send("Choose a task: ", "1")
			send("Tunnel type [1]: ", "5")
			send("Choose a type: ", tc.advancedChoice)
			send("Other server's IPv4 address (peer may be offline", "192.0.2.20")
			send("Tunnel IP on THIS server", "")
			send("Change advanced settings", "y")
			send("GRE key (Enter=keep generated key", tc.invalidKey)
			if retry := send("Enter an unsigned GRE receive key", tc.key); !strings.Contains(retry, "4294967295") {
				t.Fatalf("invalid GRE key accepted: %q", retry)
			}
			send("GRE TTL (Enter=automatic", tc.invalidTTL)
			send("GRE TTL must be an integer", tc.ttl)
			send("GRE TOS (Enter=default", tc.invalidTOS)
			send("GRE TOS must be an integer", tc.tos)
			if tc.expectedTTL == 0 {
				if tc.disablePMTU {
					send("Disable GRE PMTU discovery", "y")
				} else {
					send("Disable GRE PMTU discovery", "n")
				}
			}
			if tc.checksum {
				send("Enable GRE checksum", "y")
			} else {
				send("Enable GRE checksum", "n")
			}
			if tc.sequence {
				send("Enable GRE sequence numbers", "y")
			} else {
				send("Enable GRE sequence numbers", "n")
			}
			send("UDP receive port [", tc.invalidPort)
			send("Use a port number between 1 and 65535", tc.port)
			send("MTU on THIS server", "1")
			review := send("Create this tunnel now?", "YES")
			for _, needed := range []string{"GRE receive key", tc.key, tc.port, "GRE TTL / TOS", "GRE PMTU / checksum / sequence"} {
				if !strings.Contains(review, needed) {
					t.Fatalf("advanced review missing %q: %q", needed, review)
				}
			}
			handoff := send("Has the OTHER server already imported", "n")
			url := regexp.MustCompile(`stl://[^[:space:]]+`).FindString(handoff)
			if url == "" {
				t.Fatalf("PTY Create omitted peer Setup Link: %q", handoff)
			}
			send("Press Enter to continue", "")
			send("Choose a task: ", "8")
			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("PTY menu returned %d", code)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("PTY menu did not exit")
			}
			if len(fake.applies) != 1 {
				t.Fatalf("GRE Create was not applied exactly once: %v", fake.applies)
			}
			snapshot, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || len(snapshot.Links) != 1 {
				t.Fatalf("no creator Link: %+v %v", snapshot, err)
			}
			actual := snapshot.Links[0].Desired
			mode := domain.EncapFOU
			if tc.name == "GUE" {
				mode = domain.EncapGUE
			}
			expectedPort := uint16(1)
			if tc.name == "GUE" {
				expectedPort = 65535
			}
			if actual.Backend != domain.BackendGRE || actual.Encapsulation != mode || !actual.GRE.KeyEnabled || actual.GRE.Key != tc.expectedKey ||
				actual.GRE.TTL != tc.expectedTTL || actual.GRE.TOS != tc.expectedTOS || actual.GRE.UDPPort != expectedPort ||
				actual.GRE.DisablePMTUD != tc.disablePMTU || actual.GRE.Checksum != tc.checksum || actual.GRE.Sequence != tc.sequence {
				t.Fatalf("PTY custom GRE intent lost: %+v", actual)
			}
			offer, err := pairing.DecodeSetupLink(url)
			if err != nil || offer.Link().ID != actual.ID || offer.Link().Underlay != actual.Underlay ||
				offer.Link().Addresses != actual.Addresses || offer.Link().GRE != actual.GRE ||
				offer.ReceiverLink().GRE != actual.GRE {
				t.Fatalf("PTY custom GRE offer/pair mismatch: %v", err)
			}
			peerRoot := filepath.Join(t.TempDir(), "peer")
			peerFake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			peerOpts := guidedTestOptions(peerRoot, &guidedTestRunner{}, peerFake)
			peerOpts.probeRunner = &greReceiverProbe{inventory: greReceiverInventory("eth0", offer.ReceiverLink().Underlay.Local.String())}
			var stdout, stderr bytes.Buffer
			exit := runWithRuntimeInput([]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(url), "--json"}, strings.NewReader(url), &stdout, &stderr, peerOpts)
			if exit != 0 || len(peerFake.applies) != 1 || stderr.Len() != 0 {
				t.Fatalf("peer Import: exit=%d out=%q err=%q", exit, stdout.String(), stderr.String())
			}
			peerState, err := state.NewFileStore(peerRoot).Load(context.Background())
			if err != nil || len(peerState.Links) != 1 || peerState.Links[0].Desired != offer.ReceiverLink() {
				t.Fatalf("peer inversion lost port/key/flags: %+v %v", peerState, err)
			}
		})
	}
}

func TestAdvancedGREFOUGUECancelAtCustomReceivePortNeverMutatesHost(t *testing.T) {
	for _, selected := range []string{"1", "2"} {
		t.Run(selected, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "absent")
			fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			script := "1\n5\n" + selected + "\n192.0.2.20\n\ny\n0\n\n\nn\nn\nn\nq\n8\n"
			code, out, errText := runGuidedTest(guidedTestOptions(root, &guidedTestRunner{}, fake), script)
			if code != 0 || len(fake.applies) != 0 || !strings.Contains(out, "UDP receive port") || errText != "" {
				t.Fatalf("GRE UDP port cancel caused effects or lost prompt: code=%d applies=%d err=%q out=%q", code, len(fake.applies), errText, out)
			}
			snapshot, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || len(snapshot.Links) != 0 {
				t.Fatalf("cancelled GRE port has saved Link(s): %+v %v", snapshot, err)
			}
		})
	}
}
