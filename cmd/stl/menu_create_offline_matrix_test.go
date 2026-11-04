package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestAllPlainGuidedCreateWithOfflinePeerAndManualLocalEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, choice string
		kind         domain.Backend
		encap        domain.Encapsulation
	}{
		{"gre-native", "1", domain.BackendGRE, domain.EncapNative},
		{"gre-fou", "5\n1", domain.BackendGRE, domain.EncapFOU},
		{"gre-gue", "5\n2", domain.BackendGRE, domain.EncapGUE},
		{"ipip-native", "3", domain.BackendIPIP, domain.EncapNative},
		{"ipip-fou", "5\n3", domain.BackendIPIP, domain.EncapFOU},
		{"ipip-gue", "5\n4", domain.BackendIPIP, domain.EncapGUE},
		{"l2tpv3", "8", domain.BackendL2TPv3, domain.EncapNative},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			fake := newLifecycleFake()
			runner := &guidedTestRunner{routeFailAll: true}
			var selected backend.Backend
			var probe linux.Runner = runner
			switch tc.kind {
			case domain.BackendGRE:
				selected = &guidedTestBackend{lifecycleFakeBackend: fake}
			case domain.BackendIPIP:
				selected = &ipipImportFake{lifecycleFakeBackend: fake}
			case domain.BackendL2TPv3:
				selected = &guidedL2TPv3Backend{lifecycleFakeBackend: fake}
				probe = &guidedL2TPv3Runner{guidedTestRunner: runner}
			}
			opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{selected}, probeRunner: probe,
				packagePreview: readyGuidedPackagePreview, mtuManager: guidedMTUFake{},
				moduleObserve: func(context.Context, string) linux.KernelModuleState { return linux.KernelModuleLoaded },
				createLinkID:  func() (domain.LinkID, error) { return createTestID, nil }}
			// default proposed /31, default advanced, then freshly confirmed local
			// Ensure. With no route to the peer, choose a locally assigned IP and
			// accept the detected device. No pre-creation ping or handshake.
			script := "1\n" + tc.choice + "\n192.0.2.20\n192.0.2.10\n\n\nn\nYES\nn\n8\n"
			if tc.kind == domain.BackendIPIP {
				script = "1\n" + tc.choice + "\n192.0.2.20\n192.0.2.10\n\n\nn\nYES\n8\n"
			}
			code, out, errText := runGuidedTest(opts, script)
			if code != 0 || len(fake.applies) != 1 {
				t.Fatalf("offline guided Create failed: exit=%d mutations=%d err=%q output=%q", code, len(fake.applies), errText, out)
			}
			saved, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || len(saved.Links) != 1 {
				t.Fatalf("offline local Link not committed: %v %+v", err, saved)
			}
			desired := saved.Links[0].Desired
			if desired.Backend != tc.kind || desired.Encapsulation != tc.encap || desired.Underlay.Local != netip.MustParseAddr("192.0.2.10") || desired.Underlay.Peer != netip.MustParseAddr("192.0.2.20") {
				t.Fatalf("wrong offline saved intent: %+v", desired)
			}
			encoded := regexp.MustCompile(`stl://[^[:space:]]+`).FindString(out)
			offer, err := pairing.DecodeSetupLink(encoded)
			if err != nil || offer.ReceiverLink().Underlay.Local != desired.Underlay.Peer {
				t.Fatalf("offline creator lost receiver handoff: %v", err)
			}
			if !strings.Contains(out, "Manual local configuration selected") || !strings.Contains(out, "LOCAL STATUS / NOT A PEER PING") {
				t.Fatalf("create implied reachability or hid local fallback: %s", out)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "ping ") || strings.Contains(call, "curl ") || strings.Contains(call, "nc ") {
					t.Fatalf("Create probed remote peer: %s", call)
				}
			}
			// The receiver's direct CLI must accept the exact customized offer even
			// when the peer cannot be contacted. Its Engine still governs ownership.
			receiverRoot := filepath.Join(t.TempDir(), "receiver")
			receiverFake := newLifecycleFake()
			var receiver backend.Backend
			switch tc.kind {
			case domain.BackendGRE:
				receiver = &guidedTestBackend{lifecycleFakeBackend: receiverFake}
			case domain.BackendIPIP:
				receiver = &ipipImportFake{lifecycleFakeBackend: receiverFake}
			case domain.BackendL2TPv3:
				receiver = &guidedL2TPv3Backend{lifecycleFakeBackend: receiverFake}
			}
			receiverOpts := &runtimeOptions{stateRoot: receiverRoot, backends: []backend.Backend{receiver},
				probeRunner: &greReceiverProbe{inventory: greReceiverInventory("eth0", offer.ReceiverLink().Underlay.Local.String())}}
			var output, errorOutput bytes.Buffer
			exit := runWithRuntimeInput([]string{"link", "import", "--stdin", "--confirm", setupLinkConfirmation(encoded), "--json"},
				strings.NewReader(encoded), &output, &errorOutput, receiverOpts)
			if exit != 0 || len(receiverFake.applies) != 1 || errorOutput.Len() != 0 {
				t.Fatalf("offline receiver CLI import rejected: exit=%d out=%q err=%q", exit, output.String(), errorOutput.String())
			}
			var response map[string]any
			if json.Unmarshal(output.Bytes(), &response) != nil || response["removed"] != false {
				t.Fatalf("invalid CLI success contract: %q", output.String())
			}
			peerState, err := state.NewFileStore(receiverRoot).Load(context.Background())
			if err != nil || len(peerState.Links) != 1 || peerState.Links[0].Desired != offer.ReceiverLink() {
				t.Fatalf("receiver configuration mismatch: %+v err=%v", peerState, err)
			}
		})
	}
}

func TestGuidedOfflineManualEndpointRejectsUnassignedAndAllowsRetry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	runner := &guidedTestRunner{routeFailAll: true}
	opts := guidedTestOptions(root, runner, fake)
	// First address is not assigned locally, then a correct address but
	// foreign device, finally same assigned IP and its real interface.
	input := "1\n1\n192.0.2.20\n198.51.100.99\n192.0.2.10\nnot-owned\n192.0.2.10\n\n\nn\nYES\nn\n8\n"
	code, out, errText := runGuidedTest(opts, input)
	if code != 0 || len(fake.applies) != 1 || !strings.Contains(out, "not assigned") || !strings.Contains(out, "not verified") {
		t.Fatalf("unsafe manual fallback or failed retry: exit=%d applies=%v out=%q err=%q", code, fake.applies, out, errText)
	}
}

// Even when the peer underlay has no route, the default Enter-first wizard
// can use the one locally-assigned endpoint without guessing remote state.
func TestOfflineGuidedDefaultEnterSelectsUniqueAssignedLocalIPv4(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	runner := &guidedTestRunner{routeFailAll: true}
	opts := guidedTestOptions(root, runner, fake)
	// Enter: GRE type, local IP, local device, private /31 pair, advanced=No.
	input := "1\n\n192.0.2.20\n\n\n\nn\nYES\nn\n8\n"
	code, out, errText := runGuidedTest(opts, input)
	if code != 0 || len(fake.applies) != 1 || !strings.Contains(out, "Local IPv4 [192.0.2.10] (Enter=detected") ||
		!strings.Contains(out, "Selected local") || !strings.Contains(out, "connectivity not measured") {
		t.Fatalf("offline Enter-default wizard failed or claimed peer connectivity: %d applies=%v output=%q err=%q", code, fake.applies, out, errText)
	}
	if s, err := state.NewFileStore(root).Load(context.Background()); err != nil || len(s.Links) != 1 || s.Links[0].Desired.Underlay.Local != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("offline Enter-default state wrong: %+v %v", s, err)
	}
}

func TestGuidedCreateDoesNotAutoTrustWrongKernelInterface(t *testing.T) {
	for _, variant := range []struct {
		name                     string
		wrongDevice, wrongSource bool
	}{
		{"incorrect-device", true, false},
		{"incorrect-source", false, true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "owner")
			b := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			r := &guidedTestRunner{routeWrongDevice: variant.wrongDevice, routeWrongSource: variant.wrongSource}
			opt := guidedTestOptions(root, r, b)
			input := "1\n1\n192.0.2.20\n\n\n\nn\nYES\nn\n8\n"
			code, output, errors := runGuidedTest(opt, input)
			if code != 0 || len(b.applies) != 1 || errors != "" || !strings.Contains(output, "Manual local configuration selected") {
				t.Fatalf("misleading route was trusted or no assigned fallback offered: code=%d applies=%d err=%q output=%q", code, len(b.applies), errors, output)
			}
			if s, err := state.NewFileStore(root).Load(context.Background()); err != nil || len(s.Links) != 1 || s.Links[0].Desired.Underlay.Local != netip.MustParseAddr("192.0.2.10") {
				t.Fatalf("wrong route source got committed: %+v %v", s, err)
			}
		})
	}
}

func TestGuidedMultiHomeCanOverrideVerifiedRouteWithAssignedIPv4(t *testing.T) {
	root := filepath.Join(t.TempDir(), "owner")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	runner := &guidedTestRunner{localInventory: `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.30","prefixlen":24}]}]`}
	opts := guidedTestOptions(root, runner, fake)
	// A valid route suggests eth0, but an operator owning eth1 selects its
	// independently verified local IPv4. No synthetic route or peer ping.
	script := "1\n1\n192.0.2.20\nm\n192.0.2.30\neth1\n10.235.51.1\n10.235.51.2\nn\nYES\nn\n8\n"
	code, out, errText := runGuidedTest(opts, script)
	if code != 0 || errText != "" || len(fake.applies) != 1 || !strings.Contains(out, "m=choose another assigned pair") || !strings.Contains(out, "192.0.2.30 on eth1") || strings.Contains(out, "No trustworthy automatic") {
		t.Fatalf("multi-homed local interface override failed: %d applies=%v err=%q out=%q", code, fake.applies, errText, out)
	}
	s, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(s.Links) != 1 || s.Links[0].Desired.Underlay.Local != netip.MustParseAddr("192.0.2.30") {
		t.Fatalf("manual selected local binding lost: %+v %v", s, err)
	}
	for _, cmd := range runner.calls {
		if strings.Contains(cmd, "ping ") || strings.Contains(cmd, "curl ") {
			t.Fatalf("wizard probed remote endpoint: %s", cmd)
		}
	}
}
