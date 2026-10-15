package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestOperatorManualAdjacentPrivateAddressesAcceptThirtyAndThirtyOne(t *testing.T) {
	valid := []struct {
		local, peer string
		bits        int
	}{
		{"10.235.1.1", "10.235.1.2", 30},
		{"10.235.1.2", "10.235.1.1", 30},
		{"10.235.1.0", "10.235.1.1", 31},
		{"10.235.1.1", "10.235.1.0", 31},
	}
	for _, tc := range valid {
		got, err := manualLinkAddressPrefixes(netip.MustParseAddr(tc.local), netip.MustParseAddr(tc.peer))
		if err != nil || got.Local.Addr().String() != tc.local || got.Peer.Addr().String() != tc.peer ||
			got.Local.Bits() != tc.bits || got.Peer.Bits() != tc.bits || got.Local.Masked() != got.Peer.Masked() {
			t.Fatalf("accepted human endpoints misclassified: %+v got=%+v error=%v", tc, got, err)
		}
	}
	invalid := []struct{ local, peer string }{
		{"8.8.8.8", "10.235.1.2"},
		{"10.235.1.0", "10.235.1.2"},
		{"10.235.1.1", "10.235.1.3"},
		{"10.235.1.1", "10.235.2.2"},
		{"10.235.1.1", "10.235.1.1"},
		{"10.235.1.255", "10.235.2.0"},
	}
	for _, tc := range invalid {
		if got, err := manualLinkAddressPrefixes(netip.MustParseAddr(tc.local), netip.MustParseAddr(tc.peer)); err == nil {
			t.Fatalf("unsafe or mismatched endpoints accepted: %+v result=%+v", tc, got)
		}
	}
}

// Same operator entry must preserve canonical Engine ownership and actual
// recipient pairing inversion even with new /30 manual input.
func TestOperatorThirtyManualGRECreateManageShareAndImport(t *testing.T) {
	senderRoot := filepath.Join(t.TempDir(), "sender")
	receiverRoot := filepath.Join(t.TempDir(), "receiver")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(senderRoot, &guidedTestRunner{}, fake)
	input := "1\n1\n192.0.2.20\n10.235.1.1\n10.235.1.2\nn\nYES\nn\n3\n1\n3\n0\n8\n"
	code, out, errText := runGuidedTest(opts, input)
	if code != 0 || errText != "" || len(fake.applies) != 1 {
		t.Fatalf("manual /30 or Manage Share failed: %d %q %q", code, out, errText)
	}
	links := regexp.MustCompile("stl://[^[:space:]]+").FindAllString(out, -1)
	if len(links) != 2 || links[0] != links[1] {
		t.Fatalf("re-export must be identity-consistent, count=%d", len(links))
	}
	sender, err := state.NewFileStore(senderRoot).Load(context.Background())
	if err != nil || len(sender.Links) != 1 {
		t.Fatalf("missing persisted /30: %v", err)
	}
	l := sender.Links[0].Desired
	if l.Addresses.Local.String() != "10.235.1.1/30" ||
		l.Addresses.Peer.String() != "10.235.1.2/30" || l.MTU.Mode != domain.MTUAuto {
		t.Fatalf("unexpected /30 sender state: %+v", l)
	}
	receiver := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	ropts := guidedTestOptions(receiverRoot, &guidedTestRunner{}, receiver)
	peerCode, peerOut, peerErr := runGuidedTest(ropts, "2\n1\n"+links[0]+"\nYES\n8\n")
	if peerCode != 0 || peerErr != "" || !strings.Contains(peerOut, "changes applied and verified") || len(receiver.applies) != 1 {
		t.Fatalf("/30 peer import failed: %d %q %q", peerCode, peerOut, peerErr)
	}
	peer, err := state.NewFileStore(receiverRoot).Load(context.Background())
	if err != nil || len(peer.Links) != 1 ||
		peer.Links[0].Desired != pairing.Invert(l) {
		t.Fatalf("failed recipient /30 inversion: %+v %v", peer, err)
	}
}

func TestOperatorUnifiedCreateAllPlainBackends(t *testing.T) {
	for _, test := range []struct {
		choice  string
		backend domain.Backend
		mode    domain.Encapsulation
	}{
		{"1", domain.BackendGRE, domain.EncapNative},
		{"3", domain.BackendIPIP, domain.EncapNative},
		{"5\n1", domain.BackendGRE, domain.EncapFOU},
		{"5\n2", domain.BackendGRE, domain.EncapGUE},
		{"5\n3", domain.BackendIPIP, domain.EncapFOU},
		{"5\n4", domain.BackendIPIP, domain.EncapGUE},
	} {
		t.Run(test.choice, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			f := newLifecycleFake()
			var chosen backend.Backend
			if test.backend == domain.BackendGRE {
				chosen = &guidedTestBackend{lifecycleFakeBackend: f}
			} else {
				chosen = &ipipImportFake{lifecycleFakeBackend: f}
			}
			opts := &runtimeOptions{
				stateRoot: root, backends: []backend.Backend{chosen},
				probeRunner: &guidedTestRunner{}, mtuManager: guidedMTUFake{},
				createLinkID: func() (domain.LinkID, error) { return createTestID, nil },
			}
			code, out, errText := runGuidedTest(opts, "1\n"+test.choice+"\n192.0.2.20\n\nn\nYES\nn\n8\n")
			if code != 0 || len(f.applies) != 1 {
				t.Fatalf("backend option did not use canonical Engine: %d out=%s err=%s", code, out, errText)
			}
			saved, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || len(saved.Links) != 1 {
				t.Fatalf("missing backend saved state: %v", err)
			}
			l := saved.Links[0].Desired
			if l.Backend != test.backend || l.Encapsulation != test.mode {
				t.Fatalf("backend choice mismatch: %+v", l)
			}
			if test.backend == domain.BackendGRE && test.mode != domain.EncapNative && l.GRE.UDPPort == 0 {
				t.Fatal("UDP GRE mode missing port")
			}
			if !strings.Contains(out, "Setup link: stl://") {
				t.Fatal("selected mode did not provide canonical peer Setup Link")
			}
		})
	}
}

func TestOperatorIPsecBlockedBeforeCredentialsOrMutations(t *testing.T) {
	opts := guidedTestOptions(filepath.Join(t.TempDir(), "absent"), &guidedTestRunner{},
		&guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()})
	for _, typeChoice := range []string{"5\n5", "5\n6"} {
		code, out, errText := runGuidedTest(opts, "1\n"+typeChoice+"\n8\n")
		if code != 0 || !strings.Contains(out, "stl doctor ipsec") ||
			strings.Contains(out, "locally configured and verified") ||
			strings.Contains(errText, "secret") {
			t.Fatalf("IPsec fallback not understandable/safe: %d %q %q", code, out, errText)
		}
	}
}

func TestOperatorInputErrorsRemainInMenuWithoutHostMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
	input := "bad-main-choice\n1\n999\n1\nBAD-IP\n192.0.2.20\n8.8.8.8\n10.235.1.1\n10.235.1.2\nn\nNO\n8\n"
	code, out, errText := runGuidedTest(opts, input)
	if code != 0 || len(fake.applies) != 0 || !strings.Contains(out, "Choose 1, 2, 3, 4, 5") ||
		!strings.Contains(out, "Use a private IPv4") ||
		!strings.Contains(out, "Enter an actual reachable IPv4") ||
		!strings.Contains(out, "Create cancelled") ||
		strings.Contains(out+errText, "BAD-IP") {
		t.Fatalf("invalid prompt lost menu safety: %d %q %q", code, out, errText)
	}
	if _, err := state.NewFileStore(root).Load(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorImportLongOrMalformedLineDrainsAndCanRecover(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	source, _ := makeLifecycleDesired(t, "a", "10.70.91.0/31")
	offer := testQuickSetupLink(t, source, nil)
	long := strings.Repeat("a", 24*1024+55)
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}}
	input := "2\n1\n" + long + "\n" + offer + "\nYES\n8\n"
	var out, errText bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(input), &out, &errText, opts)
	if code != 0 || !strings.Contains(out.String(), "too long") ||
		!strings.Contains(out.String(), "changes applied and verified") ||
		len(fake.applies) != 1 ||
		strings.Contains(out.String()+errText.String(), long) {
		t.Fatalf("oversized URL broke input boundary: code=%d tooLong=%t appliedText=%t applies=%d echoedLong=%t last=%q errors=%q", code, strings.Contains(out.String(), "too long"), strings.Contains(out.String(), "changes applied and verified"), len(fake.applies), strings.Contains(out.String()+errText.String(), long), out.String()[max(0, len(out.String())-600):], errText.String())
	}
}

func TestOperatorTerminalPlainVsSensitiveOfferPreflight(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	link, _ := makeLifecycleDesired(t, "a", "10.70.91.0/31")
	link.Backend, link.Encapsulation = domain.BackendIPsec, domain.EncapNATT
	sensitive := testQuickSetupLink(t, link, bytes.Repeat([]byte{0x42}, 32))
	plainFake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	code, out, errText := runGuidedTest(
		&runtimeOptions{stateRoot: root, backends: []backend.Backend{plainFake}},
		"2\n1\n"+sensitive+"\n0\n8\n")
	if code != 0 || !strings.Contains(out, "contains a private credential") ||
		strings.Contains(out+errText, sensitive) || len(plainFake.applies) != 0 {
		t.Fatalf("unsafe plaintext import acceptance: %d %q %q", code, out, errText)
	}
}

func TestOperatorInvalidManualAddressesNeverMutate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{routes: "[{\"dst\":\"10.235.1.0/24\",\"dev\":\"eth0\"}]"}, fake)
	code, out, _ := runGuidedTest(opts, "1\n1\n192.0.2.20\n10.235.1.1\n10.235.1.2\nq\n8\n")
	if code != 0 || len(fake.applies) != 0 || !strings.Contains(out, "conflict") {
		t.Fatal("collision or retry allowed host mutation")
	}
	_, err := state.NewFileStore(root).Load(context.Background())
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestOperatorManualGREPairedOnBothServersWithoutSetupLink(t *testing.T) {
	firstRoot := filepath.Join(t.TempDir(), "server-a")
	secondRoot := filepath.Join(t.TempDir(), "server-b")
	fa := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	fb := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	first := guidedTestOptions(firstRoot, &guidedTestRunner{}, fa)
	second := guidedTestOptions(secondRoot, &guidedTestRunner{}, fb)
	scriptA := "1\n4\n1\n192.0.2.20\n10.235.1.1\n10.235.1.2\n\nn\nYES\nn\n8\n"
	scriptB := "1\n4\n1\n192.0.2.10\n10.235.1.2\n10.235.1.1\n\nn\nYES\nn\n8\n"
	code, out, errText := runGuidedTest(first, scriptA)
	if code != 0 || errText != "" || len(fa.applies) != 1 ||
		!strings.Contains(out, "No Setup Link is needed") {
		t.Fatalf("manual GRE sender creation failed: %d %q %q", code, out, errText)
	}
	code, out, errText = runGuidedTest(second, scriptB)
	if code != 0 || errText != "" || len(fb.applies) != 1 ||
		!strings.Contains(out, "No Setup Link is needed") {
		t.Fatalf("manual GRE receiver creation failed: %d %q %q", code, out, errText)
	}
	a, e := state.NewFileStore(firstRoot).Load(context.Background())
	if e != nil || len(a.Links) != 1 {
		t.Fatalf("missing server A state: %v", e)
	}
	b, e := state.NewFileStore(secondRoot).Load(context.Background())
	if e != nil || len(b.Links) != 1 {
		t.Fatalf("missing server B state: %v", e)
	}
	al, bl := a.Links[0].Desired, b.Links[0].Desired
	if al.GRE.KeyEnabled || bl.GRE.KeyEnabled || al.Addresses.Local != bl.Addresses.Peer ||
		al.Addresses.Peer != bl.Addresses.Local || al.Underlay.Local != bl.Underlay.Peer ||
		al.Underlay.Peer != bl.Underlay.Local || al.Encapsulation != domain.EncapNative {
		t.Fatalf("manual two-peer GRE configuration not reciprocal: A=%+v B=%+v", al, bl)
	}
}

// Normal Create automatically chooses the locally routed server source,
// while Enter accepts both unused private tunnel endpoints; no input asks
// the user to compute CIDRs or type a local public/private underlay address.
func TestOperatorAutoDetectsServerIPAndEnterAcceptsBothTunnelIPs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	code, out, errText := runGuidedTest(guidedTestOptions(root, &guidedTestRunner{}, fake),
		"1\n1\n192.0.2.20\n\nn\nYES\nn\n8\n")
	if code != 0 || errText != "" || len(fake.applies) != 1 ||
		!strings.Contains(out, "THIS server's connection IP: 192.0.2.10 (detected automatically") ||
		!strings.Contains(out, "Suggested tunnel IPs: THIS server") ||
		!strings.Contains(out, "Tunnel IP on THIS server (Enter=use suggested;") {
		t.Fatalf("auto IP default did not complete: %d %q %q", code, out, errText)
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snapshot.Links) != 1 ||
		snapshot.Links[0].Desired.Underlay.Local != netip.MustParseAddr("192.0.2.10") ||
		snapshot.Links[0].Desired.Addresses.Local.Bits() != 31 {
		t.Fatalf("auto source and tunnel pair were not saved: %+v %v", snapshot, err)
	}
}

func TestOperatorManualKeyedGRECanReproduceSavedPeerWithoutSetupLink(t *testing.T) {
	rootA, rootB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	aFake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	firstOpts := guidedTestOptions(rootA, &guidedTestRunner{}, aFake)
	// Force simple, explicit /30 Link IPs so a human can copy them in order.
	code, _, errText := runGuidedTest(firstOpts,
		"1\n1\n192.0.2.20\n10.235.1.1\n10.235.1.2\nn\nYES\nn\n8\n")
	if code != 0 || errText != "" {
		t.Fatalf("first GRE create failed: %d %s", code, errText)
	}
	snapA, err := state.NewFileStore(rootA).Load(context.Background())
	if err != nil || len(snapA.Links) != 1 {
		t.Fatal("no saved first peer", err)
	}
	linkA := snapA.Links[0].Desired
	if !linkA.GRE.KeyEnabled {
		t.Fatal("ordinary GRE must remain uniquely keyed")
	}
	// Details must be obtainable later by choosing numbers, even without
	// a copied setup URL or knowledge of the 128-bit Link ID.
	menuCode, details, menuErrors := runGuidedTest(firstOpts, "3\n1\n4\n0\n8\n")
	if menuCode != 0 || menuErrors != "" ||
		!strings.Contains(details, "GRE receive key:") ||
		!strings.Contains(details, fmt.Sprint(linkA.GRE.Key)) ||
		!strings.Contains(details, "THIS server connection IPv4:  192.0.2.10") ||
		!strings.Contains(details, "OTHER server connection IPv4: 192.0.2.20") ||
		!strings.Contains(details, "OTHER server tunnel/private IP: 10.235.1.2/30") ||
		!strings.Contains(details, "Other server's PEER connection IP: 192.0.2.10") ||
		!strings.Contains(details, "Other server's OWN tunnel IP:      10.235.1.2") {
		t.Fatalf("saved Link details lack two-server manual instructions: %d %q %q", menuCode, details, menuErrors)
	}
	bFake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	secondOpts := guidedTestOptions(rootB, &guidedTestRunner{}, bFake)
	input := "1\n4\n1\n192.0.2.10\n10.235.1.2\n10.235.1.1\n" +
		fmt.Sprint(linkA.GRE.Key) + "\nn\nYES\nn\n8\n"
	code, out, errText := runGuidedTest(secondOpts, input)
	if code != 0 || errText != "" || len(bFake.applies) != 1 || !strings.Contains(out, "No Setup Link is needed") {
		t.Fatalf("manual peer with copied key did not create: %d %q %q", code, out, errText)
	}
	snapB, err := state.NewFileStore(rootB).Load(context.Background())
	if err != nil || len(snapB.Links) != 1 {
		t.Fatal("manual peer state absent", err)
	}
	linkB := snapB.Links[0].Desired
	if !linkB.GRE.KeyEnabled || linkA.GRE.Key != linkB.GRE.Key ||
		linkA.Underlay.Local != linkB.Underlay.Peer ||
		linkA.Underlay.Peer != linkB.Underlay.Local ||
		linkA.Addresses.Local != linkB.Addresses.Peer ||
		linkA.Addresses.Peer != linkB.Addresses.Local {
		t.Fatalf("manual keyed remote config not reciprocal: A=%+v B=%+v", linkA, linkB)
	}
}

func TestOperatorManualIPIPNativeWithoutSetupLink(t *testing.T) {
	firstRoot, secondRoot := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	f1 := &ipipImportFake{newLifecycleFake()}
	f2 := &ipipImportFake{newLifecycleFake()}
	build := func(root string, f backend.Backend) *runtimeOptions {
		return &runtimeOptions{stateRoot: root, backends: []backend.Backend{f},
			probeRunner: &guidedTestRunner{}, mtuManager: guidedMTUFake{},
			createLinkID: func() (domain.LinkID, error) { return createTestID, nil }}
	}
	a := build(firstRoot, f1)
	b := build(secondRoot, f2)
	for i, tc := range []struct {
		opts  *runtimeOptions
		input string
	}{
		{a, "1\n4\n2\n192.0.2.20\n10.235.1.1\n10.235.1.2\nn\nYES\nn\n8\n"},
		{b, "1\n4\n2\n192.0.2.10\n10.235.1.2\n10.235.1.1\nn\nYES\nn\n8\n"},
	} {
		c, o, e := runGuidedTest(tc.opts, tc.input)
		if c != 0 || !strings.Contains(o, "No Setup Link is needed") ||
			!strings.Contains(e, "backend has no live diagnostic adapter") {
			t.Fatalf("IPIP manual side %d setup failed or silently lost the status warning: %d %q %q", i, c, o, e)
		}
	}
	s1, e1 := state.NewFileStore(firstRoot).Load(context.Background())
	s2, e2 := state.NewFileStore(secondRoot).Load(context.Background())
	if e1 != nil || e2 != nil || len(s1.Links) != 1 || len(s2.Links) != 1 {
		t.Fatalf("IPIP manual state missing: %v %v", e1, e2)
	}
	aLink, bLink := s1.Links[0].Desired, s2.Links[0].Desired
	if aLink.Backend != domain.BackendIPIP || aLink.Addresses.Local != bLink.Addresses.Peer ||
		aLink.Underlay.Local != bLink.Underlay.Peer {
		t.Fatalf("IPIP manual orientation: A=%+v B=%+v", aLink, bLink)
	}
}

func TestOperatorSavedSensitiveConnectionDetailsStayReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link, _ := makeLifecycleDesired(t, "a", "10.70.11.0/31")
	link.Backend, link.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	link.DisplayName = "PRIVATE_DISPLAY_DO_NOT_SHOW"
	// State may contain only the public WireGuard options.
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x56}, 32))
	completeWireGuardFixture(t, &link, key)
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	code, out, errText := runGuidedTest(&runtimeOptions{stateRoot: root}, "3\n1\n4\n0\n8\n")
	if code != 0 || errText != "" ||
		!strings.Contains(out, "original protected receiver offer") ||
		strings.Contains(out, "PRIVATE_DISPLAY_DO_NOT_SHOW") ||
		strings.Contains(out, "private_key") ||
		strings.Contains(out, "PSK=") {
		t.Fatalf("sensitive Link detail violated privacy or liveness: %d %q %q", code, out, errText)
	}
}
