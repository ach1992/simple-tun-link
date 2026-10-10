package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

const createTestID = domain.LinkID("lnk_ffffffffffffffffffffffffffffffff")

type guidedTestRunner struct {
	routeFail      bool
	capabilityFail bool
	routes         string
	calls          []string
}

func (r *guidedTestRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	command := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, command)
	output := ""
	switch command {
	case "ip -4 -json route get 192.0.2.20":
		if r.routeFail {
			return linux.CommandResult{}, errors.New("opaque, potentially sensitive route error")
		}
		output = "[{\"dst\":\"192.0.2.20\",\"dev\":\"eth0\",\"prefsrc\":\"192.0.2.10\",\"gateway\":\"192.0.2.1\",\"mtu\":1500}]"
	case "ip -4 -json route get 10.0.0.5":
		output = "[{\"dst\":\"10.0.0.5\",\"dev\":\"eth0\",\"prefsrc\":\"192.0.2.10\",\"gateway\":\"192.0.2.1\",\"mtu\":1500}]"
	case "ip -json -details link show type gre":
		if r.capabilityFail {
			return linux.CommandResult{}, errors.New("GRE unavailable")
		}
		output = "[]"
	case "ip -json -details link show type ipip",
		"ip -json -details link show type wireguard",
		"ip -json -details link show type xfrm", "ip fou show":
		output = "[]"
	case "ip -json link show":
		output = "[{\"ifname\":\"eth0\",\"ifalias\":\"\"}]"
	case "ip -json address show":
		output = "[{\"ifname\":\"eth0\",\"addr_info\":[{\"local\":\"192.0.2.10\",\"prefixlen\":24}]}]"
	case "ip -json route show table all":
		if r.routes == "" {
			output = "[{\"dst\":\"192.0.2.0/24\",\"dev\":\"eth0\"}]"
		} else {
			output = r.routes
		}
	case "ss -H -u -l -n":
		output = ""
	default:
		return linux.CommandResult{}, errors.New("nonrequired optional capability")
	}
	return linux.CommandResult{Stdout: []byte(output)}, nil
}

type guidedTestBackend struct {
	*lifecycleFakeBackend
	failStatus bool
}

func (*guidedTestBackend) Kind() domain.Backend { return domain.BackendGRE }

func (b *guidedTestBackend) DiagnosticState(_ context.Context, link domain.Link) (grebackend.DiagnosticState, error) {
	if b.failStatus {
		return grebackend.DiagnosticState{}, errors.New("backend state unavailable")
	}
	if !b.present[link.ID] {
		return grebackend.DiagnosticState{}, errors.New("not live")
	}
	iface, _ := grebackend.InterfaceName(link.ID)
	return grebackend.DiagnosticState{Interface: iface, IfIndex: 17, Encapsulation: link.Encapsulation}, nil
}

func guidedTestOptions(root string, host *guidedTestRunner, fake *guidedTestBackend) *runtimeOptions {
	return &runtimeOptions{
		stateRoot: root, probeRunner: host, backends: []backend.Backend{fake},
		createLinkID: func() (domain.LinkID, error) { return createTestID, nil },
	}
}

func runGuidedTest(options *runtimeOptions, input string) (int, string, string) {
	var output, errOut bytes.Buffer
	code := runWithRuntimeInput([]string{"menu"}, strings.NewReader(input), &output, &errOut, options)
	return code, output.String(), errOut.String()
}

func TestGuidedGRECreateFullOperatorPathAndPairing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	host := &guidedTestRunner{}
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, host, fake)
	input := "1\n192.0.2.20\n\nn\nn\n" + string(createTestID) + "\nn\n8\n"
	code, output, errOut := runGuidedTest(opts, input)
	if code != 0 || errOut != "" {
		t.Fatalf("guided create failed: %d out=%q err=%q", code, output, errOut)
	}
	for _, marker := range []string{
		"Create GRE Native (default)", "PREVIEW ONLY", "local host checked",
		"To APPLY, type exact Link ID", "changes applied and verified",
		"Setup link: stl://", "On the peer", "interface verified", "connectivity not measured",
		"stl link diagnose",
	} {
		if !strings.Contains(output, marker) {
			t.Fatalf("missing guided outcome %q", marker)
		}
	}
	if len(fake.applies) != 1 || fake.applies[0] != createTestID {
		t.Fatalf("wizard bypassed normal Engine ensure: %+v", fake.applies)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 {
		t.Fatalf("Link was not persisted through Engine: %+v %v", saved, err)
	}
	desired := saved.Links[0].Desired
	if desired.ID != createTestID || desired.Underlay.Local != netip.MustParseAddr("192.0.2.10") ||
		desired.Underlay.Peer != netip.MustParseAddr("192.0.2.20") ||
		desired.Backend != domain.BackendGRE || desired.Encapsulation != domain.EncapNative ||
		!desired.GRE.KeyEnabled || desired.Addresses.Local.Bits() != 31 ||
		desired.Addresses.Local.Masked() != desired.Addresses.Peer.Masked() {
		t.Fatalf("incorrect guided intent: %+v", desired)
	}
	url := regexp.MustCompile("stl://[^[:space:]]+").FindString(output)
	offer, err := pairing.DecodeSetupLink(url)
	if err != nil || offer.Link() != desired {
		t.Fatalf("explicit export differs from created Link: %v", err)
	}
	peer := offer.ReceiverLink()
	if peer.Underlay.Local != desired.Underlay.Peer || peer.Addresses.Local != desired.Addresses.Peer {
		t.Fatal("setup offer failed canonical receiver inversion")
	}
	for _, command := range host.calls {
		if strings.Contains(command, "link add") || strings.Contains(command, "iptables") {
			t.Fatalf("wizard performed host mutation outside Engine: %s", command)
		}
	}
}

func TestGuidedGRECreateManualSideAndAdvancedKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
	// Manual /31, use upper address locally, keyed GRE with an explicit zero,
	// TTL 64, TOS 16, checksum enabled, no sequence.
	input := "1\n192.0.2.20\n10.77.2.0/31\ny\ny\n0\n64\n16\ny\nn\n" +
		string(createTestID) + "\nn\n8\n"
	code, _, errOut := runGuidedTest(opts, input)
	if code != 0 || errOut != "" {
		t.Fatalf("advanced Create failed: %d %s", code, errOut)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 {
		t.Fatal("manual Link missing", err)
	}
	link := saved.Links[0].Desired
	if link.Addresses.Local.String() != "10.77.2.1/31" ||
		link.Addresses.Peer.String() != "10.77.2.0/31" ||
		!link.GRE.KeyEnabled || link.GRE.Key != 0 || link.GRE.TTL != 64 || link.GRE.TOS != 16 ||
		!link.GRE.Checksum || link.GRE.DisablePMTUD || link.GRE.Sequence {
		t.Fatalf("manual and advanced state mismatch: %+v", link)
	}
}

func TestGuidedGRECreateRejectsManualHostAndPersistedCollision(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route string
		saved bool
	}{
		{"host overlapping route", "[{\"dst\":\"10.88.0.0/16\",\"dev\":\"eth0\"}]", false},
		{"persisted overlapping Link", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			if tc.saved {
				existing, _ := makeLifecycleDesired(t, "a", "10.88.2.0/31")
				if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
					s.Upsert(state.LinkRecord{Desired: existing})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			opts := guidedTestOptions(root, &guidedTestRunner{routes: tc.route}, fake)
			code, _, errOut := runGuidedTest(opts, "1\n192.0.2.20\n10.88.2.0/31\n")
			if code != 2 || !strings.Contains(errOut, "overlaps") || len(fake.applies) != 0 {
				t.Fatalf("conflicting /31 accepted: code=%d err=%q", code, errOut)
			}
			saved, err := state.NewFileStore(root).Load(context.Background())
			expected := 0
			if tc.saved {
				expected = 1
			}
			if err != nil || len(saved.Links) != expected {
				t.Fatalf("conflict modified saved state: %+v %v", saved, err)
			}
		})
	}
}

func TestGuidedGRECreateCancelAndProbeFailuresNeverMutate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		routeBad bool
		greBad   bool
		code     int
	}{
		{"cancel before route", "1\nq\n8\n", false, false, 0},
		{"bad peer", "1\nSECRET-NOT-TO-ECHO\n", false, false, 2},
		{"route unavailable", "1\n192.0.2.20\n", true, false, 4},
		{"GRE unavailable", "1\n192.0.2.20\n", false, true, 4},
		{"manual public subnet", "1\n192.0.2.20\n8.8.8.0/31\n", false, false, 2},
		{"cancel at preview", "1\n192.0.2.20\n\nn\nn\nwrong-id\n8\n", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "absent")
			fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			opts := guidedTestOptions(root, &guidedTestRunner{routeFail: tc.routeBad, capabilityFail: tc.greBad}, fake)
			code, out, errOut := runGuidedTest(opts, tc.input)
			if code != tc.code || len(fake.applies) != 0 || strings.Contains(out+errOut, "SECRET-NOT-TO-ECHO") {
				t.Fatalf("unsafe aborted flow: code=%d out=%q err=%q", code, out, errOut)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("aborted wizard wrote state: %v", err)
			}
		})
	}
}

func TestGuidedGREApplyFailureCannotClaimSuccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	fake.failApply = true
	code, out, errOut := runGuidedTest(guidedTestOptions(root, &guidedTestRunner{}, fake),
		"1\n192.0.2.20\n\nn\nn\n"+string(createTestID)+"\n")
	if code != 1 || !strings.Contains(errOut, "did not complete") ||
		strings.Contains(out+errOut, "VERY_SECRET_NOT_FOR_OUTPUT") ||
		strings.Contains(out, "Setup link:") {
		t.Fatalf("false success or leaked backend error: code=%d out=%q err=%q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed apply published state: %v", err)
	}
}

// This drives the actual terminal descriptor and bounded input parser, not a
// scripted imitation of menuCreate. It does not require root or change Linux.
func TestGuidedGRECreateRealPTYConfirmedJourney(t *testing.T) {
	master, slave := openMenuPTY(t)
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
	done := make(chan int, 1)
	go func() {
		done <- runWithRuntimeInput([]string{"menu"}, slave, slave, slave, opts)
	}()
	chunks := make(chan string, 32)
	go func() {
		var data [2048]byte
		for {
			n, err := master.Read(data[:])
			if n > 0 {
				chunks <- string(data[:n])
			}
			if err != nil {
				close(chunks)
				return
			}
		}
	}()
	pending := ""
	expect := func(marker string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for !strings.Contains(pending, marker) {
			select {
			case chunk, ok := <-chunks:
				if !ok {
					t.Fatalf("PTY closed before %q; seen %q", marker, pending)
				}
				pending += chunk
			case <-deadline:
				t.Fatalf("PTY did not display %q; seen %q", marker, pending)
			}
		}
		pending = pending[strings.Index(pending, marker)+len(marker):]
	}
	send := func(s string) {
		t.Helper()
		if _, err := io.WriteString(master, s+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	expect("Choose a task: ")
	send("1")
	expect("Peer underlay IPv4 address: ")
	send("192.0.2.20")
	expect("Link subnet (Enter=suggested;")
	send("")
	expect("Use second /31 address locally")
	send("n")
	expect("Configure advanced GRE options?")
	send("n")
	expect("To APPLY, type exact Link ID")
	send(string(createTestID))
	expect("Setup link: stl://")
	expect("Run active peer connectivity/MTU diagnostics now?")
	send("n")
	expect("Choose a task: ")
	send("8")
	select {
	case code := <-done:
		if code != 0 || len(fake.applies) != 1 {
			t.Fatalf("TTY wizard failed: code=%d applies=%d", code, len(fake.applies))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PTY wizard did not exit after operator chose Exit")
	}
}

func TestGuidedGRECreatePeerImportAndIdempotentReimport(t *testing.T) {
	initiatorRoot, receiverRoot := filepath.Join(t.TempDir(), "initiator"), filepath.Join(t.TempDir(), "receiver")
	initiator := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	receiver := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(initiatorRoot, &guidedTestRunner{}, initiator)
	code, out, errOut := runGuidedTest(opts, "1\n192.0.2.20\n\nn\nn\n"+string(createTestID)+"\nn\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("initiator Create failed: %d %q", code, errOut)
	}
	encoded := regexp.MustCompile("stl://[^[:space:]]+").FindString(out)
	if encoded == "" {
		t.Fatal("creator did not provide a setup link")
	}
	importScript := "2\n" + encoded + "\n" + string(createTestID) + "\n8\n"
	for attempt := 0; attempt < 2; attempt++ {
		receiverOpts := guidedTestOptions(receiverRoot, &guidedTestRunner{}, receiver)
		code, peerOut, peerErr := runGuidedTest(receiverOpts, importScript)
		if code != 0 || peerErr != "" {
			t.Fatalf("receiver Import attempt %d failed: %d %q", attempt, code, peerErr)
		}
		want := "changes applied and verified"
		if attempt == 1 {
			want = "already matches desired state"
		}
		if !strings.Contains(peerOut, want) || strings.Contains(peerOut, encoded) {
			t.Fatalf("receiver Import did not report accurate result / leaked payload: %q", peerOut)
		}
	}
	sourceState, err := state.NewFileStore(initiatorRoot).Load(context.Background())
	if err != nil || len(sourceState.Links) != 1 {
		t.Fatalf("initiator state unavailable: %v", err)
	}
	peerState, err := state.NewFileStore(receiverRoot).Load(context.Background())
	if err != nil || len(peerState.Links) != 1 ||
		peerState.Links[0].Desired != pairing.Invert(sourceState.Links[0].Desired) {
		t.Fatalf("peer import not canonical inversion: %+v %v", peerState, err)
	}
	if len(receiver.applies) != 1 {
		t.Fatalf("idempotent re-import repeated peer mutations: %v", receiver.applies)
	}
	receiverOpts := guidedTestOptions(receiverRoot, &guidedTestRunner{}, receiver)
	var status, errorsOut bytes.Buffer
	if code := linkReadCommand([]string{"status", string(createTestID)}, &status, &errorsOut, receiverOpts); code != 0 ||
		!strings.Contains(status.String(), "interface verified") || errorsOut.Len() != 0 {
		t.Fatalf("receiver status did not use live backend observation: %d %q", code, errorsOut.String())
	}
}

func TestGuidedGRECreateSelectsNonOverlappingAutomaticCIDR(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	runner := &guidedTestRunner{routes: "[{\"dst\":\"10.0.0.0/8\",\"dev\":\"eth0\"},{\"dst\":\"172.16.0.0/12\",\"dev\":\"eth0\"}]"}
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	code, _, errOut := runGuidedTest(guidedTestOptions(root, runner, fake),
		"1\n192.0.2.20\n\nn\nn\n"+string(createTestID)+"\nn\n8\n")
	if code != 0 || errOut != "" {
		t.Fatalf("auto CIDR selection did not avoid existing Linux route prefixes: %d %q", code, errOut)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 ||
		!netip.MustParsePrefix("192.168.0.0/16").Contains(saved.Links[0].Desired.Addresses.Local.Addr()) {
		t.Fatalf("auto CIDR conflicted with host routes: %+v %v", saved, err)
	}
}

func TestGuidedGRECreateGeneratedIDMustNotReplaceSavedLink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	original, _ := makeLifecycleDesired(t, "f", "10.70.90.0/31")
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: original})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(root, &guidedTestRunner{}, fake)
	opts.createLinkID = func() (domain.LinkID, error) { return original.ID, nil }
	code, _, errOut := runGuidedTest(opts, "1\n192.0.2.20\n\nn\n")
	if code != 2 || len(fake.applies) != 0 || !strings.Contains(errOut, "already present") {
		t.Fatalf("existing Link ID was not protected: code=%d %s", code, errOut)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 || saved.Links[0].Desired != original {
		t.Fatalf("existing desired Link was changed: %+v %v", saved, err)
	}
}

func TestGuidedGREPTYCancellationAndInvalidPeerNoNetworkMutation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		code  int
	}{
		{"cancel before preflight", "1\nq\n8\n", 0},
		{"invalid peer", "1\nBAD-INPUT\n", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, slave := openMenuPTY(t)
			fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
			root := filepath.Join(t.TempDir(), "absent")
			result := make(chan int, 1)
			go func() {
				result <- runWithRuntimeInput([]string{"menu"}, slave, slave, slave,
					guidedTestOptions(root, &guidedTestRunner{}, fake))
			}()
			if _, err := io.WriteString(master, tc.input); err != nil {
				t.Fatal(err)
			}
			select {
			case code := <-result:
				if code != tc.code {
					t.Fatalf("unexpected cancellation/error code: %d", code)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled or invalid PTY wizard did not return")
			}
			if len(fake.applies) != 0 {
				t.Fatal("cancel/error created a Link")
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cancel/error persisted Link state: %v", err)
			}
		})
	}
}

func TestGuidedGRECreatePostEnsureReadFailureMustPreserveReconciliation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake(), failStatus: true}
	code, out, errOut := runGuidedTest(guidedTestOptions(root, &guidedTestRunner{}, fake),
		"1\n192.0.2.20\n\nn\nn\n"+string(createTestID)+"\n")
	if code == 0 || !strings.Contains(errOut, "Local Link was ensured, but live status") ||
		!strings.Contains(out, "Setup link: stl://") {
		t.Fatalf("post-apply read-only failure did not report partial outcome: %d %q %q", code, out, errOut)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 || len(fake.applies) != 1 {
		t.Fatalf("read failure should not silently roll back completed Engine apply: %+v %v", saved, err)
	}
}

func TestGuidedGRECreateDiagnosticFailureRetainsConfiguredLink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	code, out, errOut := runGuidedTest(guidedTestOptions(root, &guidedTestRunner{}, fake),
		"1\n192.0.2.20\n\nn\nn\n"+string(createTestID)+"\ny\n")
	if code != 4 || !strings.Contains(errOut, "Diagnostics did not succeed") ||
		!strings.Contains(out, "interface verified") {
		t.Fatalf("diagnostic failure reported a misleading outcome: %d %q %q", code, out, errOut)
	}
	saved, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(saved.Links) != 1 || len(fake.applies) != 1 {
		t.Fatalf("failed optional diagnosis must not remove configured Link: %+v %v", saved, err)
	}
}

func TestGuidedGRECreateRejectsKnownPeerUnderlayCollision(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	code, out, errOut := runGuidedTest(guidedTestOptions(root, &guidedTestRunner{}, fake),
		"1\n10.0.0.5\n10.0.0.4/31\n")
	if code != 2 || !strings.Contains(errOut, "known peer underlay") ||
		strings.Contains(out, "PREVIEW ONLY") || len(fake.applies) != 0 {
		t.Fatalf("known peer underlay collision was not rejected at preflight: code=%d out=%q err=%q", code, out, errOut)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected peer address collision created state: %v", err)
	}
}

func TestGuidedGRECreateAutoCandidatesSkipKnownPeerUnderlay(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.5")
	candidates := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.4/31"),
		netip.MustParsePrefix("10.0.0.6/31"),
	}
	got, available, err := domain.FreePrivate31(candidates,
		collectReservedLinkAddresses(state.EmptySnapshot(), peer))
	if err != nil || !available || got != candidates[1] {
		t.Fatalf("automatic candidate did not exclude known peer underlay: got=%s available=%t err=%v",
			got, available, err)
	}
}
