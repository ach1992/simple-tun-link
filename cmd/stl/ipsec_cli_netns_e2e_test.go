package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

const cliLabRoot = "/run/stl-ipsec-proof"

// cliLabAdmission has no production registration or exported constructor.
// It is built into an opt-in go test binary, only accepted inside a
// container with no default route, explicit fixture selectors and a pinned
// per-peer namespace/private VICI daemon.
type cliLabAdmission struct{ side string }

func (a cliLabAdmission) Authorize(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 ||
		os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_CLI_FIXTURE") != "approved" {
		return fmt.Errorf("disposable CLI test authorization denied")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return fmt.Errorf("must use Docker fixture")
	}
	if _, err := os.Stat(cliLabRoot + "/" + a.side + ".pid"); err != nil {
		return fmt.Errorf("private native peer missing")
	}
	dir, err := os.Lstat(cliLabRoot)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0o700 {
		return fmt.Errorf("private root unsafe")
	}
	socket, err := os.Lstat(cliLabRoot + "/" + a.side + ".vici")
	if err != nil || socket.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("lab socket unavailable")
	}
	// A process in the same new network namespace is pinned by the fixture.
	proc, err := os.ReadFile(cliLabRoot + "/" + a.side + ".pid")
	if err != nil {
		return fmt.Errorf("lab daemon identity unavailable")
	}
	var pid int
	if _, err = fmt.Sscanf(strings.TrimSpace(string(proc)), "%d", &pid); err != nil || pid < 2 {
		return fmt.Errorf("lab daemon PID invalid")
	}
	peerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	selfNS, e := os.Readlink("/proc/self/ns/net")
	if err != nil || e != nil || peerNS != selfNS {
		return fmt.Errorf("lab daemon namespace mismatch")
	}
	return nil
}

func fixtureLinkForCLI(t *testing.T, side, suffix, encap string) domain.Link {
	t.Helper()
	a := side == "a"
	underA, underB := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	addrA, addrB := netip.MustParsePrefix("10.251.88.0/31"), netip.MustParsePrefix("10.251.88.1/31")
	if suffix == "b" {
		addrA, addrB = netip.MustParsePrefix("10.251.88.2/31"), netip.MustParsePrefix("10.251.88.3/31")
	}
	if os.Getenv("STL_IPSEC_CROSS_E2E") == "approved" {
		if suffix != "c" {
			t.Fatal("cross-backend IPsec fixture requires its dedicated Link identity")
		}
		underA, underB = netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
		addrA, addrB = netip.MustParsePrefix("10.84.10.0/31"), netip.MustParsePrefix("10.84.10.1/31")
	}
	if !a {
		underA, underB = underB, underA
		addrA, addrB = addrB, addrA
	}
	return domain.Link{
		ID:      domain.LinkID("lnk_" + strings.Repeat(suffix, 32)),
		Backend: domain.BackendIPsec, Encapsulation: domain.Encapsulation(encap),
		Underlay:  domain.Underlay{Local: underA, Peer: underB},
		Addresses: domain.LinkAddresses{Local: addrA, Peer: addrB},
	}
}

func TestIPsecCanonicalCLIRealIsolatedE2E(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_CLI_FIXTURE") != "approved" {
		t.Skip("requires approved disconnected privileged disposable container")
	}
	op, side, suffix, encap := os.Getenv("STL_IPSEC_CLI_OP"), os.Getenv("STL_IPSEC_CLI_SIDE"),
		os.Getenv("STL_IPSEC_CLI_LINK"), os.Getenv("STL_IPSEC_CLI_ENCAP")
	crossMode := os.Getenv("STL_IPSEC_CROSS_E2E") == "approved"
	if side != "a" && side != "b" || encap != "esp" && encap != "nat-t" ||
		(!crossMode && suffix != "a" && suffix != "b") || (crossMode && suffix != "c") {
		t.Fatal("invalid fixed CLI peer fixture identity")
	}
	stateRoot := cliLabRoot + "/cli-state-" + side
	if crossMode {
		// The GRE/WireGuard runner creates this root, and the other two
		// backends persist into it. Restrict the injected IPsec CLI fixture
		// to precisely those task-owned /tmp roots and one A/B peer.
		stateRoot = os.Getenv("STL_IPSEC_CROSS_STATE_ROOT")
		if filepath.Clean(stateRoot) != stateRoot || filepath.Dir(filepath.Dir(stateRoot)) != "/tmp" ||
			!strings.HasPrefix(filepath.Base(filepath.Dir(stateRoot)), "stl-gre-e2e.") ||
			filepath.Base(stateRoot) != side {
			t.Fatal("cross-backend IPsec state root is outside isolated GRE fixture")
		}
		for _, exact := range []string{filepath.Dir(stateRoot), stateRoot} {
			info, err := os.Lstat(exact)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
				t.Fatal("cross-backend shared state path is unavailable, symlinked or unsafe")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	admit := cliLabAdmission{side: side}
	if err := admit.Authorize(ctx); err != nil {
		t.Fatal(err)
	}
	// Every invocation rebuilds the actual production-style Engine/Registry,
	// loading persisted per-Link public state and root-protected secrets from
	// the exact same disk location as the previous independent invocation.
	runner := linux.ExecRunner{}
	route := linux.RouteResolver{Runner: runner}
	keys, err := ipsec.NewPSKStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := ipsec.NewScopedWriter(cliLabRoot + "/" + side + ".vici")
	if err != nil {
		t.Fatal(err)
	}
	backendImpl, err := ipsec.NewOperationalBackend(ipsec.OperationalOptions{
		Admission: admit, Runner: ipsec.BoundedExecRunner{}, Keys: keys, Writer: writer,
		Routes: ipsec.HostRouteResolveFunc(func(ctx context.Context, peer netip.Addr) (ipsec.HostRoute, error) {
			r, err := route.Resolve(ctx, peer)
			if err != nil {
				return ipsec.HostRoute{}, err
			}
			return ipsec.HostRoute{Source: r.Source, Device: r.Device}, nil
		}),
		XFRM:     ipsec.NewXFRMVacancyInspector("ip"),
		SetAlias: linux.SetLinkAliasByIndex, AddAddr: linux.AddIPv4AddressByIndex,
		SetUp: linux.SetLinkUpByIndex, Delete: linux.DeleteLinkByIndex,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Explicit failpoints affect ONLY this disconnected Docker test binary.
	// They interrupt XFRM creation at the actual kernel-to-alias boundaries.
	switch op {
	case "fault-index":
		backendImpl.Index = func(string) (int, error) { return 0, fmt.Errorf("fixture index persistence interruption") }
	case "fault-alias":
		backendImpl.SetAlias = func(context.Context, int, string) error { return fmt.Errorf("fixture interruption before alias") }
	case "fault-address":
		backendImpl.AddAddr = func(context.Context, int, netip.Prefix) error { return fmt.Errorf("fixture interruption after alias") }
	}
	opts := &runtimeOptions{stateRoot: stateRoot, backends: []backend.Backend{backendImpl},
		probeRunner: runner}
	l := fixtureLinkForCLI(t, side, suffix, encap)
	if op == "inject-remove" {
		if side != "a" {
			t.Fatal("only fixture endpoint A may inject an isolated Remove checkpoint")
		}
		phase := os.Getenv("STL_IPSEC_FAULT_PHASE")
		if phase != state.IPsecRemoveIssuingShared && phase != state.IPsecRemoveIssuingDevice {
			t.Fatal("unsupported isolated Remove fault phase")
		}
		profile, err := ipsec.NewProfile(l)
		if err != nil {
			t.Fatal(err)
		}
		iface, err := net.InterfaceByName(profile.InterfaceName)
		if err != nil || iface.Index <= 0 {
			t.Fatal("original owned XFRM ifindex unavailable")
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal("cannot allocate fixture transaction")
		}
		store := state.NewFileStore(opts.stateRoot)
		if err := store.Update(ctx, func(s *state.Snapshot) error {
			committed, has := s.Find(l.ID)
			if !has || committed.Desired != l || len(committed.OwnedResources) == 0 {
				return fmt.Errorf("cannot simulate crash without committed exact Link")
			}
			if _, exists := s.FindIPsecRemoveOperation(l.ID); exists {
				return fmt.Errorf("Remove checkpoint already exists")
			}
			s.IPsecRemoveOperations = append(s.IPsecRemoveOperations, state.IPsecRemoveOperation{
				Intent: l, Nonce: hex.EncodeToString(nonce[:]), Phase: phase, IfIndex: iface.Index})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		t.Logf("ISOLATED_DURABLE_REMOVE_INTERRUPTION=PASS phase=%s", phase)
		return
	}
	var args []string
	var input []byte
	handoff := cliLabRoot + "/" + suffix + ".cli-handoff"
	switch op {
	case "create", "fault-index", "fault-alias", "fault-address":
		if side != "a" {
			t.Fatal("only creator side A")
		}
		source := map[string]any{
			"schema_version": 1, "link_id": l.ID, "encapsulation": l.Encapsulation,
			"underlay": l.Underlay, "addresses": l.Addresses,
		}
		input, err = json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		args = []string{"link", "create-ipsec", "--stdin", "--output", handoff, "--json"}
	case "import", "import-mismatch":
		if side != "b" {
			t.Fatal("only recipient side B")
		}
		raw, err := os.ReadFile(handoff)
		if err != nil {
			t.Fatal("handoff unavailable")
		}
		defer clear(raw)
		input = bytes.TrimSpace(raw)
		if op == "import-mismatch" {
			// This test does not exercise an unreviewed real-user rekey:
			// tamper with the transmitted SENSITIVE v2 Quick Link in the
			// isolated fixture, then confirm the exact modified payload.
			src := fixtureLinkForCLI(t, "a", suffix, encap)
			bad, err := os.ReadFile(cliLabRoot + "/" + suffix + "-mismatch.secret")
			if err != nil || len(bad) != 32 {
				t.Fatal("mismatch fixture secret missing")
			}
			defer clear(bad)
			offer, err := pairing.NewQuickOffer(src, bad)
			if err != nil {
				t.Fatal(err)
			}
			defer offer.ClearRecipientCredential()
			handoffWrong, err := offer.EncodeSetupLink()
			if err != nil {
				t.Fatal(err)
			}
			input = []byte(handoffWrong)
		}
		sha := sha256.Sum256(input)
		args = []string{"link", "import", "--stdin", "--confirm", hex.EncodeToString(sha[:]), "--json"}
	case "ensure":
		input, err = json.Marshal(map[string]any{"schema_version": 1, "link": l})
		if err != nil {
			t.Fatal(err)
		}
		args = []string{"link", "ensure", "--stdin", "--json"}
	case "connect":
		args = []string{"link", "connect-ipsec", string(l.ID), "--confirm", string(l.ID), "--json"}
	case "status":
		args = []string{"link", "status", string(l.ID), "--json"}
	case "diagnose":
		args = []string{"link", "diagnose", string(l.ID), "--json"}
	case "remove":
		args = []string{"link", "remove", string(l.ID), "--confirm", string(l.ID), "--json"}
	case "retire":
		args = []string{"link", "retire-ipsec", string(l.ID), "--confirm", string(l.ID), "--json"}
	case "activate":
		args = []string{"link", "activate-ipsec", string(l.ID), "--confirm", string(l.ID), "--json"}
	case "reconcile-remove":
		args = []string{"link", "reconcile-ipsec", string(l.ID), "--confirm", string(l.ID), "--json"}
	case "reconcile-xfrm", "reconcile-xfrm-deny":
		args = []string{"link", "reconcile-xfrm-ipsec", string(l.ID), "--confirm", string(l.ID), "--json"}
	case "ensure-reject":
		input, err = json.Marshal(map[string]any{"schema_version": 1, "link": l})
		if err != nil {
			t.Fatal(err)
		}
		args = []string{"link", "ensure", "--stdin", "--json"}
	case "restore":
		args = []string{"link", "restore", "--all"}
	case "doctor":
		args = []string{"doctor", "ipsec", "--json"}
	case "cross-list":
		if !crossMode {
			t.Fatal("five-backend inventory requires explicit cross-backend fixture")
		}
		args = []string{"link", "list", "--json"}
	default:
		t.Fatalf("unsupported isolated CLI operation %q", op)
	}
	var out, errs bytes.Buffer
	code := runWithRuntimeInput(args, bytes.NewReader(input), &out, &errs, opts)
	if strings.HasPrefix(op, "fault-") {
		if code == 0 {
			t.Fatal("deliberately interrupted XFRM creation falsely succeeded")
		}
		journalState, loadErr := state.NewFileStore(opts.stateRoot).Load(ctx)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		journal, found := journalState.FindIPsecXFRMOperation(l.ID)
		expectedPhase, expectedIndex := state.IPsecXFRMIndexed, true
		if op == "fault-index" {
			expectedPhase, expectedIndex = state.IPsecXFRMIssuingCreate, false
		}
		if op == "fault-address" {
			expectedPhase = state.IPsecXFRMAliased
		}
		if !found || journal.Phase != expectedPhase || (journal.IfIndex > 0) != expectedIndex {
			t.Fatalf("original XFRM ifindex/crash checkpoint lost: %+v", journal)
		}
		profile, _ := ipsec.NewProfile(l)
		iface, err := net.InterfaceByName(profile.InterfaceName)
		if err != nil || iface.Index <= 0 {
			t.Fatal("real partially created kernel device missing")
		}
		if expectedIndex && iface.Index != journal.IfIndex {
			t.Fatal("journal ifindex differs from original kernel device")
		}
		t.Logf("ISOLATED_XFRM_CRASH_CHECKPOINT=PASS case=%s phase=%s", op, expectedPhase)
		return
	}
	if op == "reconcile-xfrm-deny" || op == "ensure-reject" {
		if code == 0 {
			t.Fatal("unsafe automatic retry/deletion succeeded despite interrupted journal")
		}
		t.Logf("ISOLATED_IPSEC_UNCERTAIN_EFFECT_FAIL_CLOSED=PASS op=%s", op)
		return
	}
	if code != 0 {
		// Outputs in this deliberately SENSITIVE execution are never logged
		// in full on failure. Only exit status and fixed operation are safe.
		t.Fatalf("canonical CLI IPsec %s failed with exit %d", op, code)
	}
	if op == "status" {
		var envelope struct {
			InterfaceVerified bool                  `json:"interface_verified"`
			IPsecState        ipsec.DiagnosticState `json:"ipsec_state"`
		}
		if json.Unmarshal(out.Bytes(), &envelope) != nil || !envelope.InterfaceVerified ||
			!envelope.IPsecState.ConnectionConfigured || !envelope.IPsecState.SecurityAssociationPresent {
			t.Fatal("canonical IPsec CLI status did not verify live negotiated SA")
		}
	}
	if op == "diagnose" {
		var report struct {
			SchemaVersion int `json:"schema_version"`
			MTU           struct {
				SelectedMTU int `json:"selected_mtu"`
			} `json:"mtu"`
			Quality struct {
				PacketsReceived int `json:"packets_received"`
			} `json:"quality"`
		}
		if json.Unmarshal(out.Bytes(), &report) != nil || report.SchemaVersion != 1 ||
			report.MTU.SelectedMTU <= 0 || report.Quality.PacketsReceived <= 0 {
			t.Fatal("IPsec diagnose failed to measure Link Address packet traffic")
		}
	}
	if op == "cross-list" {
		var listing struct {
			SchemaVersion int `json:"schema_version"`
			Links         []struct {
				ID string `json:"id"`
			} `json:"links"`
		}
		if json.Unmarshal(out.Bytes(), &listing) != nil || listing.SchemaVersion != 1 {
			t.Fatal("five-backend persisted inventory unavailable")
		}
		expected := map[string]bool{
			"lnk_11111111111111111111111111111111": true,
			"lnk_22222222222222222222222222222222": true,
			"lnk_33333333333333333333333333333333": true,
			"lnk_88888888888888888888888888888888": true,
			"lnk_cccccccccccccccccccccccccccccccc": true,
		}
		if len(listing.Links) != len(expected) {
			t.Fatal("five simultaneous backend Links not persisted")
		}
		for _, item := range listing.Links {
			if !expected[item.ID] {
				t.Fatal("missing or duplicate five-backend persisted Link")
			}
			delete(expected, item.ID)
		}
		if len(expected) != 0 {
			t.Fatal("five-backend Link identity set incomplete")
		}
	}
	if op == "doctor" {
		var report struct {
			ActivationAllowed bool `json:"activation_allowed"`
		}
		if json.Unmarshal(out.Bytes(), &report) != nil || !report.ActivationAllowed {
			t.Fatal("injected admitted fixture should report admitted time-local status")
		}
	}
	if op == "remove" || op == "retire" || op == "reconcile-remove" {
		// Credential retirement is part of the returned success contract,
		// not an optional background cleanup.
		stored, err := ipsec.NewPSKStore(opts.stateRoot)
		if err != nil {
			t.Fatal("protected credential directory is unavailable")
		}
		_, keyErr := stored.Load(l.ID)
		if !errors.Is(keyErr, os.ErrNotExist) {
			t.Fatalf("committed IPsec Remove left unexpected credential state: %v", keyErr)
		}
		snapshot, err := state.NewFileStore(opts.stateRoot).Load(ctx)
		if err != nil {
			t.Fatal("cannot verify post-Remove retirement state")
		}
		if _, still := snapshot.Find(l.ID); still {
			t.Fatal("removed Link remains in state")
		}
		receipt, ok := snapshot.FindIPsecRemovalReceipt(l.ID)
		if !ok || !receipt.Retired {
			t.Fatal("protected key retirement lacks a completed durable receipt")
		}
	}
	if op == "create" || op == "import" {
		if strings.Contains(out.String(), "stl://") || strings.Contains(out.String(), "PSK=") {
			t.Fatal("canonical CLI JSON leaked a sensitive handoff or credential")
		}
	}
	t.Logf("CANONICAL_STL_CLI_IPSEC_%s=PASS peer=%s link=%s encap=%s", strings.ToUpper(op), side, suffix, encap)
}

// TestIsolatedNativeExclusiveOperationalPreflight introspects the exact
// production backend's non-mutating Inspect/Plan/Validate after systemd
// restart, so a failed admission, XFRM inventory or route cannot be hidden
// behind the CLI's intentionally redacted public failure envelope.
func TestIsolatedNativeExclusiveOperationalPreflight(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" ||
		os.Geteuid() != 0 {
		t.Skip("requires disconnected privileged systemd acceptance fixture")
	}
	phase := os.Getenv("STL_IPSEC_PREFLIGHT_OPERATION")
	if phase != "ensure" && phase != "remove" {
		t.Fatal("invalid bounded fixture phase")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("missing Docker marker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	observedRoute, err := (linux.ExecRunner{}).Run(ctx, "/usr/sbin/ip", "-4", "route", "show", "default")
	if err != nil || len(bytes.TrimSpace(observedRoute.Stdout)) != 0 {
		t.Fatal("preflight refuses a connected or uninspectable test container")
	}
	admission := ipsec.NewNativeRuntimeAdmission()
	if err := admission.Authorize(ctx); err != nil {
		t.Fatalf("native-exclusive origin not attested: %v", err)
	}
	keys, err := ipsec.NewPSKStore(state.DefaultRoot)
	if err != nil {
		t.Fatal("protected PSK store unavailable")
	}
	writer, err := ipsec.NewScopedWriter(ipsec.NativeExclusiveVICIPath)
	if err != nil {
		t.Fatal("private VICI endpoint unavailable")
	}
	route := linux.RouteResolver{Runner: linux.ExecRunner{}}
	impl, err := ipsec.NewOperationalBackend(ipsec.OperationalOptions{
		Admission: admission, Runner: ipsec.BoundedExecRunner{}, Keys: keys,
		Writer: writer, Routes: ipsec.HostRouteResolveFunc(func(ctx context.Context, peer netip.Addr) (ipsec.HostRoute, error) {
			observed, err := route.Resolve(ctx, peer)
			if err != nil {
				return ipsec.HostRoute{}, err
			}
			return ipsec.HostRoute{Source: observed.Source, Device: observed.Device}, nil
		}),
		XFRM:     ipsec.NewXFRMVacancyInspector("ip"),
		SetAlias: linux.SetLinkAliasByIndex, AddAddr: linux.AddIPv4AddressByIndex,
		SetUp: linux.SetLinkUpByIndex, Delete: linux.DeleteLinkByIndex,
	})
	if err != nil {
		t.Fatal("native operational backend cannot be assembled")
	}
	snapshot, err := state.NewFileStore(state.DefaultRoot).Load(ctx)
	if err != nil {
		t.Fatalf("cannot load canonical committed state: %v", err)
	}
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	record, ok := snapshot.Find(id)
	if !ok {
		t.Fatal("target IPsec Link is not committed")
	}
	req := backend.Request{Operation: backend.OperationEnsure, Link: record.Desired,
		Prior: &record.Desired, OwnedResources: record.OwnedResources}
	if phase == "remove" {
		req.Operation = backend.OperationRemove
	}
	observed, err := impl.Inspect(ctx, record.Desired)
	if err != nil {
		t.Fatalf("READ_ONLY_IPSEC_PREFLIGHT_%s_INSPECT_FAILED: %v", phase, err)
	}
	plan, err := impl.Plan(ctx, req, observed)
	if err != nil {
		t.Fatalf("READ_ONLY_IPSEC_PREFLIGHT_%s_PLAN_FAILED: %v", phase, err)
	}
	if err = impl.Validate(ctx, req, observed, plan); err != nil {
		t.Fatalf("READ_ONLY_IPSEC_PREFLIGHT_%s_VALIDATE_FAILED: %v", phase, err)
	}
	t.Logf("READ_ONLY_NATIVE_IPSEC_%s_PREFLIGHT=PASS", strings.ToUpper(phase))
}
