package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	spoofbackend "github.com/ach1992/simple-tun-link/internal/backend/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// The field smoke revealed that a correctly provisioned but still DISCOVERING
// Spoof Link returned generic "observation_unverified" on CLI and menu. The
// private five-ping is intentionally not allowed before bilateral auth.
type spoofUnconfirmedBackend struct {
	backend.Backend
	ready bool
}

func (*spoofUnconfirmedBackend) Kind() domain.Backend { return domain.BackendSpoof }
func (b *spoofUnconfirmedBackend) DiagnosticState(_ context.Context, _ domain.Link) (spoofbackend.HostObservation, error) {
	return spoofbackend.HostObservation{RuntimeReady: b.ready, UnitExists: true, UnitOwned: true, UnitActive: true, HelperPID: 8745}, nil
}

type spoofNoProbeRunner struct{ calls int }

func (r *spoofNoProbeRunner) Run(context.Context, string, ...string) (linux.CommandResult, error) {
	r.calls++
	return linux.CommandResult{}, errors.New("private_key=DO_NOT_ECHO_PROBE_ERROR")
}

func TestSpoofDisconnectedDiagnosisHasActionableCLIAndMenuReasonWithoutPing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := domain.Link{
		ID: "lnk_1234567890abcdef1234567890abcdef", Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("10.246.52.1"), Peer: netip.MustParseAddr("10.246.52.2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.248.55.1/32"), Peer: netip.MustParsePrefix("10.248.55.2/32")},
		Spoof: domain.SpoofOptions{Role: "creator", SourceFile: "/root/stl/spoof/sources.txt", OuterProtocol: "udp",
			ListenPort: 48001, PeerPort: 48002, LocalPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), MaterialSHA256: strings.Repeat("a", 64)},
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trap := &spoofNoProbeRunner{}
	mock := &spoofUnconfirmedBackend{ready: true}
	opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{mock}, probeRunner: trap}
	call := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		rc := runWithRuntime(args, &out, &errOut, opts)
		return rc, out.String(), errOut.String()
	}
	rc, raw, errs := call("link", "diagnose", string(link.ID), "--json")
	if rc != 1 || errs != "" {
		t.Fatalf("unexpected JSON failure: %d %q %q", rc, raw, errs)
	}
	var payload linkReadErrorResponse
	if e := json.Unmarshal([]byte(raw), &payload); e != nil {
		t.Fatal(e)
	}
	if payload.Error == nil || payload.Error.Code != stlerr.CodeInspect || payload.Error.Operation != "link_diagnose" ||
		payload.Error.ReasonCode != "spoof_bilateral_unconfirmed" ||
		!strings.Contains(payload.Error.NextStep, "spoof-status "+string(link.ID)) ||
		!strings.Contains(payload.Error.Detail, "no private ICMP probes") {
		t.Fatalf("non-actionable/non-specific Spoof JSON: %+v", payload.Error)
	}
	rc, _, human := call("link", "diagnose", string(link.ID))
	if rc != 1 || !strings.Contains(human, "spoof_bilateral_unconfirmed") || !strings.Contains(human, "Next:") {
		t.Fatalf("Spoof CLI human reason lost: %d %q", rc, human)
	}
	var menuOut, menuErr bytes.Buffer
	if code := menuCheckOneConnection(link.ID, &menuOut, &menuErr, opts); code != 1 || menuErr.Len() != 0 ||
		!strings.Contains(menuOut.String(), "spoof_bilateral_unconfirmed") ||
		!strings.Contains(menuOut.String(), "Run stl link spoof-status") {
		t.Fatalf("guided menu lacked precise Next check: code=%d out=%q err=%q", code, menuOut.String(), menuErr.String())
	}
	rc, all, errs := call("link", "diagnose", "--all", "--json")
	var inventory healthCenterResponse
	if e := json.Unmarshal([]byte(all), &inventory); e != nil {
		t.Fatal(e)
	}
	if rc != 1 || errs != "" || inventory.Total != 1 || inventory.Unknown != 1 || inventory.Observed != 0 ||
		len(inventory.Checks) != 1 || inventory.Checks[0].ReasonCode != "spoof_bilateral_unconfirmed" ||
		inventory.Checks[0].Observed != nil {
		t.Fatalf("all-Link diagnosis lost unconfirmed Spoof truth: code=%d %+v err=%q", rc, inventory, errs)
	}
	if trap.calls != 0 {
		t.Fatalf("unconfirmed Spoof triggered %d network/ICMP commands", trap.calls)
	}
	mock.ready = false
	rc, raw, errs = call("link", "diagnose", string(link.ID), "--json")
	if rc != 1 || errs != "" || !strings.Contains(raw, `"reason_code":"spoof_local_helper_unverified"`) {
		t.Fatalf("missing/unowned helper was not separately explained: %d %q %q", rc, raw, errs)
	}
	if trap.calls != 0 {
		t.Fatal("unverified helper triggered a private probe")
	}
}

func TestSpoofCreateMenuOrderAndCancelCopy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nonexistent")
	code, out, errOut := runMenuTest(t, root, "1\n10\nq\n\n8\n")
	if code != 0 || errOut != "" || !strings.Contains(out, "Create cancelled. No new Link was created.") ||
		strings.Contains(out, "Completed prerequisite preparation is not rolled back") {
		t.Fatalf("misleading cancel copy: code=%d out=%q err=%q", code, out, errOut)
	}
	before := strings.Index(out, "8  L2TPv3 / Direct-IP")
	after := strings.Index(out, "9  MASQUE / CONNECT-IP")
	spoof := strings.Index(out, "10  Spoof / Direct TUN")
	if before < 0 || after < 0 || spoof < 0 || !(before < after && after < spoof) {
		t.Fatalf("create choices are not in ascending order: 8=%d 9=%d 10=%d", before, after, spoof)
	}
}
