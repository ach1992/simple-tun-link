//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/quichelper"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// These synthetic public fields validate disclosure/UI behavior only. They
// never claim a real manager, process, guard, inode or kernel generation.
func quicUITestGeneration(offer quicOffer) state.QUICGeneration {
	digest := strings.Repeat("a", 64)
	token := offer.ReceiverTLS["authorization-token"]
	auth := sha256.Sum256(token[:64])
	obfuscation := ""
	if secret, ok := offer.ReceiverTLS["obfs-secret"]; ok {
		digest := sha256.Sum256(secret[:64])
		obfuscation = hex.EncodeToString(digest[:])
	}
	return state.QUICGeneration{Version: 1, OriginNonce: strings.Repeat("b", 32), MaterialNonce: strings.Repeat("c", 32),
		KernelBootID: "11111111-2222-4333-8444-555555555555", KernelBootSource: hostidentity.VerifiedHostBootSourceV1,
		NetworkNS: "net:[4012345678]", WGIfIndex: 77, GuardTableHandle: 11, GuardChainHandle: 12, GuardRuleHandle: 13,
		ExecutablePath: quic.DefaultExecutable, ExecutableSHA256: quic.PinnedAMD64SHA256, ExecutableDevice: 1, ExecutableInode: 2,
		Files: state.QUICFileIdentity{Certificate: digest, TLSKey: digest, TrustCA: digest, Authorization: hex.EncodeToString(auth[:]), ObfuscationSHA256: obfuscation, HelperConfig: digest,
			DirectoryDevice: 1, DirectoryInode: 3, ReceiptDevice: 1, ReceiptInode: 4}}
}

func quicSavedUIFixture(t *testing.T) (*runtimeOptions, quicOffer, string, []byte) {
	t.Helper()
	offer, raw := testQUICOffer(t)
	root := filepath.Join(t.TempDir(), "state")
	options := &runtimeOptions{stateRoot: root}
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: offer.Sender, QUICGeneration: quicUITestGeneration(offer)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "receiver.json")
	if err := writeSensitiveHandoff(path, append(append([]byte(nil), raw...), '\n')); err != nil {
		t.Fatal(err)
	}
	return options, offer, path, raw
}

func TestQUICSavedHandoffBindsOriginalSenderIssuanceAndPrivateFile(t *testing.T) {
	options, offer, path, raw := quicSavedUIFixture(t)
	if got, err := validatedExternalQUICMenuOffer(options, offer.Sender, path); err != nil || got != string(raw) {
		t.Fatalf("original QUIC private offer refused: %v", err)
	}
	if _, err := validatedExternalQUICMenuOffer(options, offer.Receiver, path); err == nil {
		t.Fatal("importing peer acquired sender re-export authority")
	}
	if _, err := validatedSavedProtectedMenuOffer(options, offer.Sender); !errors.Is(err, errProtectedMenuOfferMissing) {
		t.Fatal("missing menu offer incorrectly adopted", err)
	}
	var replaced quicOffer
	if json.Unmarshal(raw, &replaced) != nil {
		t.Fatal("fixture decode failed")
	}
	defer replaced.clear()
	listen, dial, err := quic.GeneratePair(offer.Sender.ID, offer.Sender.Underlay.Local.String())
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	replaced.ReceiverTLS = dial.ProtectedFiles()
	if replaced.validate() != nil {
		t.Fatal("replacement should be syntactically valid")
	}
	if quicOfferMatchesSenderGeneration(replaced, state.LinkRecord{Desired: offer.Sender, QUICGeneration: quicUITestGeneration(offer)}) {
		t.Fatal("new token was allowed to impersonate the original issuance")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedExternalQUICMenuOffer(options, offer.Sender, path); err == nil {
		t.Fatal("public private-offer file accepted")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, append(append([]byte(nil), raw...), '\n')) {
		t.Fatal("failed disclosure mutated original file")
	}
}

func TestQUICReadOnlyDiagnosticsSeparatesLocalStateFromPeerProof(t *testing.T) {
	options, offer, _, raw := quicSavedUIFixture(t)
	name, err := wg.InterfaceName(offer.Sender.ID)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	options.quicObserver = func(_ context.Context, id domain.LinkID) (app.QUICInspection, error) {
		calls++
		if id != offer.Sender.ID {
			t.Fatal("wrong observed owner")
		}
		return app.QUICInspection{Interface: name, IfIndex: 77, KernelPresent: true, GuardActive: true, HelperActive: true, HelperLoaded: true}, nil
	}
	options.quicHelperObserver = func(context.Context, domain.Link) (quichelper.HelperDiagnostics, error) {
		return quichelper.HelperDiagnostics{GuardObserved: true, HelperObserved: true, GuardPresent: true, HelperPresent: true, HelperLoaded: true,
			State: "active", Authentication: "not_observed", Handshake: "not_observed", MaterialState: "verified", JournalState: "observed"}, nil
	}
	var out, errOut bytes.Buffer
	if code := linkQUICDiagnoseCommand([]string{"diagnose-quic", string(offer.Sender.ID), "--json"}, &out, &errOut, options); code != 0 || errOut.Len() != 0 || calls != 1 {
		t.Fatal("read-only QUIC diagnostics failed")
	}
	var result QUICLinkDiagnostics
	if json.Unmarshal(out.Bytes(), &result) != nil || !result.QUICHelperActive || result.WireGuardHandshakeObserved ||
		result.AuthenticationObservation != "not_observable_from_process_state" || result.TrafficObservation != "not_tested_by_read_only_diagnostics" {
		t.Fatal("local process observation became a peer traffic/authentication claim")
	}
	if bytes.Contains(out.Bytes(), raw) || bytes.Contains(out.Bytes(), []byte(offer.ReceiverWGKey)) {
		t.Fatal("private offer escaped diagnostics")
	}
	options.quicObserver = func(context.Context, domain.LinkID) (app.QUICInspection, error) {
		return app.QUICInspection{}, errors.New("DO_NOT_LOG_PRIVATE_RUNTIME_CAUSE")
	}
	out.Reset()
	errOut.Reset()
	if code := linkQUICDiagnoseCommand([]string{"diagnose-quic", string(offer.Sender.ID), "--json"}, &out, &errOut, options); code == 0 || strings.Contains(out.String()+errOut.String(), "DO_NOT_LOG") {
		t.Fatal("unverified runtime was healthy or private cause leaked")
	}
}

func TestQUICUninstallNeedsOriginalTerminationEvenForRetiredReceipt(t *testing.T) {
	offer, _ := testQUICOffer(t)
	snapshot := state.Snapshot{RemovalReceipts: []state.RemovalReceipt{{LinkID: offer.Sender.ID, Backend: domain.BackendWireGuardQUIC,
		LocalPublicKey: offer.Sender.WireGuard.LocalPublicKey, QUICLink: offer.Sender, QUICGeneration: quicUITestGeneration(offer), Retired: true}}}
	if uninstallSnapshotReady(snapshot) {
		t.Fatal("retired flag bypassed missing original termination proof")
	}
	snapshot.RemovalReceipts[0].QUICOriginalTermination = state.QUICOriginalExactIfIndexDeleted
	if !uninstallSnapshotReady(snapshot) {
		t.Fatal("fully retired original receipt blocked uninstall")
	}
	snapshot.RemovalReceipts[0].Retired = false
	if uninstallSnapshotReady(snapshot) {
		t.Fatal("unfinished credential retirement allowed uninstall")
	}
}

func TestQUICHelperDiagnosticsExposeClassifiedEventsAndBoundPartialRead(t *testing.T) {
	options, offer, _, _ := quicSavedUIFixture(t)
	name, _ := wg.InterfaceName(offer.Sender.ID)
	options.quicObserver = func(context.Context, domain.LinkID) (app.QUICInspection, error) {
		return app.QUICInspection{Interface: name, IfIndex: 77, KernelPresent: true, GuardActive: true, HelperActive: true, HelperLoaded: true}, nil
	}
	options.quicHelperObserver = func(context.Context, domain.Link) (quichelper.HelperDiagnostics, error) {
		return quichelper.HelperDiagnostics{GuardObserved: true, HelperObserved: true, GuardPresent: true, HelperPresent: true, HelperLoaded: true,
			State: "active", Authentication: "observed", Handshake: "observed", MaterialState: "verified", JournalState: "observed", RestartCount: 2,
			Events: []quichelper.HelperEvent{{TimestampUSec: 1700000000000000, Level: "info", Event: "transport_connected"}}}, nil
	}
	var out, errOut bytes.Buffer
	if code := linkQUICDiagnoseCommand([]string{"diagnose-quic", string(offer.Sender.ID), "--json"}, &out, &errOut, options); code != 0 {
		t.Fatal("classified helper diagnostic failed")
	}
	var result QUICLinkDiagnostics
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Helper == nil || result.Helper.RestartCount != 2 || len(result.Helper.Events) != 1 || result.Helper.Events[0].Event != "transport_connected" ||
		!strings.Contains(result.AuthenticationObservation, "attributed current-invocation") || result.TrafficObservation != "not_tested_by_read_only_diagnostics" {
		t.Fatal("helper event evidence was lost or promoted to application proof")
	}
	options.quicHelperObserver = func(context.Context, domain.Link) (quichelper.HelperDiagnostics, error) {
		return quichelper.HelperDiagnostics{GuardObserved: true, HelperObserved: true, GuardPresent: true, HelperPresent: true, HelperLoaded: true,
			State: "active", Authentication: "not_observed", Handshake: "not_observed", MaterialState: "verified", JournalState: "unavailable"}, errors.New("UNTRUSTED_RAW_JOURNAL_SECRET")
	}
	out.Reset()
	errOut.Reset()
	if code := linkQUICDiagnoseCommand([]string{"diagnose-quic", string(offer.Sender.ID), "--json"}, &out, &errOut, options); code != 0 {
		t.Fatal("proven local state discarded because historical events were unavailable")
	}
	if strings.Contains(out.String()+errOut.String(), "UNTRUSTED_RAW") || !strings.Contains(out.String(), "quic_journal_unavailable") {
		t.Fatal("partial helper evidence was not explicitly bounded and sanitized")
	}
}

func TestQUICHelperObservationRechecksCommittedGenerationBeforePublishing(t *testing.T) {
	options, offer, _, _ := quicSavedUIFixture(t)
	name, _ := wg.InterfaceName(offer.Sender.ID)
	options.quicObserver = func(context.Context, domain.LinkID) (app.QUICInspection, error) {
		return app.QUICInspection{Interface: name, IfIndex: 77, KernelPresent: true, GuardActive: true, HelperActive: true, HelperLoaded: true}, nil
	}
	options.quicHelperObserver = func(ctx context.Context, _ domain.Link) (quichelper.HelperDiagnostics, error) {
		if err := state.NewFileStore(options.stateRoot).Update(ctx, func(s *state.Snapshot) error {
			record, ok := s.Find(offer.Sender.ID)
			if !ok {
				return errors.New("fixture owner missing")
			}
			record.QUICGeneration.Files.HelperConfig = strings.Repeat("d", 64)
			s.Upsert(record)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return quichelper.HelperDiagnostics{GuardObserved: true, HelperObserved: true, GuardPresent: true, HelperPresent: true, HelperLoaded: true, State: "active", JournalState: "observed"}, nil
	}
	var out, errOut bytes.Buffer
	if code := linkQUICDiagnoseCommand([]string{"diagnose-quic", string(offer.Sender.ID), "--json"}, &out, &errOut, options); code == 0 || !strings.Contains(out.String(), "quic_observation_changed") {
		t.Fatal("different generation's helper data was published as the original observation")
	}
}

func TestQUICAbandonmentReceiptBlocksUninstallUntilFullyRetired(t *testing.T) {
	offer, _ := testQUICOffer(t)
	g := quicUITestGeneration(offer)
	plan, err := composition.QUICHostPlanForLink(offer.Sender)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composition.WireGuardProviderClaims(offer.Sender.ID, offer.Sender.Addresses.Local, offer.Sender.WireGuard)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := plan.Local.CarrierClaims()
	if err != nil {
		t.Fatal(err)
	}
	var claims []domain.ResourceClaim
	seen := map[string]bool{}
	for _, claim := range append(provider, carrier...) {
		if !seen[claim.Canonical()] {
			seen[claim.Canonical()] = true
			claims = append(claims, claim)
		}
	}
	op := state.QUICCrashOperation{Plan: plan, Addresses: offer.Sender.Addresses, WireGuard: offer.Sender.WireGuard, Nonce: g.MaterialNonce, Resources: claims,
		CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization, HelperConfigSHA256: g.Files.HelperConfig,
		ExecutablePath: g.ExecutablePath, ExecutableSHA256: g.ExecutableSHA256, ExecutableDevice: g.ExecutableDevice, ExecutableInode: g.ExecutableInode,
		Managed: &state.QUICManagedOperation{Version: 1, KernelBootID: g.KernelBootID, KernelBootSource: g.KernelBootSource, Intent: offer.Sender, Operation: "ensure"}}
	receipt := state.QUICAbandonmentReceipt{Operation: op, Files: g.Files,
		ReconciledKernelBootID: "22222222-3333-4444-8555-666666666666", ReconciledKernelBootSource: hostidentity.VerifiedHostBootSourceV1}
	if err := receipt.Validate(); err != nil {
		t.Fatal("synthetic maintenance fixture invalid", err)
	}
	snapshot := state.Snapshot{QUICAbandonmentReceipts: []state.QUICAbandonmentReceipt{receipt}}
	if uninstallSnapshotReady(snapshot) || uninstallSnapshotEmpty(snapshot) {
		t.Fatal("unfinished abandoned material allowed destructive maintenance")
	}
	snapshot.QUICAbandonmentReceipts[0].Retired = true
	if !uninstallSnapshotReady(snapshot) || uninstallSnapshotEmpty(snapshot) {
		t.Fatal("fully retired history must allow uninstall but remain a downgrade reservation")
	}
	snapshot.QUICAbandonmentReceipts[0].ReconciledKernelBootID = g.KernelBootID
	if uninstallSnapshotReady(snapshot) {
		t.Fatal("retired flag bypassed missing kernel extinction proof")
	}
}
