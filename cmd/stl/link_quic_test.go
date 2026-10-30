package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func testQUICCreateRequest() quicCreateRequest {
	return quicCreateRequest{SchemaVersion: 1,
		LinkID:     domain.LinkID("lnk_0123456789abcdef0123456789abcdef"),
		Underlay:   desiredUnderlayV1{Local: netip.MustParseAddr("198.51.100.21"), Peer: netip.MustParseAddr("203.0.113.34")},
		Addresses:  desiredLinkAddressesV1{Local: netip.MustParsePrefix("10.76.0.1/30"), Peer: netip.MustParsePrefix("10.76.0.2/30")},
		ListenPort: 51821, PeerPort: 51822, Role: "listen", UDPPort: 59443,
		RemoteForwardUDPPort: 53001, LocalKeepalive: 25, PeerKeepalive: 25}
}

func testQUICOffer(t *testing.T) (quicOffer, []byte) {
	t.Helper()
	r := testQUICCreateRequest()
	local, localPublic, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer local.Zeroize()
	peer, peerPublic, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Zeroize()
	sender, receiver, err := makeQUICPair(r, r.LinkID, localPublic, peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	listen, dial, err := quic.GeneratePair(r.LinkID, r.Underlay.Local.String())
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	offer := quicOffer{SchemaVersion: 1, Sender: sender, Receiver: receiver,
		ReceiverWGKey: peer.SecretWireValue(), ReceiverTLS: dial.ProtectedFiles()}
	raw, err := json.Marshal(offer)
	if err != nil {
		offer.clear()
		t.Fatal(err)
	}
	t.Cleanup(func() { offer.clear(); clear(raw) })
	return offer, raw
}

func TestQUICOfferRoundTripAndPublicPreviewKeepSecretsPrivate(t *testing.T) {
	offer, raw := testQUICOffer(t)
	decoded, contents, err := decodeQUICOffer(bytes.NewReader(append(append([]byte(nil), raw...), '\n')))
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.clear()
	defer clear(contents)
	if decoded.Sender != offer.Sender || decoded.Receiver != offer.Receiver || !bytes.Equal(contents, raw) {
		t.Fatal("QUIC receiver identity or exact confirmation bytes changed")
	}
	var out, errOut bytes.Buffer
	if code := linkQUICCommand([]string{"preview-quic", "--stdin", "--json"}, bytes.NewReader(raw), &out, &errOut, nil); code != 0 || errOut.Len() != 0 {
		t.Fatalf("public preview failed: code=%d", code)
	}
	var preview struct {
		Backend       domain.Backend `json:"backend"`
		Confirm       string         `json:"confirmation_sha256"`
		Sensitive     bool           `json:"sensitive"`
		PeerUnderlay  string         `json:"receiver_peer_underlay"`
		PeerPrivateIP string         `json:"receiver_peer_private_ip"`
		TLSListener   string         `json:"tls_listener_name"`
		LocalForward  uint16         `json:"receiver_forward_udp_port"`
		PeerForward   uint16         `json:"peer_forward_udp_port"`
	}
	if json.Unmarshal(out.Bytes(), &preview) != nil || preview.Backend != domain.BackendWireGuardQUIC || !preview.Sensitive || preview.Confirm != setupLinkConfirmation(string(raw)) {
		t.Fatal("public preview does not bind the exact private offer")
	}
	if preview.PeerUnderlay != offer.Receiver.Underlay.Peer.String() || preview.PeerPrivateIP != offer.Receiver.Addresses.Peer.String() ||
		preview.TLSListener != offer.Sender.Underlay.Local.String() || preview.LocalForward != offer.Receiver.QUIC.ForwardUDPPort || preview.PeerForward != 0 {
		t.Fatal("receiver confirmation concealed or reversed its peer endpoint, forwarding socket or effective TLS listener identity")
	}
	public, _ := json.Marshal(offer.Sender)
	for _, output := range [][]byte{out.Bytes(), public} {
		if bytes.Contains(output, []byte(offer.ReceiverWGKey)) || bytes.Contains(output, []byte("PRIVATE KEY")) {
			t.Fatal("private key escaped protected handoff")
		}
		for _, value := range offer.ReceiverTLS {
			if bytes.Contains(output, value) || bytes.Contains(output, []byte(base64.StdEncoding.EncodeToString(value))) {
				t.Fatal("QUIC protected material leaked into public output")
			}
		}
	}
}

func TestQUICOfferRejectsAmbiguityCrossBackendAndNonreciprocalIdentity(t *testing.T) {
	_, raw := testQUICOffer(t)
	cases := map[string][]byte{
		"duplicate-schema": bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"SCHEMA_VERSION":1`), 1),
		"unknown-field":    append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"extra-value":      append(append([]byte(nil), raw...), []byte(` {}`)...),
		"wrong-backend":    bytes.ReplaceAll(raw, []byte("wireguard-quic"), []byte("wireguard-wss")),
		"oversized":        []byte(strings.Repeat("x", 64<<10+1)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			offer, contents, err := decodeQUICOffer(bytes.NewReader(input))
			offer.clear()
			clear(contents)
			if err == nil {
				t.Fatal("invalid private offer accepted")
			}
		})
	}
	for _, change := range []struct {
		name   string
		mutate func(*quicOffer)
	}{
		{"reciprocal-wg-port", func(o *quicOffer) { o.Receiver.WireGuard.ListenPort++ }},
		{"same-role", func(o *quicOffer) { o.Receiver.QUIC.Role = o.Sender.QUIC.Role }},
		{"receiver-key", func(o *quicOffer) { o.ReceiverWGKey = strings.Repeat("A", 44) }},
		{"extra-tls-file", func(o *quicOffer) { o.ReceiverTLS["other-key.pem"] = []byte("untrusted") }},
		{"missing-auth", func(o *quicOffer) { delete(o.ReceiverTLS, "authorization-token") }},
	} {
		t.Run(change.name, func(t *testing.T) {
			var mutated quicOffer
			if json.Unmarshal(raw, &mutated) != nil {
				t.Fatal("fixture decode failed")
			}
			defer mutated.clear()
			change.mutate(&mutated)
			if mutated.validate() == nil {
				t.Fatal("mutated recipient identity accepted")
			}
		})
	}
}

func TestQUICImportRequiresExactPreviewBeforeAnyRuntimeOrStateWrite(t *testing.T) {
	_, raw := testQUICOffer(t)
	root := filepath.Join(t.TempDir(), "never-created")
	options := &runtimeOptions{stateRoot: root}
	for _, operation := range []string{"import-quic", "resume-quic"} {
		var out, errOut bytes.Buffer
		code := linkQUICCommand([]string{operation, "--stdin", "--confirm", strings.Repeat("0", 64), "--json"}, bytes.NewReader(raw), &out, &errOut, options)
		if code == 0 || errOut.Len() != 0 || !strings.Contains(out.String(), "preview confirmation differs") {
			t.Fatalf("%s did not reject stale confirmation", operation)
		}
		if _, err := os.Lstat(root); !os.IsNotExist(err) {
			t.Fatal("confirmation rejection touched the State root")
		}
	}
}

func TestQUICDesiredSchemaCannotBeConsumedAsNativeOrWSS(t *testing.T) {
	offer, _ := testQUICOffer(t)
	encode := func(version int, link domain.Link) []byte {
		raw, err := json.Marshal(struct {
			SchemaVersion int         `json:"schema_version"`
			Link          domain.Link `json:"link"`
		}{version, link})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if decoded, err := decodeDesiredLink(bytes.NewReader(encode(4, offer.Sender))); err != nil || decoded != offer.Sender {
		t.Fatalf("explicit QUIC public schema rejected: %v", err)
	}
	for _, version := range []int{1, 2, 3} {
		if _, err := decodeDesiredLink(bytes.NewReader(encode(version, offer.Sender))); err == nil {
			t.Fatalf("legacy schema %d acquired QUIC capability", version)
		}
	}
	native := offer.Sender
	native.Backend = domain.BackendWireGuard
	native.QUIC = domain.QUICOptions{}
	if _, err := decodeDesiredLink(bytes.NewReader(encode(4, native))); err == nil {
		t.Fatal("QUIC schema silently accepted another backend")
	}
}

func TestQUICActivationErrorRetainsEvidenceWithoutRawCause(t *testing.T) {
	const secret = "UNTRUSTED_PRIVATE_HELPER_DETAIL"
	id := testQUICCreateRequest().LinkID
	cause := stlerr.Wrap(stlerr.CodeApply, "ensure", string(id), string(domain.BackendWireGuardQUIC), secret, fmt.Errorf("%s", secret))
	causeWithEvidence := stlerr.WithEvidence(cause, stlerr.OperationEvidence{Stage: "apply", HostMutation: "attempted", DesiredState: "no_commit_attempted", Rollback: "incomplete", CredentialProvision: "attempted"})
	var out, errOut bytes.Buffer
	if code := quicActivationFailure("import-quic", true, id, app.Result{}, causeWithEvidence, "activation not verified; preserve the original offer", &out, &errOut); code != 1 || errOut.Len() != 0 {
		t.Fatal("unexpected error channel")
	}
	if strings.Contains(out.String(), secret) || !strings.Contains(out.String(), "rollback_incomplete") {
		t.Fatal("typed operation evidence lost or private cause leaked")
	}
	var response lifecycleFailureResponse
	if json.Unmarshal(out.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != stlerr.CodeApply {
		t.Fatal("canonical Apply failure was relabeled as a State failure")
	}
}

func TestQUICActivationFailurePreservesTypedCategories(t *testing.T) {
	const secret = "PRIVATE_QUIC_CAUSE_MUST_NOT_REACH_OUTPUT"
	const detail = "activation unconfirmed; preserve original material and inspect owned State"
	id := testQUICCreateRequest().LinkID
	cases := []struct {
		name                               string
		code                               stlerr.Code
		stage, mutation, desired, rollback string
		exit                               int
	}{
		{"invalid-before-apply", stlerr.CodeInvalid, "preflight", "not_attempted", "no_commit_attempted", "not_required", 2},
		{"unsupported-before-apply", stlerr.CodeUnsupported, "preflight", "not_attempted", "no_commit_attempted", "not_required", 4},
		{"inspection-before-apply", stlerr.CodeInspect, "inspect", "not_attempted", "no_commit_attempted", "not_required", 1},
		{"conflict-before-apply", stlerr.CodeConflict, "plan", "not_attempted", "no_commit_attempted", "not_required", 1},
		{"validation-before-apply", stlerr.CodeValidate, "validate", "not_attempted", "no_commit_attempted", "not_required", 1},
		{"apply-uncertain", stlerr.CodeApply, "apply", "attempted", "no_commit_attempted", "not_attempted", 1},
		{"verification-after-apply", stlerr.CodeVerify, "verify", "attempted", "no_commit_attempted", "completed_unverified", 1},
		{"state-publication-after-apply", stlerr.CodeState, "commit", "attempted", "visible_unconfirmed", "not_attempted", 1},
		{"rollback-after-apply", stlerr.CodeRollback, "apply", "attempted", "no_commit_attempted", "incomplete", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evidence := stlerr.OperationEvidence{Stage: tc.stage, HostMutation: tc.mutation, DesiredState: tc.desired, Rollback: tc.rollback}
			cause := stlerr.WithEvidence(stlerr.Wrap(tc.code, "ensure", string(id), string(domain.BackendWireGuardQUIC), secret, fmt.Errorf("%s", secret)), evidence)
			for _, machine := range []bool{true, false} {
				var out, errOut bytes.Buffer
				if exit := quicActivationFailure("create-quic", machine, id, app.Result{}, cause, detail, &out, &errOut); exit != tc.exit {
					t.Fatalf("typed failure exit=%d, want %d", exit, tc.exit)
				}
				if strings.Contains(out.String()+errOut.String(), secret) {
					t.Fatal("private cause or backend detail leaked")
				}
				if !machine {
					if out.Len() != 0 || !strings.Contains(errOut.String(), string(tc.code)+":") {
						t.Fatal("human failure category or channel changed")
					}
					continue
				}
				var response lifecycleFailureResponse
				if errOut.Len() != 0 || json.Unmarshal(out.Bytes(), &response) != nil || response.Error == nil {
					t.Fatal("machine failure is not one public JSON record")
				}
				if response.Error.Code != tc.code || response.Error.Detail != "create-quic: "+detail ||
					response.Error.Evidence == nil || *response.Error.Evidence != evidence {
					t.Fatal("canonical category, authored detail or stage evidence was lost")
				}
			}
		})
	}
}

func TestQUICActivationFailureUnknownCategoryIsInternalAndPrivate(t *testing.T) {
	const secret = "UNRECOGNIZED_CODE_AND_CAUSE_MUST_STAY_PRIVATE"
	id := testQUICCreateRequest().LinkID
	for _, cause := range []error{
		stlerr.Wrap(stlerr.Code(secret), "ensure", string(id), string(domain.BackendWireGuardQUIC), secret, fmt.Errorf("%s", secret)),
		fmt.Errorf("%s", secret),
	} {
		var out, errOut bytes.Buffer
		if exit := quicActivationFailure("import-quic", true, id, app.Result{}, cause, "activation unconfirmed", &out, &errOut); exit != 1 || errOut.Len() != 0 {
			t.Fatal("unknown cause did not remain a failed JSON operation")
		}
		var response lifecycleFailureResponse
		if json.Unmarshal(out.Bytes(), &response) != nil || response.Error == nil || response.Error.Code != stlerr.CodeInternal ||
			strings.Contains(out.String(), secret) {
			t.Fatal("unknown category or private cause escaped the safe fallback")
		}
	}
}

func TestQUICColdBootRecoveryRequiresExactConfirmationBeforeRuntime(t *testing.T) {
	root := filepath.Join(t.TempDir(), "untouched")
	id := string(testQUICCreateRequest().LinkID)
	var out, errOut bytes.Buffer
	if code := linkQUICColdBootReconcileCommand([]string{id, "--confirm", "lnk_ffffffffffffffffffffffffffffffff", "--json"}, &out, &errOut, &runtimeOptions{stateRoot: root}); code == 0 {
		t.Fatal("wrong original identity was accepted")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("rejected confirmation touched State")
	}
}
