package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/app"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Deliberately independent v1 sender request. Adding fields to domain.Link or
// the frozen public desired Link v1 contract cannot expand this input silently.
// No private bytes are accepted in JSON; the sender and recipient keys are
// generated independently from crypto/rand inside the authenticated CLI.
type wireGuardSenderRequestV1 struct {
	SchemaVersion  int                    `json:"schema_version"`
	LinkID         domain.LinkID          `json:"link_id,omitempty"`
	DisplayName    string                 `json:"display_name,omitempty"`
	Underlay       desiredUnderlayV1      `json:"underlay"`
	Addresses      desiredLinkAddressesV1 `json:"addresses"`
	ListenPort     uint16                 `json:"listen_port"`
	PeerPort       uint16                 `json:"peer_port"`
	LocalKeepalive uint16                 `json:"local_keepalive,omitempty"`
	PeerKeepalive  uint16                 `json:"peer_keepalive,omitempty"`
}

type wireGuardSenderResult struct {
	SchemaVersion        int                  `json:"schema_version"`
	Operation            string               `json:"operation"`
	LinkID               domain.LinkID        `json:"link_id"`
	PairingSchemaVersion int                  `json:"pairing_schema_version"`
	Mode                 pairing.ExchangeMode `json:"mode"`
	Sensitive            bool                 `json:"sensitive"`
	HandoffFile          string               `json:"handoff_file"`
	Changed              bool                 `json:"changed"`
}

func decodeWireGuardSenderRequest(in io.Reader) (wireGuardSenderRequestV1, error) {
	if in == nil {
		return wireGuardSenderRequestV1{}, fmt.Errorf("missing WireGuard creator input")
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxDesiredLinkBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDesiredLinkBytes || !utf8.Valid(raw) {
		return wireGuardSenderRequestV1{}, fmt.Errorf("invalid or oversized WireGuard creator input")
	}
	if err = ensureUnambiguousJSON(raw); err != nil {
		return wireGuardSenderRequestV1{}, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var request wireGuardSenderRequestV1
	if err = d.Decode(&request); err != nil {
		return wireGuardSenderRequestV1{}, fmt.Errorf("invalid WireGuard creator fields")
	}
	if request.SchemaVersion != 1 {
		return wireGuardSenderRequestV1{}, stlerr.New(stlerr.CodeUnsupported, "link_create_wireguard", "", "", "unsupported WireGuard creator schema version")
	}
	if request.LinkID != "" && request.LinkID.Validate() != nil {
		return wireGuardSenderRequestV1{}, fmt.Errorf("invalid explicit Link ID")
	}
	return request, nil
}

func (r wireGuardSenderRequestV1) link(id domain.LinkID, local, peer string) domain.Link {
	return domain.Link{ID: id, DisplayName: r.DisplayName,
		Underlay:  domain.Underlay{Local: r.Underlay.Local, Peer: r.Underlay.Peer},
		Addresses: domain.LinkAddresses{Local: r.Addresses.Local, Peer: r.Addresses.Peer},
		Backend:   domain.BackendWireGuard, Encapsulation: domain.EncapUDP,
		WireGuard: domain.WireGuardOptions{LocalPublicKey: local, PeerPublicKey: peer,
			ListenPort: r.ListenPort, PeerPort: r.PeerPort,
			LocalKeepalive: r.LocalKeepalive, PeerKeepalive: r.PeerKeepalive},
	}
}

func wireGuardCreationError(out, errOut io.Writer, isJSON bool, code stlerr.Code, id domain.LinkID, detail string) int {
	var result *app.Result
	if id.Validate() == nil {
		result = &app.Result{LinkID: id}
	}
	return lifecycleFailure(out, errOut, isJSON, code, "link_create_wireguard", result, detail)
}

// create-wireguard is deliberately explicit and non-idempotent for new key
// material; a lost/interrupted attempt MUST be reconciled via its handoff and
// the separate resume-wireguard path, not silently generate replacement keys.
func linkCreateWireGuardCommand(args []string, input io.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := slices.Contains(args, "--json")
	if !((len(args) == 4 || (len(args) == 5 && args[4] == "--json")) &&
		args[0] == "create-wireguard" && args[1] == "--stdin" && args[2] == "--output") {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "link_create_wireguard",
			"usage: stl link create-wireguard --stdin --output <absolute-private-file> [--json]")
	}
	output := args[3]
	request, err := decodeWireGuardSenderRequest(input)
	if err != nil {
		code := stlerr.CodeInvalid
		if stlerr.CodeOf(err) == stlerr.CodeUnsupported {
			code = stlerr.CodeUnsupported
		}
		return wireGuardCreationError(out, errOut, isJSON, code, "", "invalid or unsupported WireGuard sender request")
	}
	id := request.LinkID
	if id == "" {
		identity := domain.NewLinkID
		if opts != nil && opts.createLinkID != nil {
			identity = opts.createLinkID
		}
		id, err = identity()
		if err != nil || id.Validate() != nil {
			return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, "", "cannot allocate WireGuard Link ID")
		}
	}
	// Check runtime and output path before creating or persisting ANY new
	// sender/recipient private key. This is only an early check: the final
	// no-clobber publication is repeated inside the Engine transaction.
	if err = checkSensitiveHandoffDestination(output); err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeInvalid, id,
			"SENSITIVE handoff destination unsafe or already exists; nothing staged")
	}
	if opts == nil {
		opts, err = productionRuntimeOptions()
		if err != nil {
			return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id,
				"sender runtime unavailable before handoff publication")
		}
	}
	runtime, err := buildRuntimeEngine(*opts)
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id,
			"cannot initialize canonical sender Engine before handoff publication")
	}
	keys, err := wgbackend.NewKeyStore(opts.stateRoot)
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id,
			"protected sender KeyStore unavailable before handoff publication")
	}
	local, localPub, err := wgbackend.GenerateKeyPair()
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id, "cannot generate local WireGuard identity")
	}
	defer local.Zeroize()
	receiver, peerPub, err := wgbackend.GenerateKeyPair()
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id, "cannot generate receiver WireGuard identity")
	}
	defer receiver.Zeroize()
	link := request.link(id, localPub, peerPub)
	if err = link.Validate(); err != nil || link.WireGuard.ListenPort == 0 || link.WireGuard.PeerPort == 0 ||
		!link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeInvalid, id, "invalid WireGuard endpoint, Link Address, or listen port configuration")
	}
	peerCredential := []byte(receiver.SecretWireValue())
	defer clear(peerCredential)
	offer, err := pairing.NewQuickOffer(link, peerCredential)
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeInvalid, id, "cannot create identity-bound Quick Link")
	}
	defer offer.ClearRecipientCredential()
	block, err := offer.EncodeSetupLink()
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id, "cannot encode protected recipient Quick Link")
	}
	localCredential := []byte(local.SecretWireValue())
	defer clear(localCredential)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	timed, cancel := context.WithTimeout(ctx, lifecycleTimeLimit)
	defer cancel()
	// The Engine owns staging and publication ordering under the SAME
	// maintenance + Link lock as normal Ensure/Remove/recipient Import.
	write := writeSensitiveHandoff
	if opts != nil && opts.writeHandoff != nil {
		write = opts.writeHandoff
	}
	result, err := runtime.CreateWireGuardSender(timed, link, localCredential,
		setupLinkConfirmation(block), keys, func() error {
			return write(output, []byte(block+"\n"))
		})
	if err != nil || result.LinkID != id || result.Removed {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, id,
			"sender Create not confirmed: key/pending staging or handoff publication may be partial; inspect protected file and committed state before exact Resume/reconciliation")
	}
	if isJSON {
		if err = json.NewEncoder(out).Encode(wireGuardSenderResult{SchemaVersion: jsonSchemaVersion, Operation: "link_create_wireguard", LinkID: id,
			PairingSchemaVersion: pairing.WireGuardSchemaVersion, Mode: pairing.ModeQuick, Sensitive: true, HandoffFile: output, Changed: result.Changed}); err != nil {
			fmt.Fprintln(errOut, "WireGuard Link may be active but result could not be written; inspect saved state and private handoff")
			return 1
		}
	} else {
		fmt.Fprintf(out, "WireGuard Link %s locally ensured; SENSITIVE v3 receiver handoff written to the explicitly requested private file.\n", id)
		fmt.Fprintln(out, "Verify peer identity out-of-band. Receiver: preview and confirmed import of the protected setup link; check actual handshake/traffic separately.")
		fmt.Fprintln(out, "Do not treat local Ensure as proof of bidirectional connectivity. Delete the SENSITIVE export after deliberate delivery and acceptance.")
	}
	return 0
}

// Replay an explicitly confirmed *sender-oriented* v3 handoff without
// generating a new keypair or reprovisioning an existing credential. This
// makes a failure after protected handoff publication recoverable, while
// canonical Engine rejects same-ID desired-state reconfiguration.
func linkResumeWireGuardCommand(args []string, input io.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := slices.Contains(args, "--json")
	if !((len(args) == 4 || (len(args) == 5 && args[4] == "--json")) &&
		args[0] == "resume-wireguard" && args[1] == "--stdin" && args[2] == "--confirm" && len(args[3]) == 64 && !strings.ContainsAny(args[3], " \t\r\n")) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "link_resume_wireguard",
			"usage: stl link resume-wireguard --stdin --confirm <preview-token> [--json]")
	}
	raw, err := readSetupLink(input)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "link_resume_wireguard", "invalid SENSITIVE sender handoff input")
	}
	offer, err := pairing.DecodeSetupLink(raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(setupLinkConfirmation(raw)), []byte(args[3])) != 1 || offer.Preview().SchemaVersion != pairing.WireGuardSchemaVersion || offer.Link().Backend != domain.BackendWireGuard ||
		offer.CredentialKind() != pairing.CredentialWireGuardPrivateKey || !offer.IsSensitive() ||
		offer.Link().WireGuard.ListenPort == 0 || offer.Link().WireGuard.PeerPort == 0 {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "link_resume_wireguard", "handoff identity, confirmation, or WireGuard v3 data is invalid")
	}
	defer offer.ClearRecipientCredential()
	link := offer.Link()
	if opts == nil {
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "link_resume_wireguard", "runtime unavailable")
		}
	}
	// Resume requires exact persistent pending intent + original handoff digest,
	// or an already committed identical sender Link, and verifies KeyStore
	// public identity before canonical Engine reapply. No rekeying.
	return executeSenderResume(link, setupLinkConfirmation(raw), isJSON, out, errOut, opts)
}

func executeSenderResume(link domain.Link, digest string, isJSON bool, out, errOut io.Writer, opts *runtimeOptions) int {
	runtime, err := buildRuntimeEngine(*opts)
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, link.ID, "cannot initialize WireGuard resume runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleTimeLimit)
	defer cancel()
	keys, err := wgbackend.NewKeyStore(opts.stateRoot)
	if err != nil {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, link.ID,
			"cannot open protected sender KeyStore for exact Resume")
	}
	result, err := runtime.ResumeWireGuardSender(ctx, link, digest, keys)
	if err != nil || result.LinkID != link.ID || result.Removed {
		return wireGuardCreationError(out, errOut, isJSON, stlerr.CodeState, link.ID, "sender retry unconfirmed; reconcile persisted Link and protected local credential")
	}
	if isJSON {
		return encodeSenderResume(out, errOut, result)
	}
	fmt.Fprintf(out, "WireGuard sender Link %s verified through canonical Engine (changed=%t). Receiver handoff remains SENSITIVE.\n", link.ID, result.Changed)
	return 0
}
func encodeSenderResume(out, errOut io.Writer, result app.Result) int {
	if err := json.NewEncoder(out).Encode(lifecycleResultResponse{SchemaVersion: jsonSchemaVersion, Operation: "link_resume_wireguard", LinkID: result.LinkID, Changed: result.Changed}); err != nil {
		fmt.Fprintln(errOut, "sender resumed but result could not be written")
		return 1
	}
	return 0
}
