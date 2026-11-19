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
	"syscall"

	"github.com/ach1992/simple-tun-link/internal/app"
	masquebackend "github.com/ach1992/simple-tun-link/internal/backend/masque"
	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/masquehost"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const maxMASQUEOfferBytes = 32 * 1024

// v1 MASQUE creator has a frozen, explicit public schema. Existing v1..v5
// Link input, WSS, QUIC and WireGuard pairing never accept this topology.
type masqueCreateRequestV1 struct {
	SchemaVersion           int                    `json:"schema_version"`
	LinkID                  domain.LinkID          `json:"link_id,omitempty"`
	DisplayName             string                 `json:"display_name,omitempty"`
	Underlay                desiredUnderlayV1      `json:"underlay"`
	Addresses               desiredLinkAddressesV1 `json:"addresses"`
	Role                    string                 `json:"role"`
	TCPPort                 uint16                 `json:"tcp_port"`
	TLSServerName           string                 `json:"tls_server_name"`
	PublicTLS               bool                   `json:"public_tls,omitempty"`
	CertificateValidityDays int                    `json:"certificate_validity_days,omitempty"`
	MTU                     domain.MTUPolicy       `json:"mtu,omitzero"`
}

func (r masqueCreateRequestV1) makePair(id domain.LinkID) (domain.Link, domain.Link, error) {
	if r.SchemaVersion != 1 || id.Validate() != nil || (r.Role != "dial" && r.Role != "listen") {
		return domain.Link{}, domain.Link{}, fmt.Errorf("unsupported MASQUE creator schema, role or Link ID")
	}
	sender := domain.Link{
		ID: id, DisplayName: r.DisplayName,
		Backend: domain.BackendMASQUE, Encapsulation: domain.EncapTLS,
		Underlay:  domain.Underlay{Local: r.Underlay.Local, Peer: r.Underlay.Peer},
		Addresses: domain.LinkAddresses{Local: r.Addresses.Local, Peer: r.Addresses.Peer},
		MTU:       r.MTU,
		MASQUE:    domain.MASQUEOptions{Role: r.Role, TCPPort: r.TCPPort, TLSServerName: r.TLSServerName, PublicTLS: r.PublicTLS},
	}
	receiver := sender
	receiver.Underlay.Local, receiver.Underlay.Peer = sender.Underlay.Peer, sender.Underlay.Local
	receiver.Addresses.Local, receiver.Addresses.Peer = sender.Addresses.Peer, sender.Addresses.Local
	if r.Role == "dial" {
		receiver.MASQUE.Role = "listen"
	} else {
		receiver.MASQUE.Role = "dial"
	}
	// Protected immutable fingerprints are filled after material issuance.
	sender.MASQUE.MaterialSHA256 = string(bytes.Repeat([]byte{'0'}, 64))
	receiver.MASQUE.MaterialSHA256 = sender.MASQUE.MaterialSHA256
	if masquebackend.ValidateTopology(sender) != nil || masquebackend.ValidateTopology(receiver) != nil {
		return domain.Link{}, domain.Link{}, fmt.Errorf("invalid MASQUE physical/private endpoint or TLS configuration")
	}
	return sender, receiver, nil
}

type masqueOfferV1 struct {
	SchemaVersion int         `json:"schema_version"`
	Sender        domain.Link `json:"sender"`
	Receiver      domain.Link `json:"receiver"`
	// []byte JSON encoding is base64. Output is a SENSITIVE 0600 file; the
	// private receiver key is never written into normal stdout, State, or logs.
	ReceiverMaterial map[string][]byte `json:"receiver_material"`
}

func (o *masqueOfferV1) Clear() {
	if o == nil {
		return
	}
	masquehost.ClearFiles(o.ReceiverMaterial)
	o.ReceiverMaterial = nil
}
func (o masqueOfferV1) Validate(root string) error {
	if o.SchemaVersion != 1 || o.Sender.Backend != domain.BackendMASQUE ||
		o.Receiver.Backend != domain.BackendMASQUE || masquebackend.ValidateTopology(o.Sender) != nil ||
		masquebackend.ValidateTopology(o.Receiver) != nil || o.Sender.ID != o.Receiver.ID ||
		o.Sender.MASQUE.Role == o.Receiver.MASQUE.Role ||
		o.Sender.MASQUE.TCPPort != o.Receiver.MASQUE.TCPPort ||
		o.Sender.MASQUE.TLSServerName != o.Receiver.MASQUE.TLSServerName ||
		o.Sender.MASQUE.PublicTLS != o.Receiver.MASQUE.PublicTLS ||
		o.Sender.Underlay.Local != o.Receiver.Underlay.Peer ||
		o.Sender.Underlay.Peer != o.Receiver.Underlay.Local ||
		o.Sender.Addresses.Local != o.Receiver.Addresses.Peer ||
		o.Sender.Addresses.Peer != o.Receiver.Addresses.Local ||
		o.Sender.MASQUE.MaterialSHA256 == o.Receiver.MASQUE.MaterialSHA256 {
		return fmt.Errorf("MASQUE peer handoff topology or original material identity invalid")
	}
	return masquehost.VerifyMaterialBundle(root, o.Receiver, o.ReceiverMaterial)
}

func decodeMASQUEOffer(in io.Reader, root string) (offer masqueOfferV1, raw []byte, err error) {
	if in == nil {
		return offer, nil, fmt.Errorf("MASQUE private handoff missing")
	}
	raw, err = io.ReadAll(io.LimitReader(in, maxMASQUEOfferBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxMASQUEOfferBytes {
		return offer, nil, fmt.Errorf("MASQUE handoff missing or oversized")
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	if ensureUnambiguousJSON(raw) != nil {
		return offer, nil, fmt.Errorf("invalid or ambiguous MASQUE handoff")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&offer); err != nil {
		return offer, nil, fmt.Errorf("invalid MASQUE handoff payload")
	}
	if err = offer.Validate(root); err != nil {
		return offer, nil, err
	}
	return offer, raw, nil
}

func masqueCommandError(op string, jsonOutput bool, id domain.LinkID, code stlerr.Code, reason string, out, errOut io.Writer) int {
	var r *app.Result
	if id.Validate() == nil {
		r = &app.Result{LinkID: id}
	}
	return lifecycleFailure(out, errOut, jsonOutput, code, "link_"+op, r, op+": "+reason)
}

func masqueCommandResult(op string, result app.Result, jsonOutput bool, out, errOut io.Writer, handoffPath, sha string) int {
	resp := struct {
		SchemaVersion      int           `json:"schema_version"`
		Operation          string        `json:"operation"`
		LinkID             domain.LinkID `json:"link_id"`
		Changed            bool          `json:"changed"`
		Sensitive          bool          `json:"sensitive"`
		HandoffFile        string        `json:"handoff_file,omitempty"`
		ConfirmationSHA256 string        `json:"confirmation_sha256,omitempty"`
	}{SchemaVersion: 1, Operation: op, LinkID: result.LinkID, Changed: result.Changed, Sensitive: true,
		HandoffFile: handoffPath, ConfirmationSHA256: sha}
	if jsonOutput {
		if json.NewEncoder(out).Encode(resp) != nil {
			fmt.Fprintln(errOut, "MASQUE operation completed but response delivery failed; inspect saved Link State")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "MASQUE Link %s locally %s; remote private traffic is not yet proven\n",
		result.LinkID, op)
	if handoffPath != "" {
		fmt.Fprintf(out, "SENSITIVE receiver handoff: %s\n", handoffPath)
		fmt.Fprintf(out, "Import on the other endpoint with: stl link import-masque --stdin --confirm %s\n", sha)
	}
	return 0
}

func masqueRuntime(options *runtimeOptions) (*app.Engine, *runtimeOptions, error) {
	var err error
	if options == nil {
		// An unavailable unrelated optional backend must not block MASQUE.
		options, err = assembleRuntimeOptionsForBackend(state.DefaultRoot, domain.BackendMASQUE)
		if err != nil {
			return nil, nil, err
		}
	}
	engine, err := buildRuntimeEngine(*options)
	return engine, options, err
}
func masqueOperationContext() (context.Context, context.CancelFunc) {
	root, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(root, lifecycleTimeLimit)
	return ctx, func() { cancel(); stop() }
}

// Only mutation commands enter the canonical Engine; preview is read-only.
// Import receives a SHA256 of the exact sensitive file from an independent
// trusted operator channel, not an unauthenticated remote "success" signal.
func linkMASQUECommand(args []string, in io.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	if len(args) == 0 {
		return masqueCommandError("masque", jsonOutput, "", stlerr.CodeInvalid, "missing operation", out, errOut)
	}
	switch args[0] {
	case "create-masque":
		if !(len(args) == 4 || len(args) == 5 && args[4] == "--json") ||
			args[1] != "--stdin" || args[2] != "--output" {
			return masqueCommandError(args[0], jsonOutput, "", stlerr.CodeInvalid,
				"usage: stl link create-masque --stdin --output <private-file> [--json]", out, errOut)
		}
		return createMASQUE(in, args[3], jsonOutput, out, errOut, options)
	case "preview-masque":
		if !((len(args) == 2 && args[1] == "--stdin") ||
			(len(args) == 3 && args[1] == "--stdin" && args[2] == "--json")) {
			return masqueCommandError(args[0], jsonOutput, "", stlerr.CodeInvalid,
				"usage: stl link preview-masque --stdin [--json]", out, errOut)
		}
		root := masqueDefaultRoot(options)
		offer, raw, err := decodeMASQUEOffer(in, root)
		if err != nil {
			return masqueCommandError(args[0], jsonOutput, "", stlerr.CodeInvalid, "invalid private handoff", out, errOut)
		}
		defer offer.Clear()
		return previewMASQUE(offer, setupLinkConfirmation(string(raw)), jsonOutput, out)
	case "import-masque", "resume-masque":
		if !((len(args) == 4) || (len(args) == 5 && args[4] == "--json")) ||
			args[1] != "--stdin" || args[2] != "--confirm" || len(args[3]) != 64 {
			return masqueCommandError(args[0], jsonOutput, "", stlerr.CodeInvalid,
				"usage: stl link "+args[0]+" --stdin --confirm <sha256> [--json]", out, errOut)
		}
		return importOrResumeMASQUE(args[0], in, args[3], jsonOutput, out, errOut, options)
	default:
		return masqueCommandError(args[0], jsonOutput, "", stlerr.CodeInvalid, "unknown MASQUE operation", out, errOut)
	}
}

func masqueDefaultRoot(options *runtimeOptions) string {
	if options != nil && options.stateRoot != "" {
		return options.stateRoot
	}
	return state.DefaultRoot
}

func createMASQUE(in io.Reader, output string, jsonOutput bool, out, errOut io.Writer, options *runtimeOptions) int {
	const op = "create-masque"
	raw, err := io.ReadAll(io.LimitReader(in, maxDesiredLinkBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDesiredLinkBytes || ensureUnambiguousJSON(raw) != nil {
		return masqueCommandError(op, jsonOutput, "", stlerr.CodeInvalid, "invalid MASQUE creator request", out, errOut)
	}
	var request masqueCreateRequestV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.SchemaVersion != 1 {
		return masqueCommandError(op, jsonOutput, "", stlerr.CodeInvalid, "invalid creator fields or private output destination", out, errOut)
	}
	id := request.LinkID
	if id == "" {
		choose := domain.NewLinkID
		if options != nil && options.createLinkID != nil {
			choose = options.createLinkID
		}
		id, err = choose()
		if err != nil {
			return masqueCommandError(op, jsonOutput, "", stlerr.CodeState, "cannot allocate Link identity", out, errOut)
		}
	}
	if err := checkCreatorHandoffDestination(options, id, output); err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeInvalid, "private output destination is unsafe or reserved for guided Create", out, errOut)
	}
	sender, receiver, err := request.makePair(id)
	if err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeInvalid, "invalid sender/receiver topology", out, errOut)
	}
	// Reject an unassigned local physical source before issuing either
	// endpoint private key or publishing a sensitive receiver handoff.
	if err := masquehost.VerifyLocalUnderlay(sender.Underlay.Local); err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodePlan,
			"this host does not uniquely own the requested MASQUE physical source", out, errOut)
	}
	validity := request.CertificateValidityDays
	if validity == 0 {
		validity = 365
	}
	issued, err := masque.GeneratePair(id, request.TLSServerName, validity)
	if err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeInvalid, "MASQUE protected TLS identity and request credential issuance failed", out, errOut)
	}
	defer issued.Clear()
	root := masqueDefaultRoot(options)
	sender, ownFiles, err := masquehost.BuildMaterial(root, sender, issued)
	if err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeState, "cannot build sender identity", out, errOut)
	}
	defer masquehost.ClearFiles(ownFiles)
	receiver, receiverFiles, err := masquehost.BuildMaterial(root, receiver, issued)
	if err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeState, "cannot build receiver identity", out, errOut)
	}
	offer := masqueOfferV1{SchemaVersion: 1, Sender: sender, Receiver: receiver, ReceiverMaterial: receiverFiles}
	defer offer.Clear()
	if err = offer.Validate(root); err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeInvalid, "generated MASQUE handoff failed identity validation", out, errOut)
	}
	encoded, err := json.Marshal(offer)
	if err != nil || len(encoded) > maxMASQUEOfferBytes {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeState, "sensitive handoff encoding unavailable", out, errOut)
	}
	defer clear(encoded)
	engine, runtime, err := masqueRuntime(options)
	if err != nil {
		return masqueCommandError(op, jsonOutput, id, stlerr.CodeState, "MASQUE Engine initialization unavailable", out, errOut)
	}
	ctx, cancel := masqueOperationContext()
	defer cancel()
	result, err := engine.EnsureWithMASQUEProvision(ctx, sender, func() error {
		if err := masquehost.StageFiles(runtime.stateRoot, sender, ownFiles); err != nil {
			return err
		}
		return writeSensitiveHandoff(output, append(encoded, '\n'))
	}, nil)
	if err != nil {
		return lifecycleFailureWithEvidence(out, errOut, jsonOutput, stlerr.CodeOf(err),
			"link_"+op, &result, "MASQUE creation did not complete; preserve sensitive handoff and exact protected material for reconciliation",
			stlerr.EvidenceOf(err), err)
	}
	return masqueCommandResult(op, result, jsonOutput, out, errOut, output, setupLinkConfirmation(string(encoded)))
}

func previewMASQUE(offer masqueOfferV1, digest string, jsonOutput bool, out io.Writer) int {
	resp := struct {
		SchemaVersion      int            `json:"schema_version"`
		LinkID             domain.LinkID  `json:"link_id"`
		Backend            domain.Backend `json:"backend"`
		LocalUnderlay      string         `json:"local_underlay"`
		PeerUnderlay       string         `json:"peer_underlay"`
		LocalPrivate       string         `json:"local_private"`
		PeerPrivate        string         `json:"peer_private"`
		Role               string         `json:"role"`
		TCPPort            uint16         `json:"tcp_port"`
		TLSServerName      string         `json:"tls_server_name"`
		PublicTLS          bool           `json:"public_tls"`
		ConfirmationSHA256 string         `json:"confirmation_sha256"`
		Sensitive          bool           `json:"sensitive"`
	}{1, offer.Receiver.ID, offer.Receiver.Backend, offer.Receiver.Underlay.Local.String(),
		offer.Receiver.Underlay.Peer.String(), offer.Receiver.Addresses.Local.String(),
		offer.Receiver.Addresses.Peer.String(), offer.Receiver.MASQUE.Role, offer.Receiver.MASQUE.TCPPort,
		offer.Receiver.MASQUE.TLSServerName, offer.Receiver.MASQUE.PublicTLS, digest, true}
	if jsonOutput {
		if json.NewEncoder(out).Encode(resp) != nil {
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "SENSITIVE MASQUE receiver %s: %s %s -> %s, private %s -> %s, TLS name %s, TCP port %d\n",
		resp.LinkID, resp.Role, resp.LocalUnderlay, resp.PeerUnderlay, resp.LocalPrivate, resp.PeerPrivate,
		resp.TLSServerName, resp.TCPPort)
	mode := "private mTLS"
	if resp.PublicTLS {
		mode = "public TLS + per-Link request bearer"
	}
	fmt.Fprintf(out, "TLS authentication: %s\n", mode)
	fmt.Fprintf(out, "After independently checking this handoff, import with --confirm %s\n", digest)
	return 0
}

func importOrResumeMASQUE(op string, in io.Reader, confirmation string, jsonOutput bool, out, errOut io.Writer, options *runtimeOptions) int {
	root := masqueDefaultRoot(options)
	offer, raw, err := decodeMASQUEOffer(in, root)
	if err != nil {
		return masqueCommandError(op, jsonOutput, "", stlerr.CodeInvalid, "unverified private MASQUE handoff", out, errOut)
	}
	defer offer.Clear()
	actual := setupLinkConfirmation(string(raw))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(confirmation)) != 1 {
		return masqueCommandError(op, jsonOutput, offer.Receiver.ID, stlerr.CodeInvalid,
			"private MASQUE handoff confirmation hash mismatch", out, errOut)
	}
	engine, runtime, err := masqueRuntime(options)
	if err != nil {
		return masqueCommandError(op, jsonOutput, offer.Receiver.ID, stlerr.CodeState, "MASQUE Engine unavailable", out, errOut)
	}
	ctx, cancel := masqueOperationContext()
	defer cancel()
	var result app.Result
	if op == "import-masque" {
		// Even a valid private handoff cannot authorize provisioning on an
		// unrelated machine. Recheck under the canonical Engine Link lock.
		admission := func(ctx context.Context, link domain.Link) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return masquehost.VerifyLocalUnderlay(link.Underlay.Local)
		}
		result, err = engine.EnsureWithMASQUEProvision(ctx, offer.Receiver, func() error {
			return masquehost.StageFiles(runtime.stateRoot, offer.Receiver, offer.ReceiverMaterial)
		}, admission)
	} else {
		result, err = engine.Ensure(ctx, offer.Sender)
	}
	if err != nil {
		return lifecycleFailureWithEvidence(out, errOut, jsonOutput, stlerr.CodeOf(err),
			"link_"+op, &result, "MASQUE activation not verified; inspect exact saved Link, original material and service",
			stlerr.EvidenceOf(err), err)
	}
	return masqueCommandResult(op, result, jsonOutput, out, errOut, "", "")
}
