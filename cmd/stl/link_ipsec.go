package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/app"
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// This intentionally versioned creator schema never accepts secret bytes.
// User-supplied PSKs in JSON must not become a persistent API.
type ipsecSenderRequestV1 struct {
	SchemaVersion int                    `json:"schema_version"`
	LinkID        domain.LinkID          `json:"link_id,omitempty"`
	DisplayName   string                 `json:"display_name,omitempty"`
	Underlay      desiredUnderlayV1      `json:"underlay"`
	Addresses     desiredLinkAddressesV1 `json:"addresses"`
	Encapsulation domain.Encapsulation   `json:"encapsulation"`
}

// v2 adds a local MTU choice without reinterpreting the pinned v1 request.
type ipsecSenderRequestV2 struct {
	ipsecSenderRequestV1
	MTU domain.MTUPolicy `json:"mtu,omitzero"`
}

func (r ipsecSenderRequestV2) Link(id domain.LinkID) domain.Link {
	link := r.ipsecSenderRequestV1.Link(id)
	link.MTU = r.MTU
	return link
}

type ipsecSenderResult struct {
	SchemaVersion        int                  `json:"schema_version"`
	Operation            string               `json:"operation"`
	LinkID               domain.LinkID        `json:"link_id"`
	PairingSchemaVersion int                  `json:"pairing_schema_version"`
	Mode                 pairing.ExchangeMode `json:"mode"`
	Sensitive            bool                 `json:"sensitive"`
	HandoffFile          string               `json:"handoff_file"`
	Changed              bool                 `json:"changed"`
}

type ipsecConnectResult struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	LinkID        domain.LinkID `json:"link_id"`
	Initiation    string        `json:"initiation"`
}

type ipsecXFRMReconcileResult struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	LinkID        domain.LinkID `json:"link_id"`
	Reconciled    bool          `json:"reconciled"`
}

type ipsecRetireResult struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	LinkID        domain.LinkID `json:"link_id"`
	Retired       bool          `json:"retired"`
}

func hasOperationalIPsec(opts runtimeOptions) bool {
	for _, candidate := range opts.backends {
		if _, ok := candidate.(*ipsecbackend.OperationalBackend); ok {
			return true
		}
	}
	return false
}

func activeIPsecBackend(ctx context.Context, options *runtimeOptions) (*ipsecbackend.OperationalBackend, error) {
	if options == nil {
		return nil, fmt.Errorf("IPsec runtime options unavailable")
	}
	for _, candidate := range options.backends {
		if active, ok := candidate.(*ipsecbackend.OperationalBackend); ok && active != nil {
			if err := active.CheckAdmission(ctx); err != nil {
				return nil, fmt.Errorf("native-exclusive IPsec service origin is not admitted")
			}
			return active, nil
		}
	}
	return nil, fmt.Errorf("native-exclusive IPsec backend is not registered")
}

func decodeIPsecSenderRequest(input io.Reader) (ipsecSenderRequestV2, error) {
	if input == nil {
		return ipsecSenderRequestV2{}, fmt.Errorf("missing IPsec creator request")
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxDesiredLinkBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDesiredLinkBytes || !utf8.Valid(raw) {
		return ipsecSenderRequestV2{}, fmt.Errorf("invalid bounded IPsec creator input")
	}
	if err := ensureUnambiguousJSON(raw); err != nil {
		return ipsecSenderRequestV2{}, err
	}
	var envelope struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.SchemaVersion <= 0 {
		return ipsecSenderRequestV2{}, fmt.Errorf("missing or invalid IPsec creator schema_version")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var request ipsecSenderRequestV2
	switch envelope.SchemaVersion {
	case 1:
		if err := dec.Decode(&request.ipsecSenderRequestV1); err != nil {
			return ipsecSenderRequestV2{}, fmt.Errorf("invalid IPsec creator v1 fields")
		}
	case 2:
		if err := dec.Decode(&request); err != nil {
			return ipsecSenderRequestV2{}, fmt.Errorf("invalid IPsec creator v2 fields")
		}
	default:
		return ipsecSenderRequestV2{}, stlerr.New(stlerr.CodeUnsupported, "link_create_ipsec", "", "ipsec",
			"unsupported IPsec creator schema version")
	}
	if request.LinkID != "" && request.LinkID.Validate() != nil {
		return ipsecSenderRequestV2{}, fmt.Errorf("invalid IPsec Link ID")
	}
	if !request.Underlay.Local.IsValid() || !request.Underlay.Peer.IsValid() ||
		!request.Addresses.Local.IsValid() || !request.Addresses.Peer.IsValid() ||
		(request.Encapsulation != domain.EncapESP && request.Encapsulation != domain.EncapNATT) {
		return ipsecSenderRequestV2{}, fmt.Errorf("missing or invalid IPsec Link fields")
	}
	if err := request.MTU.Validate(); err != nil {
		return ipsecSenderRequestV2{}, err
	}
	return request, nil
}

func (r ipsecSenderRequestV1) Link(id domain.LinkID) domain.Link {
	return domain.Link{ID: id, DisplayName: r.DisplayName,
		Underlay:  domain.Underlay{Local: r.Underlay.Local, Peer: r.Underlay.Peer},
		Addresses: domain.LinkAddresses{Local: r.Addresses.Local, Peer: r.Addresses.Peer},
		Backend:   domain.BackendIPsec, Encapsulation: r.Encapsulation}
}

func ipsecFailure(out, errOut io.Writer, jsonOutput bool, code stlerr.Code, op string, id domain.LinkID, detail string, observed error) int {
	var result *app.Result
	if id.Validate() == nil {
		result = &app.Result{LinkID: id}
	}
	return lifecycleFailureWithEvidence(out, errOut, jsonOutput, code, op, result, detail, stlerr.EvidenceOf(observed), observed)
}

// create-ipsec is an explicitly authorized SENSITIVE sender operation;
// never silently generate a replacement PSK on a failed retry.
func linkCreateIPsecCommand(args []string, input io.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	const op = "link_create_ipsec"
	isJSON := slices.Contains(args, "--json")
	if !((len(args) == 4 || (len(args) == 5 && args[4] == "--json")) &&
		args[0] == "create-ipsec" && args[1] == "--stdin" && args[2] == "--output") {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, op,
			"usage: stl link create-ipsec --stdin --output <absolute-private-file> [--json]")
	}
	request, err := decodeIPsecSenderRequest(input)
	if err != nil {
		code := stlerr.CodeInvalid
		if stlerr.CodeOf(err) == stlerr.CodeUnsupported {
			code = stlerr.CodeUnsupported
		}
		return ipsecFailure(out, errOut, isJSON, code, op, "",
			"invalid or unsupported IPsec sender request", nil)
	}
	id := request.LinkID
	if id == "" {
		identity := domain.NewLinkID
		if opts != nil && opts.createLinkID != nil {
			identity = opts.createLinkID
		}
		id, err = identity()
		if err != nil || id.Validate() != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, "",
				"cannot generate protected IPsec Link identity", nil)
		}
	}
	link := request.Link(id)
	if _, err := ipsecbackend.NewProfile(link); err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeInvalid, op, id,
			"invalid IPsec/IKEv2 endpoint, Link Address or encapsulation", nil)
	}
	if err := checkSensitiveHandoffDestination(args[3]); err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeInvalid, op, id,
			"SENSITIVE handoff destination is unsafe or already occupied", nil)
	}
	if opts == nil {
		opts, err = productionRuntimeOptions()
		if err != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
				"cannot inspect native-exclusive IPsec runtime", nil)
		}
	}
	// Fail before generating a key or writing protected state if service
	// origin and lifetime-private writer admission is not available.
	pre, preCancel := context.WithTimeout(context.Background(), readOperationTimeout)
	_, admissionErr := activeIPsecBackend(pre, opts)
	preCancel()
	if admissionErr != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeUnsupported, op, id,
			"native-exclusive IPsec service is not admitted; no PSK generated", nil)
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"cannot initialize canonical protected IPsec Engine", nil)
	}
	keys, err := ipsecbackend.NewPSKStore(opts.stateRoot)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"protected IPsec key store is unavailable", nil)
	}
	secret, err := ipsecbackend.GeneratePSK()
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"IPsec key generation failed before staging", nil)
	}
	defer clear(secret)
	offer, err := pairing.NewQuickOffer(link, secret)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeInvalid, op, id,
			"cannot construct validated SENSITIVE IPsec Quick Link", nil)
	}
	defer offer.ClearRecipientCredential()
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, lifecycleTimeLimit)
	defer cancel()
	writer := writeSensitiveHandoff
	if opts.writeHandoff != nil {
		writer = opts.writeHandoff
	}
	err = engine.StageIPsecSender(ctx, offer, keys, func(url string) error {
		return writer(args[3], []byte(url+"\n"))
	})
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"IPsec PSK/handoff staging failed or is uncertain; preserve exact key and output for reconciliation", err)
	}
	result, err := engine.ActivateStagedIPsec(ctx, id)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(err), op, id,
			"SENSITIVE handoff staged but IPsec activation is not confirmed; do not silently rekey", err)
	}
	if result.LinkID != id || result.Removed {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeInternal, op, id,
			"IPsec activation returned inconsistent result", nil)
	}
	if isJSON {
		if err = json.NewEncoder(out).Encode(ipsecSenderResult{
			SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id,
			PairingSchemaVersion: pairing.SchemaVersion, Mode: pairing.ModeQuick,
			Sensitive: true, HandoffFile: args[3], Changed: result.Changed}); err != nil {
			fmt.Fprintln(errOut, "IPsec may have been activated but its result could not be encoded; inspect committed state")
			return 1
		}
	} else {
		fmt.Fprintf(out, "IPsec Link %s locally configured and verified; SENSITIVE v2 handoff saved privately.\n", id)
		fmt.Fprintln(out, "Peer must preview/import the handoff and explicitly initiate IKEv2. Local activation is not proof of encrypted traffic.")
	}
	return 0
}

// Only a valid, nonzero exact 32-byte v2 PSK can enter the protected store.
// Older bounded v2 PSKs remain previewable, but must not receive an APPLY
// confirmation or proceed to native-runtime admission. No secret is logged.
func importableIPsecOffer(offer pairing.Offer) bool {
	p := offer.Preview()
	if p.SchemaVersion != pairing.SchemaVersion || p.Mode != pairing.ModeQuick ||
		!p.Sensitive || !p.HasCredential || p.Credential != pairing.CredentialIPsecPSK ||
		p.Link.Backend != domain.BackendIPsec ||
		(p.Link.Encapsulation != domain.EncapESP && p.Link.Encapsulation != domain.EncapNATT) {
		return false
	}
	secret := offer.RecipientCredential()
	defer clear(secret)
	key, err := ipsecbackend.ParsePSK(secret)
	if err != nil {
		return false
	}
	key.Zeroize()
	return true
}

func executeIPsecRecipientImport(encoded, confirmation string, id domain.LinkID,
	isJSON bool, out, errOut io.Writer, opts *runtimeOptions) int {
	const op = "link_import"
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
				"IPsec recipient runtime unavailable before PSK staging", nil)
		}
	}
	pre, stop := context.WithTimeout(context.Background(), readOperationTimeout)
	_, admissionErr := activeIPsecBackend(pre, opts)
	stop()
	if admissionErr != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeUnsupported, op, id,
			"native-exclusive IPsec runtime not admitted; no recipient key staged", nil)
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"cannot initialize canonical IPsec Engine", nil)
	}
	keys, err := ipsecbackend.NewPSKStore(opts.stateRoot)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"protected IPsec recipient key store is unavailable", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleTimeLimit)
	defer cancel()
	if err = engine.StageIPsecRecipient(ctx, encoded, confirmation, keys); err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(err), op, id,
			"protected IPsec import staging failed or its outcome is uncertain", err)
	}
	result, err := engine.ActivateStagedIPsec(ctx, id)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(err), op, id,
			"recipient PSK staged but IPsec activation failed or is uncertain; reconcile exact intent", err)
	}
	if result.LinkID != id || result.Removed {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeInternal, op, id,
			"unexpected IPsec recipient activation result", nil)
	}
	if isJSON {
		if err = json.NewEncoder(out).Encode(lifecycleResultResponse{
			SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id, Changed: result.Changed}); err != nil {
			fmt.Fprintln(errOut, "IPsec import may be committed but result could not be encoded")
			return 1
		}
	} else {
		fmt.Fprintf(out, "IPsec Link %s imported with protected PSK; initiate IKEv2 and inspect encrypted traffic separately.\n", id)
	}
	return 0
}

// activate-ipsec is a retry of an exact already staged public intent, not
// a rekey/replacement and not an override of an indeterminate VICI journal.
func linkIPsecLifecycleCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := slices.Contains(args, "--json")
	if len(args) < 4 || len(args) > 5 || (len(args) == 5 && args[4] != "--json") ||
		(args[0] != "activate-ipsec" && args[0] != "connect-ipsec" && args[0] != "retire-ipsec" && args[0] != "reconcile-ipsec" && args[0] != "reconcile-xfrm-ipsec") ||
		args[2] != "--confirm" || args[1] != args[3] {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "link_ipsec",
			"usage: stl link activate-ipsec|connect-ipsec|retire-ipsec|reconcile-ipsec|reconcile-xfrm-ipsec <link-id> --confirm <link-id> [--json]")
	}
	id := domain.LinkID(args[1])
	if id.Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "link_ipsec", "invalid exact IPsec Link ID")
	}
	op := "link_" + args[0]
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
				"cannot initialize IPsec runtime before operation", nil)
		}
	}
	// Post-Remove credential retirement is local, not a daemon operation.
	// A stopped service must not trap an already committed removal receipt.
	if args[0] != "retire-ipsec" {
		pre, stop := context.WithTimeout(context.Background(), readOperationTimeout)
		_, admissionErr := activeIPsecBackend(pre, opts)
		stop()
		if admissionErr != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeUnsupported, op, id,
				"native-exclusive IPsec backend is unavailable; no mutation attempted", nil)
		}
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
			"cannot initialize protected IPsec Engine", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleTimeLimit)
	defer cancel()
	if args[0] == "retire-ipsec" {
		keys, keyErr := ipsecbackend.NewPSKStore(opts.stateRoot)
		if keyErr != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeState, op, id,
				"protected IPsec retirement store unavailable", nil)
		}
		engine.SetIPsecRetirementStore(keys)
		if err := engine.RetireIPsecCredential(ctx, id); err != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(err), op, id,
				"no exact committed IPsec removal receipt, or protected credential retirement is unconfirmed", err)
		}
		if isJSON {
			if err := json.NewEncoder(out).Encode(ipsecRetireResult{
				SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id, Retired: true}); err != nil {
				fmt.Fprintln(errOut, "IPsec key retirement completed but result could not be encoded")
				return 1
			}
		} else {
			fmt.Fprintf(out, "Protected IPsec key for removed Link %s retired; no active Link was changed.\n", id)
		}
		return 0
	}
	if args[0] == "reconcile-xfrm-ipsec" {
		if reconcileErr := engine.ReconcileIPsecXFRM(ctx, id); reconcileErr != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(reconcileErr), op, id,
				"XFRM creation cannot be safely reconciled without original durable ifindex", reconcileErr)
		}
		if isJSON {
			if err := json.NewEncoder(out).Encode(ipsecXFRMReconcileResult{
				SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id, Reconciled: true}); err != nil {
				fmt.Fprintln(errOut, "XFRM reconciliation completed but result could not be encoded")
				return 1
			}
		} else {
			fmt.Fprintf(out, "Exact IPsec XFRM creation for Link %s safely reconciled; retry original intent if needed.\n", id)
		}
		return 0
	}
	if args[0] == "reconcile-ipsec" {
		result, recoverErr := engine.ReconcileIPsecRemove(ctx, id)
		if recoverErr != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(recoverErr), op, id,
				"exact IPsec Remove reconciliation not confirmed; inspect its durable journal", recoverErr)
		}
		if isJSON {
			if err := json.NewEncoder(out).Encode(lifecycleResultResponse{
				SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id, Changed: result.Changed, Removed: result.Removed}); err != nil {
				fmt.Fprintln(errOut, "IPsec Remove reconciliation succeeded but result could not be encoded")
				return 1
			}
		} else {
			fmt.Fprintf(out, "IPsec Remove reconciled for Link %s with committed exact ownership.\n", id)
		}
		return 0
	}
	if args[0] == "connect-ipsec" {
		if err := engine.ConnectIPsec(ctx, id); err != nil {
			return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(err), op, id,
				"IPsec IKEv2 initiation rejected or result unknown; inspect Link status", err)
		}
		if isJSON {
			if err := json.NewEncoder(out).Encode(ipsecConnectResult{
				SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id, Initiation: "accepted"}); err != nil {
				fmt.Fprintln(errOut, "IKE initiation outcome not reliably delivered")
				return 1
			}
		} else {
			fmt.Fprintf(out, "IPsec IKEv2 initiation accepted for Link %s; verify ESP traffic separately.\n", id)
		}
		return 0
	}
	result, err := engine.ActivateStagedIPsec(ctx, id)
	if err != nil {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeOf(err), op, id,
			"staged IPsec activation failed or is unknown; reconcile journal before retry", err)
	}
	if result.LinkID != id || result.Removed {
		return ipsecFailure(out, errOut, isJSON, stlerr.CodeInternal, op, id,
			"unexpected IPsec staged activation result", nil)
	}
	if isJSON {
		if err := json.NewEncoder(out).Encode(lifecycleResultResponse{
			SchemaVersion: jsonSchemaVersion, Operation: op, LinkID: id, Changed: result.Changed}); err != nil {
			fmt.Fprintln(errOut, "IPsec activation result could not be delivered")
			return 1
		}
	} else {
		fmt.Fprintf(out, "IPsec staged Link %s activated locally; check remote IKE/ESP traffic.\n", id)
	}
	return 0
}
