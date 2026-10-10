package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/app"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const (
	// Input schema and response schema evolve independently. A future
	// change to CLI output must not silently reinterpret existing requests.
	desiredLinkSchemaVersion = 1
	maxDesiredLinkBytes      = 16 * 1024
	lifecycleTimeLimit       = 5 * time.Minute
	maxLinkJSONNesting       = 12
)

type lifecycleResultResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	LinkID        domain.LinkID `json:"link_id"`
	Changed       bool          `json:"changed"`
	Removed       bool          `json:"removed"`
}

type lifecycleFailureResponse struct {
	SchemaVersion          int                     `json:"schema_version"`
	Error                  *stlerr.Error           `json:"error"`
	Outcome                string                  `json:"outcome"`
	ReconciliationRequired bool                    `json:"reconciliation_required"`
	PartialResult          *lifecyclePartialResult `json:"partial_result,omitempty"`
}

type lifecyclePartialResult struct {
	LinkID  domain.LinkID `json:"link_id"`
	Changed bool          `json:"changed"`
	Removed bool          `json:"removed"`
}

// An intentional mutating command calls only the existing atomic, owned
// Engine Ensure/Remove lifecycle. It never shells out using JSON payloads.
func linkLifecycleCommand(args []string, input io.Reader, stdout, stderr io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	if len(args) == 0 {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_mutation", "missing lifecycle operation")
	}
	var operation string
	var desired domain.Link
	var id domain.LinkID
	switch args[0] {
	case "ensure":
		operation = "link_ensure"
		if input == nil || !((len(args) == 2 && args[1] == "--stdin") ||
			(len(args) == 3 && args[1] == "--stdin" && args[2] == "--json")) {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, operation, "usage: stl link ensure --stdin [--json]")
		}
		var err error
		desired, err = decodeDesiredLink(input)
		if err != nil {
			// Syntax and malformed schema are invalid, while an explicitly
			// unsupported schema version or domain capability is unsupported.
			// Never expose the decoder's raw error or desired state here.
			code := stlerr.CodeInvalid
			if stlerr.CodeOf(err) == stlerr.CodeUnsupported {
				code = stlerr.CodeUnsupported
			}
			return readCommandError(stdout, stderr, jsonOutput, code, operation, "desired Link JSON is invalid or unsupported")
		}
		id = desired.ID
	case "remove":
		operation = "link_remove"
		if !((len(args) == 4 && args[2] == "--confirm") ||
			(len(args) == 5 && args[2] == "--confirm" && args[4] == "--json")) {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, operation, "usage: stl link remove <id> --confirm <id> [--json]")
		}
		id = domain.LinkID(args[1])
		if err := id.Validate(); err != nil || args[1] != args[3] {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, operation, "Link ID and explicit confirmation must match")
		}
	default:
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_mutation", "unknown lifecycle operation")
	}
	return executeLinkMutation(operation, desired, id, jsonOutput, stdout, stderr, options)
}

// executeLinkMutation is the sole CLI execution path for import, ensure and
// remove. All three delegate actual mutations, ownership and rollback to the
// same canonical Engine, without another pairing-specific lifecycle.
func executeLinkMutation(operation string, desired domain.Link, id domain.LinkID,
	jsonOutput bool, stdout, stderr io.Writer, options *runtimeOptions) int {
	return executeLinkMutationConditional(operation, desired, id, jsonOutput, stdout, stderr, options, nil)
}

// The menu alone can pass a previewed desired Link to the same mutation
// executor. The direct versioned CLI continues to use unconditional Remove.
func executeLinkMutationConditional(operation string, desired domain.Link, id domain.LinkID,
	jsonOutput bool, stdout, stderr io.Writer, options *runtimeOptions, expected *domain.Link) int {
	return executeLinkMutationControlled(operation, desired, id, jsonOutput, stdout, stderr, options, expected, nil)
}

func executeLinkMutationRecipient(operation string, desired domain.Link, id domain.LinkID,
	jsonOutput bool, stdout, stderr io.Writer, options *runtimeOptions, credential []byte) int {
	return executeLinkMutationControlled(operation, desired, id, jsonOutput, stdout, stderr, options, nil, credential)
}

func executeLinkMutationControlled(operation string, desired domain.Link, id domain.LinkID,
	jsonOutput bool, stdout, stderr io.Writer, options *runtimeOptions, expected *domain.Link, credential []byte) int {
	if len(credential) != 0 && (operation != "link_import" || desired.Backend != domain.BackendWireGuard) {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, operation, "invalid protected import operation")
	}
	if expected != nil && (operation != "link_remove" || expected.ID != id) {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, operation,
			"conditional removal Link identity does not match")
	}
	if options == nil {
		var err error
		options, err = productionRuntimeOptions()
		if err != nil {
			return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeState, operation, nil, "cannot initialize backend/runtime; no success is confirmed")
		}
	}
	if len(credential) != 0 {
		registered := false
		for _, candidate := range options.backends {
			if candidate != nil && candidate.Kind() == domain.BackendWireGuard {
				registered = true
				break
			}
		}
		if !registered {
			return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, operation, nil,
				"protected WireGuard backend is unavailable; no mutation attempted")
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeState, operation, nil, "cannot initialize Link Engine; no success is confirmed")
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, lifecycleTimeLimit)
	defer cancel()
	var result app.Result
	switch operation {
	case "link_ensure":
		result, err = engine.Ensure(ctx, desired)
	case "link_import":
		if len(credential) != 0 {
			keys, keyErr := wgbackend.NewKeyStore(options.stateRoot)
			if keyErr != nil {
				return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeState, operation, nil, "cannot initialize protected WireGuard recipient store")
			}
			result, err = engine.EnsureImportedRecipient(ctx, desired, credential, keys)
		} else {
			result, err = engine.EnsureImported(ctx, desired)
		}
	case "link_remove":
		if expected != nil {
			result, err = engine.RemoveIfUnchanged(ctx, *expected)
		} else {
			result, err = engine.Remove(ctx, id)
		}
	default:
		return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeInternal, operation, nil,
			"unknown internal Link operation")
	}
	if err != nil {
		code := stlerr.CodeOf(err)
		if expected != nil && code == stlerr.CodeConflict {
			return lifecycleFailure(stdout, stderr, jsonOutput, code, operation, &result,
				"Saved Link changed since preview or removal conflicted; review current Link state before retry")
		}
		return lifecycleFailure(stdout, stderr, jsonOutput, code, operation, &result,
			"Link operation did not complete successfully; inspect current Link status/state before retry")
	}
	if result.LinkID != id || (operation == "link_remove" && !result.Removed) ||
		(operation != "link_remove" && result.Removed) {
		return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeInternal, operation, &result,
			"Link Engine returned an inconsistent lifecycle result; reconcile before retry")
	}

	if jsonOutput {
		resp := lifecycleResultResponse{SchemaVersion: jsonSchemaVersion, Operation: operation,
			LinkID: id, Changed: result.Changed, Removed: result.Removed}
		if err := json.NewEncoder(stdout).Encode(resp); err != nil {
			fmt.Fprintln(stderr, "Link operation may have completed but the machine result could not be written")
			return 1
		}
		return 0
	}
	if operation != "link_remove" {
		if result.Changed {
			if operation == "link_import" {
				fmt.Fprintf(stdout, "Link %s imported; changes applied and verified\n", id)
			} else {
				fmt.Fprintf(stdout, "Link %s ensured; changes applied and verified\n", id)
			}
		} else {
			fmt.Fprintf(stdout, "Link %s already matches desired state\n", id)
		}
	} else {
		fmt.Fprintf(stdout, "Link %s removed via canonical Engine\n", id)
	}
	return 0
}

func lifecycleFailure(stdout, stderr io.Writer, jsonOutput bool, code stlerr.Code, operation string, result *app.Result, detail string) int {
	if code == "" {
		code = stlerr.CodeInternal
	}
	// Error details here are authored literals, never the raw OS, backend,
	// private state, caller-provided JSON or credential-bearing exception.
	safe := stlerr.New(code, operation, "", "", detail)
	out := lifecycleFailureResponse{
		SchemaVersion:          jsonSchemaVersion,
		Error:                  safe,
		Outcome:                "unconfirmed",
		ReconciliationRequired: true,
	}
	if result != nil && result.LinkID.Validate() == nil {
		// Engine's partial return is evidence for reconciliation, not a
		// successful or durable state transition. Never marshal app.Result
		// directly: its Go field names are not the machine JSON contract.
		out.PartialResult = &lifecyclePartialResult{
			LinkID: result.LinkID, Changed: result.Changed, Removed: result.Removed,
		}
	}
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			fmt.Fprintln(stderr, "Link outcome uncertain and error response could not be written; inspect before retry")
			return 1
		}
	} else {
		fmt.Fprintln(stderr, safe.Error())
		if result != nil && result.LinkID != "" {
			fmt.Fprintf(stderr, "Partial operation result for Link %s; reconcile current host/state before retry\n", result.LinkID)
		}
	}
	switch code {
	case stlerr.CodeInvalid:
		return 2
	case stlerr.CodeUnsupported:
		return 4
	default:
		return 1
	}
}

// The v1 automation wire contract is intentionally frozen at EVERY nesting
// level. Never put domain.* structs in these JSON-decoded types: adding a
// domain field must not silently expand the public schema_version:1 input.
// Only stable primitives and standard-library IP value types are allowed.
// Introducing a new public input field needs an explicit schema decision.
type desiredLinkRequestV1 struct {
	SchemaVersion int           `json:"schema_version"`
	Link          desiredLinkV1 `json:"link"`
}

type desiredLinkV1 struct {
	ID            domain.LinkID          `json:"id"`
	DisplayName   string                 `json:"display_name,omitempty"`
	Underlay      desiredUnderlayV1      `json:"underlay"`
	Addresses     desiredLinkAddressesV1 `json:"addresses"`
	Backend       domain.Backend         `json:"backend"`
	Encapsulation domain.Encapsulation   `json:"encapsulation"`
	GRE           desiredGREOptionsV1    `json:"gre,omitempty"`
}

type desiredUnderlayV1 struct {
	Local netip.Addr `json:"local"`
	Peer  netip.Addr `json:"peer"`
}

type desiredLinkAddressesV1 struct {
	Local netip.Prefix `json:"local"`
	Peer  netip.Prefix `json:"peer"`
}

// Keep the exact GRE v1 option set here. KeyEnabled must remain separate
// from Key so a present key value of zero is not confused with no GRE key.
type desiredGREOptionsV1 struct {
	KeyEnabled   bool   `json:"key_enabled,omitempty"`
	Key          uint32 `json:"key,omitempty"`
	TTL          uint8  `json:"ttl,omitempty"`
	TOS          uint8  `json:"tos,omitempty"`
	DisablePMTUD bool   `json:"disable_pmtud,omitempty"`
	Checksum     bool   `json:"checksum,omitempty"`
	Sequence     bool   `json:"sequence,omitempty"`
	UDPPort      uint16 `json:"udp_port,omitempty"`
}

// Explicit v1-to-domain mapping is the compatibility boundary. Do not
// reflect/round-trip JSON here: new internal fields must take their default
// until a consciously versioned public input supports them.
func (d desiredLinkV1) link() domain.Link {
	return domain.Link{
		ID: d.ID, DisplayName: d.DisplayName,
		Underlay: domain.Underlay{
			Local: d.Underlay.Local, Peer: d.Underlay.Peer,
		},
		Addresses: domain.LinkAddresses{
			Local: d.Addresses.Local, Peer: d.Addresses.Peer,
		},
		Backend: d.Backend, Encapsulation: d.Encapsulation,
		GRE: domain.GREOptions{
			KeyEnabled: d.GRE.KeyEnabled, Key: d.GRE.Key,
			TTL: d.GRE.TTL, TOS: d.GRE.TOS,
			DisablePMTUD: d.GRE.DisablePMTUD,
			Checksum:     d.GRE.Checksum, Sequence: d.GRE.Sequence,
			UDPPort: d.GRE.UDPPort,
		},
	}
}

// Decode from a small, bounded, versioned data-only JSON object. A setup link
// is NOT accepted here; credential-bearing pairing needs separately reviewed
// import/secret storage, never a silent conversion to desired Link.
func decodeDesiredLink(reader io.Reader) (domain.Link, error) {
	if reader == nil {
		return domain.Link{}, fmt.Errorf("Link input is required")
	}
	input, err := io.ReadAll(io.LimitReader(reader, maxDesiredLinkBytes+1))
	if err != nil || len(input) == 0 || len(input) > maxDesiredLinkBytes || !utf8.Valid(input) {
		return domain.Link{}, fmt.Errorf("invalid or oversized Link input")
	}
	if err := ensureUnambiguousJSON(input); err != nil {
		return domain.Link{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var request desiredLinkRequestV1
	if err := decoder.Decode(&request); err != nil {
		return domain.Link{}, fmt.Errorf("invalid desired Link request")
	}
	switch {
	case request.SchemaVersion <= 0:
		return domain.Link{}, fmt.Errorf("missing or invalid desired Link schema_version")
	case request.SchemaVersion != desiredLinkSchemaVersion:
		return domain.Link{}, stlerr.New(stlerr.CodeUnsupported, "decode_link", "", "",
			"unsupported desired Link schema version")
	}
	link := request.Link.link()
	if err := link.Validate(); err != nil {
		// Keep the existing typed CodeUnsupported (IPv6 Link Addresses,
		// unsupported GRE encapsulations); the caller projects only its code.
		return domain.Link{}, err
	}
	return link, nil
}

// No duplicate JSON object keys, null values or unbounded nested objects.
// Multiple top-level JSON values, arrays and case-variant duplicate fields
// are rejected; all Link field types are subsequently checked by decoding.
func ensureUnambiguousJSON(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxLinkJSONNesting {
		return fmt.Errorf("JSON nesting too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON token")
	}
	if token == nil {
		return fmt.Errorf("JSON null fields are unsupported")
	}
	switch d := token.(type) {
	case json.Delim:
		if d != '{' {
			return fmt.Errorf("JSON objects required")
		}
		seen := make(map[string]struct{})
		for decoder.More() {
			field, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON field")
			}
			key, ok := field.(string)
			if !ok {
				return fmt.Errorf("invalid JSON field name")
			}
			// Go's struct decoder matches field names case-insensitively.
			// Fold duplicate field names to avoid two different meanings.
			folded := strings.ToLower(key)
			if _, exists := seen[folded]; exists {
				return fmt.Errorf("duplicate JSON field")
			}
			seen[folded] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object end")
		}
	default:
		// Primitive Link JSON fields are validated by typed decode and
		// domain validation after duplicate/shape checks.
	}
	return nil
}
