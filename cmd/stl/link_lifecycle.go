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
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const (
	maxDesiredLinkBytes = 16 * 1024
	lifecycleTimeLimit  = 5 * time.Minute
	maxLinkJSONNesting  = 12
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
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, operation, "desired Link JSON is invalid or unsupported")
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
	if options == nil {
		var err error
		options, err = productionRuntimeOptions()
		if err != nil {
			return lifecycleFailure(stdout, stderr, jsonOutput, stlerr.CodeState, operation, nil, "cannot initialize backend/runtime; no success is confirmed")
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
	switch args[0] {
	case "ensure":
		result, err = engine.Ensure(ctx, desired)
	case "remove":
		result, err = engine.Remove(ctx, id)
	}
	if err != nil {
		code := stlerr.CodeOf(err)
		return lifecycleFailure(stdout, stderr, jsonOutput, code, operation, &result,
			"Link operation did not complete successfully; inspect current Link status/state before retry")
	}
	if result.LinkID != id || (args[0] == "remove" && !result.Removed) ||
		(args[0] == "ensure" && result.Removed) {
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
	if args[0] == "ensure" {
		if result.Changed {
			fmt.Fprintf(stdout, "Link %s ensured; changes applied and verified\n", id)
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

// Decode from a small, bounded, data-only JSON object. A setup link is NOT
// accepted here; credential-bearing pairing requires a separately reviewed
// import/secret-storage flow, never a silent conversion to desired Link.
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
	var link domain.Link
	if err := decoder.Decode(&link); err != nil {
		return domain.Link{}, fmt.Errorf("invalid Link JSON")
	}
	if err := link.Validate(); err != nil {
		return domain.Link{}, fmt.Errorf("invalid desired Link")
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
