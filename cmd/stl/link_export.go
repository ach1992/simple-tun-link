package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// SetupLinkExport is an intentionally explicit export/copy payload, not a
// status/diagnostic result. It may reveal endpoint addresses, Link IDs and
// display names encoded in the URL even though current GRE is unencrypted.
type SetupLinkExport struct {
	SchemaVersion        int                  `json:"schema_version"`
	PairingSchemaVersion int                  `json:"pairing_schema_version"`
	LinkID               domain.LinkID        `json:"link_id"`
	Backend              domain.Backend       `json:"backend"`
	Encapsulation        domain.Encapsulation `json:"encapsulation"`
	Mode                 pairing.ExchangeMode `json:"mode"`
	HasCredential        bool                 `json:"has_credential"`
	Sensitive            bool                 `json:"sensitive"`
	SetupLink            string               `json:"setup_link"`
}

// Export an already persisted GRE Link by stable Link ID. No backend runtime
// is assembled, and no secret-bearing backend is supported until its key
// storage/receiver import contract is implemented and separately reviewed.
func linkExportCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	valid := (len(args) == 2 || (len(args) == 3 && args[2] == "--json")) && args[0] == "export"
	if !valid {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_export",
			"usage: stl link export <link-id> [--json]")
	}
	id := domain.LinkID(args[1])
	if err := id.Validate(); err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_export", "invalid Link ID")
	}
	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	if root == "" {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_export", "local state root is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_export",
			"cannot read desired state for export")
	}
	record, exists := snapshot.Find(id)
	if !exists {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_export",
			"Link ID is not present in local desired state")
	}
	// Never silently drop required recipient secrets. IPIP is also deferred
	// until its backend/FOU/GUE options have a complete persisted contract.
	if record.Desired.Backend != domain.BackendGRE {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_export",
			"export is not yet supported for this backend")
	}
	offer, err := pairing.NewQuickOffer(record.Desired, nil)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_export",
			"persisted Link is not compatible with the current pairing format")
	}
	if offer.IsSensitive() || offer.CredentialKind() != pairing.CredentialNone {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_export",
			"credential-bearing pairing export requires a separately protected workflow")
	}
	if jsonOutput {
		url, err := offer.EncodeSetupLink()
		if err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_export",
				"cannot encode validated GRE pairing data")
		}
		payload := SetupLinkExport{
			SchemaVersion:        jsonSchemaVersion,
			PairingSchemaVersion: pairing.SchemaVersion,
			LinkID:               id, Backend: record.Desired.Backend,
			Encapsulation: record.Desired.Encapsulation,
			Mode:          offer.Mode(), HasCredential: false, Sensitive: false,
			SetupLink: url,
		}
		if err := json.NewEncoder(stdout).Encode(payload); err != nil {
			fmt.Fprintln(stderr, "cannot encode requested pairing export")
			return 1
		}
		return 0
	}
	block, err := offer.HumanReadableBlock()
	if err != nil {
		return readCommandError(stdout, stderr, false, stlerr.CodeInvalid, "link_export",
			"cannot format validated GRE pairing data")
	}
	fmt.Fprintln(stdout, "Explicit export only: this link reveals endpoint metadata and is not encrypted.")
	_, err = io.WriteString(stdout, block)
	if err != nil {
		fmt.Fprintln(stderr, "cannot write requested pairing export")
		return 1
	}
	return 0
}
