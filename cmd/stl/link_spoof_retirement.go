package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// This is the supported, repeatable post-commit recovery path; Remove cannot
// operate on a Link that the Engine has already durably removed.
func linkSpoofRetirementCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	asJSON := slices.Contains(args, "--json")
	if !((len(args) == 3) || (len(args) == 4 && args[3] == "--json")) ||
		args[1] != "--confirm" || args[0] != args[2] {
		return spoofCLIError(fmt.Errorf("usage: stl link retire-spoof <id> --confirm <id> [--json]"), errOut)
	}
	id := domain.LinkID(args[0])
	if err := id.Validate(); err != nil {
		return spoofCLIError(err, errOut)
	}
	if options == nil {
		var err error
		options, err = assembleRuntimeOptionsForBackend(state.DefaultRoot, domain.BackendSpoof)
		if err != nil {
			return spoofCLIError(err, errOut)
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return spoofCLIError(err, errOut)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := engine.RetireSpoofCredential(ctx, id); err != nil {
		return spoofCLIError(err, errOut)
	}
	if asJSON {
		if err := json.NewEncoder(out).Encode(struct {
			SchemaVersion int           `json:"schema_version"`
			LinkID        domain.LinkID `json:"link_id"`
			Retired       bool          `json:"retired"`
		}{1, id, true}); err != nil {
			return spoofCLIError(err, errOut)
		}
	} else {
		fmt.Fprintf(out, "Spoof %s: exact committed removal receipt and protected material retirement verified.\n", id)
	}
	return 0
}
