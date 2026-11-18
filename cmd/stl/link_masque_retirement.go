package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Unlike Remove, retirement targets an already-removed Link. There is no
// committed backend to select with productionRemovalRuntimeOptions, so
// assemble only MASQUE and the existing Engine's locked State authority.
func linkMASQUERetirementCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	if !((len(args) == 3) || (len(args) == 4 && args[3] == "--json")) ||
		args[1] != "--confirm" || args[0] != args[2] {
		return masqueCommandError("retire-masque", jsonOutput, "", stlerr.CodeInvalid,
			"usage: stl link retire-masque <id> --confirm <id> [--json]", out, errOut)
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return masqueCommandError("retire-masque", jsonOutput, id, stlerr.CodeInvalid,
			"invalid exact MASQUE retirement Link identity", out, errOut)
	}
	if options == nil {
		var err error
		options, err = assembleRuntimeOptionsForBackend(state.DefaultRoot, domain.BackendMASQUE)
		if err != nil {
			return masqueCommandError("retire-masque", jsonOutput, id, stlerr.CodeState,
				"MASQUE retirement runtime unavailable", out, errOut)
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return masqueCommandError("retire-masque", jsonOutput, id, stlerr.CodeState,
			"MASQUE retirement Engine unavailable", out, errOut)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := engine.RetireMASQUECredential(ctx, id); err != nil {
		return lifecycleFailureWithEvidence(out, errOut, jsonOutput,
			stlerr.CodeOf(err), "link_retire-masque", &app.Result{LinkID: id},
			"original MASQUE certificate/key retirement not yet proven; preserve exact receipt and inspect original host",
			stlerr.EvidenceOf(err), err)
	}
	if jsonOutput {
		if err := json.NewEncoder(out).Encode(struct {
			SchemaVersion int           `json:"schema_version"`
			LinkID        domain.LinkID `json:"link_id"`
			Retired       bool          `json:"retired"`
		}{1, id, true}); err != nil {
			fmt.Fprintln(errOut, "MASQUE retirement committed but response unavailable; inspect saved receipt")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "MASQUE protected original %s retired with exact State receipt\n", id)
	return 0
}
