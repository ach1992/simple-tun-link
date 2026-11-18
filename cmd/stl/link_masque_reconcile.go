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

// This command can ONLY reconcile a saved MASQUE journal and only after a
// double-checked empty original unit/TUN inventory. It never forcibly
// terminates a service or deletes a foreign resource.
func linkMASQUEReconcileCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	if !((len(args) == 3) || (len(args) == 4 && args[3] == "--json")) ||
		args[1] != "--confirm" || args[0] != args[2] {
		return masqueCommandError("reconcile-masque", jsonOutput, "", stlerr.CodeInvalid,
			"usage: stl link reconcile-masque <id> --confirm <id> [--json]", out, errOut)
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return masqueCommandError("reconcile-masque", jsonOutput, id, stlerr.CodeInvalid, "invalid Link ID", out, errOut)
	}
	var err error
	if options == nil {
		options, err = assembleRuntimeOptionsForBackend(state.DefaultRoot, domain.BackendMASQUE)
		if err != nil {
			return masqueCommandError("reconcile-masque", jsonOutput, id, stlerr.CodeState, "MASQUE recovery runtime unavailable", out, errOut)
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return masqueCommandError("reconcile-masque", jsonOutput, id, stlerr.CodeState, "MASQUE recovery Engine unavailable", out, errOut)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := engine.ReconcileMASQUE(ctx, id)
	if err != nil {
		return lifecycleFailureWithEvidence(out, errOut, jsonOutput,
			stlerr.CodeOf(err), "link_reconcile-masque", &app.Result{LinkID: id},
			"MASQUE original host effect remains unverified or receipt retirement incomplete; inspect original State and service",
			stlerr.EvidenceOf(err), err)
	}
	if jsonOutput {
		payload := struct {
			SchemaVersion    int           `json:"schema_version"`
			LinkID           domain.LinkID `json:"link_id"`
			Recovery         string        `json:"recovery"`
			CommittedRemoved bool          `json:"committed_removed"`
			OriginalRetired  bool          `json:"original_retired"`
		}{1, id, result.Recovery, result.CommittedRemoved, result.OriginalRetired}
		if json.NewEncoder(out).Encode(payload) != nil {
			fmt.Fprintln(errOut, "MASQUE recovery committed but result output failed; inspect saved State")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "MASQUE %s: %s (original material retired: %t)\n",
		id, result.Recovery, result.OriginalRetired)
	return 0
}
