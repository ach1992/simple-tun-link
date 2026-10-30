package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// This command reconciles one durable managed journal only after the Engine
// proves a later genuine host kernel generation and exact host vacancy. It
// never fabricates a reboot, adopts matching objects, or replays a first start.
func linkQUICColdBootReconcileCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	const operation = "reconcile-quic-cold-boot"
	isJSON := len(args) == 4 && args[3] == "--json"
	if !((len(args) == 3 || isJSON) && args[1] == "--confirm" && args[0] == args[2]) {
		return quicCommandError(operation, isJSON, "", stlerr.CodeInvalid, "usage: stl link reconcile-quic-cold-boot <link-id> --confirm <link-id> [--json]", out, errOut)
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return quicCommandError(operation, isJSON, "", stlerr.CodeInvalid, "invalid Link identity", out, errOut)
	}
	var err error
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return quicCommandError(operation, isJSON, id, stlerr.CodeState, "runtime unavailable", out, errOut)
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return quicCommandError(operation, isJSON, id, stlerr.CodeState, "canonical Engine unavailable", out, errOut)
	}
	ctx, cancel := quicCtx()
	defer cancel()
	result, err := engine.ReconcileQUICAfterKernelExtinction(ctx, id)
	if err != nil {
		return quicActivationFailure(operation, isJSON, id, app.Result{LinkID: id}, err,
			"reconciliation refused or unconfirmed; preserve the original journal and credentials. This operation requires a verified later host kernel boot, complete original material, and exact host vacancy", out, errOut)
	}
	if isJSON {
		if json.NewEncoder(out).Encode(struct {
			SchemaVersion int           `json:"schema_version"`
			Operation     string        `json:"operation"`
			LinkID        domain.LinkID `json:"link_id"`
			Changed       bool          `json:"changed"`
			Reconciled    bool          `json:"reconciled"`
		}{1, operation, id, result.Changed, true}) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(out, "QUIC operation for Link %s reconciled after verified kernel-generation extinction. Review committed State before ordinary restore or receipt-bound credential retirement.\n", id)
	}
	return 0
}
