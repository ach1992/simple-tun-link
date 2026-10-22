package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Explicit consent, not a hidden repair during list, status or boot restore.
// Only deletes an exact durable journal after host vacancy is proven.
func linkWSSCrashVacantCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := len(args) == 4 && args[3] == "--json"
	if !((len(args) == 3 || isJSON) && args[1] == "--confirm" && args[0] == args[2]) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "wss_crash_reconcile",
			"usage: stl link reconcile-wss-vacant <link-id> --confirm <link-id> [--json]")
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "wss_crash_reconcile", "invalid Link ID")
	}
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState,
				"wss_crash_reconcile", "runtime unavailable")
		}
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState,
			"wss_crash_reconcile", "canonical Engine unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := engine.ReconcileWSSCrashVacant(ctx, id); err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeOf(err),
			"wss_crash_reconcile", "WSS pre-effect journal retained: host absence or original identity not proven; no resources deleted")
	}
	if isJSON {
		payload := struct {
			SchemaVersion  int           `json:"schema_version"`
			LinkID         domain.LinkID `json:"link_id"`
			VacantVerified bool          `json:"vacant_verified"`
			JournalCleared bool          `json:"journal_cleared"`
			HostMutated    bool          `json:"host_mutated"`
		}{1, id, true, true, false}
		if json.NewEncoder(out).Encode(payload) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(out, "WSS Link %s pre-effect journal cleared after host vacancy proof. No host resources or credentials modified. Retry only the original Link and protected handoff.\n", id)
	}
	return 0
}
