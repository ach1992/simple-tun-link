package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type wssSupersessionResponse struct {
	SchemaVersion              int           `json:"schema_version"`
	Operation                  string        `json:"operation"`
	Outcome                    string        `json:"outcome"`
	OldLinkID                  domain.LinkID `json:"old_link_id"`
	ReplacementLinkID          domain.LinkID `json:"replacement_link_id"`
	Changed                    bool          `json:"changed"`
	OldRestoreBlocked          bool          `json:"old_restore_blocked"`
	OriginalDeletionProven     bool          `json:"original_deletion_proven"`
	HostMutated                bool          `json:"host_mutated"`
	ReplacementTrafficVerified bool          `json:"replacement_traffic_verified"`
	RebootPerformed            bool          `json:"reboot_performed"`
}

// Explicit two-identity, operator-confirmed State transition. This command
// never creates a peer or changes the old kernel/guard/helper identity.
// The operator must first verify the new pair on BOTH endpoints and actual
// private-IP traffic; local committed State alone cannot prove that traffic.
func linkWSSSupersedeCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	jsonOutput := len(args) > 0 && args[len(args)-1] == "--json"
	if !((len(args) == 5 || (len(args) == 6 && jsonOutput)) &&
		args[1] == "--replacement" && args[3] == "--confirm" && args[0] == args[4]) {
		return readCommandError(out, errOut, jsonOutput, stlerr.CodeInvalid, "wss_supersede",
			"usage: stl link supersede-wss <old-id> --replacement <new-id> --confirm <old-id> [--json]")
	}
	oldID, newID := domain.LinkID(args[0]), domain.LinkID(args[2])
	if oldID.Validate() != nil || newID.Validate() != nil || oldID == newID {
		return readCommandError(out, errOut, jsonOutput, stlerr.CodeInvalid, "wss_supersede",
			"original and replacement must be distinct valid WSS Link IDs")
	}
	if options == nil {
		var err error
		options, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, jsonOutput, stlerr.CodeState, "wss_supersede",
				"canonical runtime unavailable; no supersession can be confirmed")
		}
	}
	engine, err := buildRuntimeEngine(*options)
	if err != nil {
		return readCommandError(out, errOut, jsonOutput, stlerr.CodeState, "wss_supersede",
			"canonical Engine unavailable; original State unchanged or unconfirmed")
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, 30*time.Second)
	defer cancel()
	changed, err := engine.SupersedeWSSOriginal(ctx, oldID, newID)
	if err != nil {
		public := stlerr.New(stlerr.CodeOf(err), "wss_supersede", string(oldID), "wireguard-wss",
			"supersession could not be durably confirmed; do not assume the old original is inactive")
		public.ReasonCode = "wss_supersession_unconfirmed"
		public.NextStep = "Inspect stl link plan-wss-replacement " + string(oldID) +
			" --json and both committed WSS identities. Verify fresh disjoint resources and real bilateral private-IP traffic, then retry only after confirming State; do not delete original credentials or replay blocked Ensure."
		return readCommandPublicError(out, errOut, jsonOutput, public)
	}
	result := wssSupersessionResponse{
		SchemaVersion: 1, Operation: "wss_supersede", Outcome: "quarantined_old",
		OldLinkID: oldID, ReplacementLinkID: newID, Changed: changed,
		OldRestoreBlocked: true,
	}
	if jsonOutput {
		if err := json.NewEncoder(out).Encode(result); err != nil {
			fmt.Fprintln(errOut, "supersession may be committed but machine report could not be written; read protected State before retry")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "Original WSS Link %s durably superseded by %s; old automatic Restore and ordinary Ensure disabled (changed=%t).\n", oldID, newID, changed)
	fmt.Fprintln(out, "No kernel interface, helper, firewall, credentials, or external routes were removed or altered. Old reservations remain protected; separately verify new peer traffic and retire old only with proven original extinction.")
	return 0
}
