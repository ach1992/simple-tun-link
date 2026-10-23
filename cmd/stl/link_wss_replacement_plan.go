package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// WSSReplacementPlan is a read-only assessment of persisted authority, NOT
// evidence that a hidden original has disappeared or a new peer will work.
// The canonical create/import/Engine transactions remain the only writers.
type WSSReplacementPlan struct {
	SchemaVersion          int           `json:"schema_version"`
	OldLinkID              domain.LinkID `json:"old_link_id"`
	RecoveryState          string        `json:"recovery_state"`
	Committed              bool          `json:"old_link_committed"`
	CrashJournalRetained   bool          `json:"crash_journal_retained"`
	OldResourcesReserved   bool          `json:"old_resources_reserved"`
	OldIdentityReserved    bool          `json:"old_identity_reserved"`
	HostMutated            bool          `json:"host_mutated"`
	OriginalDeletionProven bool          `json:"original_deletion_proven"`
	RebootPerformed        bool          `json:"reboot_performed"`
	Steps                  []string      `json:"steps"`
}

// A saved WSS original can be alive in another network namespace while
// absent from the original namespace. Never convert local absence into
// original deletion proof, authorization to retire keys, or resource reuse.
func planWSSReplacement(snapshot state.Snapshot, id domain.LinkID) (WSSReplacementPlan, bool) {
	record, committed := snapshot.Find(id)
	journal, pending := snapshot.FindWSSCrashOperation(id)
	receipt, removed := snapshot.FindRemovalReceipt(id)
	if committed && record.Desired.Backend != domain.BackendWireGuardWSS {
		return WSSReplacementPlan{}, false
	}
	if pending && journal.Intent.Backend != domain.BackendWireGuardWSS {
		return WSSReplacementPlan{}, false
	}
	if !committed && !pending && (!removed || receipt.Backend != domain.BackendWireGuardWSS) {
		return WSSReplacementPlan{}, false
	}

	result := WSSReplacementPlan{
		SchemaVersion: 1, OldLinkID: id, Committed: committed,
		CrashJournalRetained: pending, OldResourcesReserved: committed || pending, OldIdentityReserved: true,
		Steps: []string{},
	}
	switch {
	case pending:
		result.RecoveryState = "crash_journal_quarantined"
		result.Steps = append(result.Steps,
			"Do not retry the blocked original, remove its ownership claims or delete original credentials. Exact original-object recovery needs verified nonce/ifindex and a positive deletion witness; a missing local interface is not enough.",
			fmt.Sprintf("Inspect the original crash in the operator recovery runbook; scoped stl link reconcile-wss-original %s --confirm %s requires verified original identity and explicit Owner authorization for the host effects.", id, id))
	case committed:
		result.RecoveryState = "committed_health_unverified"
		result.Steps = append(result.Steps,
			fmt.Sprintf("First inspect stl link diagnose-wss %s --json and peer-side connectivity. An old committed Link is not declared broken by this read-only State assessment.", id),
			"Use the original Link's approved repair/Ensure only after verifying host identity and intended effects; do not assume a missing local WG means kernel extinction.")
	default:
		result.RecoveryState = "removed_identity_reserved"
		result.Steps = append(result.Steps,
			"The old Link has a removal receipt and its identity must not be reused. Follow receipt-bound retire-wss only when original termination and protected credential absence can be proved.")
	}

	result.Steps = append(result.Steps,
		"If recovery is not possible, prepare an independent WSS peer pair on the intended listener: stl link create-wss --stdin --output <private-file>. Choose a NEW Link ID, new WG/WSS keys, distinct private Link subnet and unused WG UDP / WSS TCP / forwarding ports; never copy the old Link's secrets or claims.",
		"Transfer the generated sensitive receiver handoff through an authenticated encrypted channel; run stl link preview-wss --stdin --json and stl link import-wss --stdin --confirm <preview-sha256> on the peer. The Engine must validate every resource conflict before host Apply.",
		"Verify both newly configured peers with stl link diagnose-wss <new-link-id> --json and actual private-IP peer traffic before shifting workloads. Successful local Ensure alone is not connectivity proof.",
		"Keep the old original's State/journal, original ownership reservations and protected credentials untouched until exact original deletion/retirement can be independently proved. A new independent Link need not reboot the host, but is NOT guaranteed if suitable disjoint resources, peer handoff or safe host admission are unavailable.",
	)
	return result, true
}

func linkWSSReplacementPlanCommand(args []string, stdout, stderr io.Writer, opts *runtimeOptions) int {
	jsonOutput := len(args) > 0 && args[len(args)-1] == "--json"
	if !((len(args) == 1) || (len(args) == 2 && jsonOutput)) {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "wss_replacement_plan",
			"usage: stl link plan-wss-replacement <old-link-id> [--json]")
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "wss_replacement_plan", "invalid old Link ID")
	}
	root := state.DefaultRoot
	if opts != nil {
		root = opts.stateRoot
	}
	if root == "" {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "wss_replacement_plan", "local State root unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil || ctx.Err() != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "wss_replacement_plan",
			"trusted local State snapshot unavailable; no replacement decision can be made")
	}
	plan, found := planWSSReplacement(snapshot, id)
	if !found {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "wss_replacement_plan",
			"no persisted WSS Link, crash journal or removal receipt matches this identity")
	}
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(plan); err != nil {
			fmt.Fprintln(stderr, "cannot encode WSS replacement plan")
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "WSS recovery/replacement plan for %s: %s\n", plan.OldLinkID, plan.RecoveryState)
	fmt.Fprintf(stdout, "Committed: %t; crash journal retained: %t; old resources reserved: %t\n",
		plan.Committed, plan.CrashJournalRetained, plan.OldResourcesReserved)
	fmt.Fprintln(stdout, "Read-only plan: no live kernel deletion or vacancy inspected; no host change or reboot performed.")
	for i, step := range plan.Steps {
		fmt.Fprintf(stdout, "%d. %s\n", i+1, step)
	}
	return 0
}
