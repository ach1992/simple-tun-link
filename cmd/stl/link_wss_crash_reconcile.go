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

// Explicit operator consent. Both paths inspect host resources read-only:
// initial Ensure clears only a journal; completed interrupted Remove commits
// deletion of the exact persisted Link plus an immutable retirement receipt.
// Neither endpoint deletes, adopts or restarts any kernel/systemd/nft object.
func linkWSSCrashVacantCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkWSSCrashCommand(args, out, errOut, opts, false)
}
func linkWSSCrashRemovedCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkWSSCrashCommand(args, out, errOut, opts, true)
}
func linkWSSCrashRepairVacantCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkWSSCrashCommandMode(args, out, errOut, opts, "repair-vacant")
}
func linkWSSCrashOriginalCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkWSSCrashCommandMode(args, out, errOut, opts, "original")
}
func linkWSSColdBootArmCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkWSSCrashCommandMode(args, out, errOut, opts, "cold-boot-arm")
}
func linkWSSColdBootReconcileCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkWSSCrashCommandMode(args, out, errOut, opts, "cold-boot")
}
func linkWSSCrashCommand(args []string, out, errOut io.Writer, opts *runtimeOptions, removed bool) int {
	mode := "initial-vacant"
	if removed {
		mode = "removed"
	}
	return linkWSSCrashCommandMode(args, out, errOut, opts, mode)
}
func linkWSSCrashCommandMode(args []string, out, errOut io.Writer, opts *runtimeOptions, mode string) int {
	removed := mode == "removed"
	repair := mode == "repair-vacant"
	original := mode == "original"
	coldBootArm := mode == "cold-boot-arm"
	coldBoot := mode == "cold-boot"
	command := "reconcile-wss-vacant"
	if removed {
		command = "reconcile-wss-removed"
	} else if repair {
		command = "reconcile-wss-repair-vacant"
	} else if original {
		command = "reconcile-wss-original"
	} else if coldBootArm {
		command = "arm-wss-cold-boot"
	} else if coldBoot {
		command = "reconcile-wss-cold-boot"
	}
	isJSON := len(args) == 4 && args[3] == "--json"
	if !((len(args) == 3 || isJSON) && args[1] == "--confirm" && args[0] == args[2]) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "wss_crash_reconcile",
			"usage: stl link "+command+" <link-id> --confirm <link-id> [--json]")
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "wss_crash_reconcile", "invalid Link ID")
	}
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "wss_crash_reconcile", "runtime unavailable")
		}
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "wss_crash_reconcile", "canonical Engine unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if coldBootArm {
		err = engine.ArmWSSColdBootRecovery(ctx, id)
	} else if coldBoot {
		err = engine.ReconcileWSSCrashColdBoot(ctx, id)
	} else if removed {
		err = engine.ReconcileWSSCrashRemoved(ctx, id)
	} else if repair {
		err = engine.ReconcileWSSCrashRepairVacant(ctx, id)
	} else if original {
		err = engine.ReconcileWSSCrashOriginal(ctx, id)
	} else {
		err = engine.ReconcileWSSCrashVacant(ctx, id)
	}
	if err != nil {
		details := "WSS journal retained: exact original owner and complete host vacancy required; no host resources deleted"
		if original {
			details = "WSS journal retained: original-object identity, scoped compensation or final host vacancy unverified. Earlier exact-owner host compensation may have been applied; reinspect and retry only with this original journal"
		}
		return readCommandError(out, errOut, isJSON, stlerr.CodeOf(err), "wss_crash_reconcile", details)
	}
	if coldBootArm {
		if isJSON {
			return encodeWSSColdBootResult(out, id, true)
		}
		fmt.Fprintf(out, "WSS Link %s cold-boot recovery checkpoint durably armed; original journal, firewall, kernel, services, credentials and owner claims unchanged.\n", id)
		fmt.Fprintln(out, "No reboot performed. Arrange separate Owner-approved whole-kernel reboot after host/service impact review, then use reconcile-wss-cold-boot; ordinary recovery remains fail closed.")
		return 0
	}
	if coldBoot {
		if isJSON {
			return encodeWSSColdBootResult(out, id, false)
		}
		fmt.Fprintf(out, "WSS Link %s original cold-boot generation extinct; current-boot host vacancy verified; exact journal/State transition committed without host mutation.\n", id)
		fmt.Fprintln(out, "For committed Remove, retire-wss still requires the original credential receipt and fresh strict absence.")
		return 0
	}
	if original && isJSON {
		payload := struct {
			SchemaVersion                  int           `json:"schema_version"`
			LinkID                         domain.LinkID `json:"link_id"`
			OriginalObjectRecovery         bool          `json:"original_object_recovery"`
			JournalCleared                 bool          `json:"journal_cleared"`
			HostVacantVerified             bool          `json:"host_vacant_verified"`
			ScopedHostCompensationPossible bool          `json:"scoped_host_compensation_possible"`
		}{1, id, true, true, true, true}
		if err := json.NewEncoder(out).Encode(payload); err != nil {
			return 1
		}
		return 0
	}
	if isJSON {
		payload := struct {
			SchemaVersion      int           `json:"schema_version"`
			LinkID             domain.LinkID `json:"link_id"`
			VacantVerified     bool          `json:"vacant_verified"`
			JournalCleared     bool          `json:"journal_cleared"`
			HostMutated        bool          `json:"host_mutated"`
			RemovedCommitted   bool          `json:"removed_committed"`
			RetirementReceipt  bool          `json:"retirement_receipt"`
			PreservedCommitted bool          `json:"preserved_committed"`
		}{1, id, true, true, false, removed, removed, repair}
		if err := json.NewEncoder(out).Encode(payload); err != nil {
			return 1
		}
	} else if original {
		fmt.Fprintf(out, "WSS Link %s original-host-object compensation verified, complete host vacancy proved, and exact journal/State transition committed. No foreign or name-only resource cleanup authorized.\n", id)
	} else if repair {
		fmt.Fprintf(out, "WSS Link %s committed Ensure journal cleared after complete host vacancy proof. Original committed Link, owner claims and credential identities preserved; normal Ensure/RestoreAll may now recreate the Link. No host objects touched.\n", id)
	} else if removed {
		fmt.Fprintf(out, "WSS Link %s Removed from durable State after verified absence; original retirement receipt committed. No host files, services or kernel resources changed. Use retire-wss to retire the exact original credentials.\n", id)
	} else {
		fmt.Fprintf(out, "WSS Link %s pre-effect journal cleared after host vacancy proof. No host resources or credentials modified. Retry only the original Link identity and protected handoff.\n", id)
	}
	return 0
}

// Versioned no-secret result. Armed does not mean a reboot occurred.
func encodeWSSColdBootResult(out io.Writer, id domain.LinkID, armed bool) int {
	payload := map[string]any{
		"schema_version": 1, "link_id": id,
		"recovery_method":      "owner_approved_cold_boot",
		"checkpoint_persisted": armed, "journal_cleared": !armed,
		"host_mutated": false, "reboot_performed": false,
		"kernel_reset_verified": !armed,
	}
	if err := json.NewEncoder(out).Encode(payload); err != nil {
		return 1
	}
	return 0
}
