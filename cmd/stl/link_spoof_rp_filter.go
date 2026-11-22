package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/spoofhost"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// rp-filter plan is strictly read-only; apply and restore are separately
// confirmed mutations using the same canonical Engine as Spoof Remove/Restore.
func linkSpoofRPFilterCommand(args []string, out, errOut io.Writer, options *runtimeOptions) int {
	const use = "usage: stl link rp-filter (plan|apply) <id> --mode (loose|off) [--interface IFACE] [--confirm <id>] [--json] OR stl link rp-filter restore <id> --confirm <id> [--json]"
	if len(args) < 2 {
		return spoofCLIError(fmt.Errorf(use), errOut)
	}
	action := args[0]
	id := domain.LinkID(args[1])
	if id.Validate() != nil || (action != "plan" && action != "apply" && action != "restore") {
		return spoofCLIError(fmt.Errorf(use), errOut)
	}
	mode, iface, confirmed, asJSON := "", "", "", false
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--mode", "--interface", "--confirm":
			if i+1 >= len(args) {
				return spoofCLIError(fmt.Errorf(use), errOut)
			}
			name, value := args[i], args[i+1]
			i++
			switch name {
			case "--mode":
				if mode != "" {
					return spoofCLIError(fmt.Errorf(use), errOut)
				}
				mode = value
			case "--interface":
				if iface != "" {
					return spoofCLIError(fmt.Errorf(use), errOut)
				}
				iface = value
			case "--confirm":
				if confirmed != "" {
					return spoofCLIError(fmt.Errorf(use), errOut)
				}
				confirmed = value
			}
		case "--json":
			if asJSON {
				return spoofCLIError(fmt.Errorf(use), errOut)
			}
			asJSON = true
		default:
			return spoofCLIError(fmt.Errorf(use), errOut)
		}
	}
	if action == "plan" && (confirmed != "" || (mode != "loose" && mode != "off")) ||
		action == "apply" && (confirmed != string(id) || (mode != "loose" && mode != "off")) ||
		action == "restore" && (confirmed != string(id) || mode != "" || iface != "") {
		return spoofCLIError(fmt.Errorf(use), errOut)
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if action == "restore" {
		err = engine.RestoreSpoofRPFilter(ctx, id)
		if err != nil {
			return spoofCLIError(err, errOut)
		}
		if asJSON {
			return encodeRPFilterJSON(out, struct {
				SchemaVersion int           `json:"schema_version"`
				LinkID        domain.LinkID `json:"link_id"`
				Restored      bool          `json:"restored"`
			}{1, id, true}, errOut)
		}
		fmt.Fprintf(out, "Spoof %s: confirmed managed rp_filter claim removed; exact remaining owners/baselines reconciled.\n", id)
		return 0
	}
	var plan app.SpoofRPFilterPlan
	if action == "plan" {
		plan, err = engine.PreviewSpoofRPFilter(ctx, id, iface, mode)
	} else {
		plan, err = engine.ConfigureSpoofRPFilter(ctx, id, iface, mode)
	}
	if err != nil {
		return spoofCLIError(err, errOut)
	}
	if asJSON {
		return encodeRPFilterJSON(out, struct {
			SchemaVersion int                   `json:"schema_version"`
			Operation     string                `json:"operation"`
			Plan          app.SpoofRPFilterPlan `json:"plan"`
		}{1, action, plan}, errOut)
	}
	printSpoofRPFilterPlan(out, plan, action)
	return 0
}

func encodeRPFilterJSON(out io.Writer, payload any, errOut io.Writer) int {
	if err := json.NewEncoder(out).Encode(payload); err != nil {
		return spoofCLIError(err, errOut)
	}
	return 0
}

func printSpoofRPFilterPlan(out io.Writer, p app.SpoofRPFilterPlan, action string) {
	fmt.Fprintf(out, "Spoof %s rp_filter %s: incoming=%s, mode=%s, effective before=%d after=%d, other STL owners=%d\n", p.LinkID, strings.ToUpper(action), p.Interface, strings.ToUpper(p.Mode), p.EffectiveBefore, p.EffectiveAfter, p.ExistingOwners)
	if len(p.Changes) == 0 {
		fmt.Fprintln(out, "No Linux sysctl value change needed for this current plan.")
	}
	for _, item := range p.Changes {
		fmt.Fprintf(out, "  net.ipv4.conf.%s.rp_filter: %d -> %d\n", item.Interface, item.Current, item.Proposed)
	}
	if p.GlobalImpact {
		fmt.Fprintln(out, "WARNING: net.ipv4.conf.all.rp_filter affects OTHER interfaces/services and can make their effective filters weaker OR stronger depending on each NIC setting.")
	}
	fmt.Fprintln(out, p.Note)
	if action == "plan" {
		fmt.Fprintf(out, "Read-only preview. To approve on THIS host: stl link rp-filter apply %s --mode %s --confirm %s\n", p.LinkID, p.Mode, p.LinkID)
		if p.Interface != "" {
			fmt.Fprintf(out, "If NIC detection differs, add --interface %s to that command.\n", p.Interface)
		}
	} else {
		fmt.Fprintln(out, "Applied and verified. This Link's approved policy will be reconciled on STL Restore; STL restores owned old values on Link Remove or explicit restore.")
	}
}

func rpFilterStatusForLink(snapshot state.Snapshot, id domain.LinkID) *state.SpoofRPFilterClaim {
	for _, claim := range snapshot.SpoofRPFilterClaims {
		if claim.LinkID == id {
			copy := claim
			return &copy
		}
	}
	return nil
}

// Auto-detection is read-only and never changes a shared NIC without consent.
func effectiveSpoofRPFilterStatus(link domain.Link) spoofhost.RPFilterStatus {
	if link.Spoof.IngressInterface != "" {
		return spoofhost.ReadRPFilterStatus(link)
	}
	iface, err := (spoofhost.ManagedRPFilter{}).ResolveIncoming(link, "")
	if err != nil {
		return spoofhost.RPFilterStatus{Mode: "UNVERIFIED", Note: err.Error()}
	}
	link.Spoof.IngressInterface = iface
	return spoofhost.ReadRPFilterStatus(link)
}
