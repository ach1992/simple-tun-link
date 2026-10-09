package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const readOperationTimeout = 12 * time.Second

// Public read models are projections, not serialized desired state.
// Display names and other user-provided fields can contain secrets.
type linkSummary struct {
	ID            domain.LinkID        `json:"id"`
	Backend       domain.Backend       `json:"backend"`
	Encapsulation domain.Encapsulation `json:"encapsulation"`
	LocalAddress  string               `json:"local_address"`
	PeerAddress   string               `json:"peer_address"`
}

func summarizeLink(link domain.Link) linkSummary {
	return linkSummary{
		ID: link.ID, Backend: link.Backend, Encapsulation: link.Encapsulation,
		LocalAddress: link.Addresses.Local.String(), PeerAddress: link.Addresses.Peer.String(),
	}
}

type linkListResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Links         []linkSummary `json:"links"`
}

// InterfaceVerified is true only after a live identity/counter check.
// It does not assert Link Address reachability or firewall effectiveness.
type linkStatusResponse struct {
	SchemaVersion     int                          `json:"schema_version"`
	Link              linkSummary                  `json:"link"`
	InterfaceVerified bool                         `json:"interface_verified"`
	Connectivity      string                       `json:"connectivity"`
	GREState          *grebackend.DiagnosticState  `json:"gre_state,omitempty"`
	IPIPState         *ipipbackend.DiagnosticState `json:"ipip_state,omitempty"`
}

type linkReadErrorResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Error         *stlerr.Error `json:"error"`
}

func readCommandError(stdout, stderr io.Writer, jsonOutput bool, code stlerr.Code, operation, detail string) int {
	public := stlerr.New(code, operation, "", "", detail)
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(linkReadErrorResponse{SchemaVersion: jsonSchemaVersion, Error: public}); err != nil {
			fmt.Fprintln(stderr, "cannot encode error response")
			return 1
		}
	} else {
		fmt.Fprintln(stderr, public.Error())
	}
	switch code {
	case stlerr.CodeInvalid:
		return 2
	case stlerr.CodeUnsupported:
		return 4
	default:
		return 1
	}
}

func linkReadCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	isStatus := args[0] == "status"
	jsonOutput := len(args) > 0 && args[len(args)-1] == "--json"
	valid := (!isStatus && (len(args) == 1 || (len(args) == 2 && jsonOutput))) ||
		(isStatus && (len(args) == 2 || (len(args) == 3 && jsonOutput)))
	if !valid {
		if isStatus {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_status", "usage: stl link status <link-id> [--json]")
		}
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_list", "usage: stl link list [--json]")
	}
	if isStatus {
		if err := domain.LinkID(args[1]).Validate(); err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_status", "invalid Link ID")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	defer cancel()
	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	if root == "" {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_read", "local state root is unavailable")
	}
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_read", "cannot read local desired-state snapshot")
	}
	if !isStatus {
		items := make([]linkSummary, 0, len(snapshot.Links))
		for _, item := range snapshot.Links {
			items = append(items, summarizeLink(item.Desired))
		}
		if jsonOutput {
			if err := json.NewEncoder(stdout).Encode(linkListResponse{SchemaVersion: jsonSchemaVersion, Links: items}); err != nil {
				fmt.Fprintln(stderr, "cannot encode link list")
				return 1
			}
			return 0
		}
		fmt.Fprintln(stdout, "Configured Links (not a live connectivity check):")
		for _, item := range items {
			fmt.Fprintf(stdout, "%s  %s/%s  %s -> %s\n", item.ID, item.Backend, item.Encapsulation, item.LocalAddress, item.PeerAddress)
		}
		fmt.Fprintf(stdout, "%d configured link(s)\n", len(items))
		return 0
	}
	id := domain.LinkID(args[1])
	record, ok := snapshot.Find(id)
	if !ok {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_status", "Link ID is not present in local desired state")
	}
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_status", "cannot initialize read-only backend inspection")
		}
	}
	var selected backend.Backend
	for _, item := range options.backends {
		if item != nil && item.Kind() == record.Desired.Backend {
			selected = item
			break
		}
	}
	if selected == nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "live status is unavailable for this backend")
	}
	response := linkStatusResponse{
		SchemaVersion: jsonSchemaVersion, Link: summarizeLink(record.Desired),
		Connectivity: "not_measured",
	}
	var interfaceName, kindLabel string
	var rxPackets, txPackets uint64
	switch record.Desired.Backend {
	case domain.BackendGRE:
		inspector, ok := selected.(interface {
			DiagnosticState(context.Context, domain.Link) (grebackend.DiagnosticState, error)
		})
		if !ok {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "backend has no live diagnostic adapter")
		}
		observed, err := inspector.DiagnosticState(ctx, record.Desired)
		if err != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput)
		}
		expectedName, nameErr := grebackend.InterfaceName(id)
		if nameErr != nil || observed.Interface != expectedName || observed.IfIndex <= 0 ||
			observed.Encapsulation != record.Desired.Encapsulation {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "backend returned inconsistent Link identity")
		}
		response.GREState = &observed
		interfaceName, kindLabel = observed.Interface, "GRE"
		rxPackets, txPackets = observed.RXPackets, observed.TXPackets
	case domain.BackendIPIP:
		inspector, ok := selected.(interface {
			DiagnosticState(context.Context, domain.Link) (ipipbackend.DiagnosticState, error)
		})
		if !ok {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "backend has no live diagnostic adapter")
		}
		observed, err := inspector.DiagnosticState(ctx, record.Desired)
		if err != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput)
		}
		expectedName, nameErr := ipipbackend.InterfaceName(id)
		if nameErr != nil || observed.Interface != expectedName || observed.IfIndex <= 0 ||
			observed.Encapsulation != record.Desired.Encapsulation {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "backend returned inconsistent Link identity")
		}
		response.IPIPState = &observed
		interfaceName, kindLabel = observed.Interface, "IPIP"
		rxPackets, txPackets = observed.RXPackets, observed.TXPackets
	default:
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "live status is unavailable for this backend")
	}
	response.InterfaceVerified = true
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			fmt.Fprintln(stderr, "cannot encode link status")
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Link %s: %s/%s interface verified on %s; connectivity not measured (RX %d packets, TX %d packets)\n",
		id, kindLabel, record.Desired.Encapsulation, interfaceName, rxPackets, txPackets)
	return 0
}

func readStatusInspectionError(ctx context.Context, stdout, stderr io.Writer, jsonOutput bool) int {
	if ctx.Err() != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "live diagnostic inspection was interrupted")
	}
	return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "live diagnostic state could not be verified")
}
