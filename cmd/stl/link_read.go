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
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
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
	Disposition   string               `json:"disposition,omitempty"`
	SupersededBy  domain.LinkID        `json:"superseded_by,omitempty"`
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
	SchemaVersion     int                           `json:"schema_version"`
	Link              linkSummary                   `json:"link"`
	InterfaceVerified bool                          `json:"interface_verified"`
	Connectivity      string                        `json:"connectivity"`
	GREState          *grebackend.DiagnosticState   `json:"gre_state,omitempty"`
	IPIPState         *ipipbackend.DiagnosticState  `json:"ipip_state,omitempty"`
	WireGuardState    *wgbackend.DiagnosticState    `json:"wireguard_state,omitempty"`
	WSSState          *WSSLinkDiagnostics           `json:"wss_state,omitempty"`
	QUICState         *QUICLinkDiagnostics          `json:"quic_state,omitempty"`
	IPsecState        *ipsecbackend.DiagnosticState `json:"ipsec_state,omitempty"`
}

type linkReadErrorResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Error         *stlerr.Error `json:"error"`
}

func readCommandError(stdout, stderr io.Writer, jsonOutput bool, code stlerr.Code, operation, detail string) int {
	return readCommandPublicError(stdout, stderr, jsonOutput,
		stlerr.New(code, operation, "", "", detail))
}

// readCommandPublicError preserves the versioned error envelope and exit
// semantics for ordinary errors and for errors with additional safe context.
func readCommandPublicError(stdout, stderr io.Writer, jsonOutput bool, public *stlerr.Error) int {
	public = stlerr.WithGuidance(public)
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(linkReadErrorResponse{SchemaVersion: jsonSchemaVersion, Error: public}); err != nil {
			fmt.Fprintln(stderr, "cannot encode error response")
			return 1
		}
	} else {
		fmt.Fprintln(stderr, public.Error())
		fmt.Fprintf(stderr, "Reason: %s\nNext: %s\n", public.ReasonCode, public.NextStep)
	}
	switch public.Code {
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
			summary := summarizeLink(item.Desired)
			if item.WSSSupersededBy != "" {
				summary.Disposition = "quarantined_old"
				summary.SupersededBy = item.WSSSupersededBy
			}
			items = append(items, summary)
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
			fmt.Fprintf(stdout, "%s  %s/%s  %s -> %s", item.ID, item.Backend, item.Encapsulation, item.LocalAddress, item.PeerAddress)
			if item.Disposition == "quarantined_old" {
				fmt.Fprintf(stdout, "  [quarantined_old -> %s; NOT auto-restored]", item.SupersededBy)
			}
			fmt.Fprintln(stdout)
		}
		fmt.Fprintf(stdout, "%d configured link(s)\n", len(items))
		return 0
	}
	id := domain.LinkID(args[1])
	record, ok := snapshot.Find(id)
	if !ok {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_status", "Link ID is not present in local desired state")
	}
	if record.WSSSupersededBy != "" {
		blocked := stlerr.New(stlerr.CodeConflict, "link_status", string(id), "wireguard-wss",
			"original WSS Link has been durably superseded; no active status is asserted")
		blocked.ReasonCode = "wss_original_superseded"
		blocked.NextStep = "Inspect stl link plan-wss-replacement " + string(id) + " --json and verify replacement " +
			string(record.WSSSupersededBy) + " on both peers. Do not treat this original as active or reuse its reserved resources."
		return readCommandPublicError(stdout, stderr, jsonOutput, blocked)
	}
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_status", "cannot initialize read-only backend inspection")
		}
	}
	if record.Desired.Backend == domain.BackendWireGuardQUIC {
		observed, runner, inspectErr := trustedQUICObservation(ctx, record.Desired, *options)
		if inspectErr != nil {
			return readQUICInspectionError(ctx, stdout, stderr, jsonOutput, inspectErr)
		}
		if observed.KernelWireGuardPresent {
			if _, inspectErr := diagnostics.VerifyPrivateLinkIdentity(ctx, record.Desired, observed.Interface, runner); inspectErr != nil {
				return readQUICInspectionError(ctx, stdout, stderr, jsonOutput, inspectErr)
			}
		}
		response := linkStatusResponse{SchemaVersion: jsonSchemaVersion, Link: summarizeLink(record.Desired),
			InterfaceVerified: observed.KernelWireGuardPresent, Connectivity: "not_measured", QUICState: &observed}
		if jsonOutput {
			if json.NewEncoder(stdout).Encode(response) != nil {
				return 1
			}
		} else {
			fmt.Fprintf(stdout, "Link %s: managed QUIC helper=%t guard=%t kernel=%t WG-handshake=%t, RX=%d TX=%d bytes (connectivity not measured)\n",
				id, observed.QUICHelperActive, observed.WGIngressGuardActive, observed.KernelWireGuardPresent,
				observed.WireGuardHandshakeObserved, observed.RXBytes, observed.TXBytes)
		}
		return 0
	}
	// Managed WSS does not register as Native WireGuard. Its separately
	// attested helper/guard/kernel observer still belongs in the SAME
	// public status contract and the SAME terminal menu.
	if record.Desired.Backend == domain.BackendWireGuardWSS {
		observed, runner, err := trustedWSSObservation(ctx, record.Desired, *options)
		if err != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput, err)
		}
		iface, err := wgbackend.InterfaceName(id)
		if err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "WSS interface identity unverified")
		}
		if _, err := diagnostics.VerifyPrivateLinkIdentity(ctx, record.Desired, iface, runner); err != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput, err)
		}
		response := linkStatusResponse{SchemaVersion: jsonSchemaVersion, Link: summarizeLink(record.Desired),
			InterfaceVerified: observed.KernelWireGuardPresent, Connectivity: "not_measured", WSSState: &observed}
		if jsonOutput {
			if err := json.NewEncoder(stdout).Encode(response); err != nil {
				fmt.Fprintln(stderr, "cannot encode WSS link status")
				return 1
			}
		} else {
			fmt.Fprintf(stdout, "Link %s: managed WSS WireGuard interface %s verified; helper=%t guard=%t handshake=%t, RX=%d TX=%d bytes (connectivity not measured)\n",
				id, iface, observed.WSSHelperActive, observed.WGIngressGuardActive, observed.WireGuardHandshakeObserved, observed.RXBytes, observed.TXBytes)
		}
		return 0
	}
	var selected backend.Backend
	for _, item := range options.backends {
		if item != nil && item.Kind() == record.Desired.Backend {
			selected = item
			break
		}
	}
	if selected == nil {
		if record.Desired.Backend == domain.BackendIPsec {
			return ipsecUnregisteredError(stdout, stderr, jsonOutput, "link_status", id)
		}
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "live status is unavailable for this backend")
	}
	response := linkStatusResponse{
		SchemaVersion: jsonSchemaVersion, Link: summarizeLink(record.Desired),
		Connectivity: "not_measured",
	}
	var interfaceName, kindLabel string
	var rxPackets, txPackets uint64
	counterUnit := "packets"
	switch record.Desired.Backend {
	case domain.BackendIPsec:
		inspector, ok := selected.(*ipsecbackend.OperationalBackend)
		if !ok {
			return ipsecUnregisteredError(stdout, stderr, jsonOutput, "link_status", id)
		}
		observed, err := inspector.DiagnosticState(ctx, record.Desired)
		if err != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput, err)
		}
		expected, _ := ipsecbackend.NewProfile(record.Desired)
		if observed.Interface != expected.InterfaceName || observed.XFRMID != expected.InterfaceID ||
			observed.IfIndex <= 0 || !observed.ConnectionConfigured {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status",
				"live IPsec interface or strongSwan identity is inconsistent")
		}
		response.IPsecState = &observed
		interfaceName, kindLabel = observed.Interface, "IPsec"
	case domain.BackendGRE:
		inspector, ok := selected.(interface {
			DiagnosticState(context.Context, domain.Link) (grebackend.DiagnosticState, error)
		})
		if !ok {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "backend has no live diagnostic adapter")
		}
		observed, err := inspector.DiagnosticState(ctx, record.Desired)
		if err != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput, err)
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
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput, err)
		}
		expectedName, nameErr := ipipbackend.InterfaceName(id)
		if nameErr != nil || observed.Interface != expectedName || observed.IfIndex <= 0 ||
			observed.Encapsulation != record.Desired.Encapsulation {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "backend returned inconsistent Link identity")
		}
		response.IPIPState = &observed
		interfaceName, kindLabel = observed.Interface, "IPIP"
		rxPackets, txPackets = observed.RXPackets, observed.TXPackets
	case domain.BackendWireGuard:
		inspector, ok := selected.(interface {
			DiagnosticState(context.Context, domain.Link) (wgbackend.DiagnosticState, error)
		})
		if !ok {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_status", "WireGuard has no live diagnostic adapter")
		}
		measured, readErr := inspector.DiagnosticState(ctx, record.Desired)
		if readErr != nil {
			return readStatusInspectionError(ctx, stdout, stderr, jsonOutput, readErr)
		}
		expectedName, nameErr := wgbackend.InterfaceName(id)
		if nameErr != nil || measured.Interface != expectedName || measured.IfIndex <= 0 ||
			measured.LocalPublicKey != record.Desired.WireGuard.LocalPublicKey ||
			measured.PeerPublicKey != record.Desired.WireGuard.PeerPublicKey ||
			measured.ListenPort != record.Desired.WireGuard.ListenPort {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "WireGuard returned inconsistent Link identity")
		}
		response.WireGuardState = &measured
		interfaceName, kindLabel = measured.Interface, "WireGuard"
		rxPackets, txPackets = measured.RXBytes, measured.TXBytes
		counterUnit = "bytes"
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
	if response.IPsecState != nil {
		fmt.Fprintf(stdout, "Link %s: IPsec/%s XFRM interface %s verified; SA observed=%t, packet reachability not measured\n",
			id, record.Desired.Encapsulation, interfaceName, response.IPsecState.SecurityAssociationPresent)
		return 0
	}
	fmt.Fprintf(stdout, "Link %s: %s/%s interface verified on %s; connectivity not measured (RX %d %s, TX %d %s)\n",
		id, kindLabel, record.Desired.Encapsulation, interfaceName, rxPackets, counterUnit, txPackets, counterUnit)
	return 0
}

func readStatusInspectionError(ctx context.Context, stdout, stderr io.Writer, jsonOutput bool, observed error) int {
	if stlerr.Public(observed).ReasonCode == "kernel_module_not_loaded" && ctx.Err() == nil {
		public := stlerr.New(stlerr.CodeInspect, "link_status", "", "",
			"required kernel module is available on disk but not loaded; Link state was not verified")
		public.ReasonCode = "kernel_module_not_loaded"
		public.NextStep = "Check installed kernel module and host policy; load only with authorization, then retry status."
		return readCommandPublicError(stdout, stderr, jsonOutput, public)
	}
	if ctx.Err() != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "live diagnostic inspection was interrupted")
	}
	return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_status", "live diagnostic state could not be verified")
}
