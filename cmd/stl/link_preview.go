package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// ImportPreviewResponse is a safe CLI projection of the canonical recipient-
// oriented pairing Preview. It deliberately omits arbitrary display names,
// the setup URL and every secret-bearing or future backend-specific field.
// CLI schema version and pairing-wire schema version are distinct contracts.
type ImportPreviewResponse struct {
	SchemaVersion        int                    `json:"schema_version"`
	PairingSchemaVersion int                    `json:"pairing_schema_version"`
	Mode                 pairing.ExchangeMode   `json:"mode"`
	LinkID               domain.LinkID          `json:"link_id"`
	Backend              domain.Backend         `json:"backend"`
	Encapsulation        domain.Encapsulation   `json:"encapsulation"`
	LocalUnderlay        string                 `json:"local_underlay"`
	PeerUnderlay         string                 `json:"peer_underlay"`
	LocalAddress         string                 `json:"local_address"`
	PeerAddress          string                 `json:"peer_address"`
	HasCredential        bool                   `json:"has_credential"`
	CredentialKind       pairing.CredentialKind `json:"credential_kind,omitempty"`
	Sensitive            bool                   `json:"sensitive"`
	ImportConfirmation   string                 `json:"import_confirmation,omitempty"`
	GRE                  *domain.GREOptions     `json:"gre,omitempty"`
}

func linkPreviewCommand(args []string, input io.Reader, stdout, stderr io.Writer) int {
	jsonOutput := slices.Contains(args, "--json")
	valid := len(args) >= 2 && len(args) <= 3 && args[0] == "preview" && args[1] == "--stdin" &&
		(len(args) == 2 || args[2] == "--json")
	if !valid || input == nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_preview", "usage: stl link preview --stdin [--json]")
	}
	encoded, err := readSetupLink(input)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_preview", "setup-link input is unavailable or exceeds the size limit")
	}
	preview, err := pairing.PreviewSetupLink(encoded)
	if err != nil {
		// Do not include raw setup strings, credential bytes, decode cause,
		// or arbitrary user-provided input in human or machine errors.
		code := stlerr.CodeOf(err)
		if code != stlerr.CodeUnsupported {
			code = stlerr.CodeInvalid
		}
		return readCommandError(stdout, stderr, jsonOutput, code, "link_preview", "setup link is invalid or unsupported")
	}
	link := preview.Link
	response := ImportPreviewResponse{
		SchemaVersion: jsonSchemaVersion, PairingSchemaVersion: preview.SchemaVersion,
		Mode: preview.Mode, LinkID: link.ID, Backend: link.Backend,
		Encapsulation: link.Encapsulation,
		LocalUnderlay: link.Underlay.Local.String(), PeerUnderlay: link.Underlay.Peer.String(),
		LocalAddress: link.Addresses.Local.String(), PeerAddress: link.Addresses.Peer.String(),
		HasCredential: preview.HasCredential, CredentialKind: preview.Credential,
		Sensitive: preview.Sensitive,
	}
	// GRE knobs such as the UDP receive port and key are not credentials.
	// Without their preview a recipient cannot recognize what would be
	// configured for FOU/GUE or distinguish keyed from unkeyed GRE.
	if link.Backend == domain.BackendGRE && link.GRE != (domain.GREOptions{}) {
		gre := link.GRE
		response.GRE = &gre
	}
	if importablePlaintextOffer(preview) {
		response.ImportConfirmation = setupLinkConfirmation(encoded)
	}
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			fmt.Fprintln(stderr, "cannot encode pairing import preview")
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "STL import preview (not applied) — pairing v%d, mode %s\n", response.PairingSchemaVersion, response.Mode)
	fmt.Fprintf(stdout, "Link %s: %s/%s\n", response.LinkID, response.Backend, response.Encapsulation)
	fmt.Fprintf(stdout, "Receiver underlay %s; peer underlay %s\n", response.LocalUnderlay, response.PeerUnderlay)
	fmt.Fprintf(stdout, "Receiver Link Address %s; peer Link Address %s\n", response.LocalAddress, response.PeerAddress)
	if response.GRE != nil {
		o := response.GRE
		fmt.Fprintf(stdout, "GRE options: key_enabled=%t key=%d udp_port=%d ttl=%d tos=%d disable_pmtud=%t checksum=%t sequence=%t\n",
			o.KeyEnabled, o.Key, o.UDPPort, o.TTL, o.TOS, o.DisablePMTUD, o.Checksum, o.Sequence)
	}
	if response.HasCredential {
		fmt.Fprintf(stdout, "Recipient credential %s: PRESENT / REDACTED (SENSITIVE)\n", response.CredentialKind)
	} else {
		fmt.Fprintln(stdout, "Recipient credential: none")
	}
	if response.ImportConfirmation != "" {
		fmt.Fprintln(stdout, "After reviewing these receiver settings, apply this exact setup link with:")
		fmt.Fprintf(stdout, "stl link import --stdin --confirm %s (same stdin data)\n", response.ImportConfirmation)
	} else {
		fmt.Fprintln(stdout, "Recipient import/apply is not available for this backend or credential-bearing payload.")
	}
	fmt.Fprintln(stdout, "No Link was applied during preview.")
	return 0
}
