package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// setupLinkConfirmation identifies the exact reviewed plaintext setup URL.
// It is an operator confirmation token, NOT a signature, MAC or proof of
// the sender's identity/trustworthiness.
func setupLinkConfirmation(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return fmt.Sprintf("%x", sum)
}

func importablePlaintextOffer(preview pairing.Preview) bool {
	if preview.Mode != pairing.ModeQuick || preview.HasCredential || preview.Sensitive {
		return false
	}
	return preview.Link.Backend == domain.BackendGRE || preview.Link.Backend == domain.BackendIPIP
}

// linkImportCommand requires a preview-derived token for the EXACT setup link
// before the canonical Engine is even assembled. Credentialed Quick Links
// fail closed until the relevant backend has protected recipient storage;
// silently applying a Link while dropping its credential is forbidden.
func linkImportCommand(args []string, input io.Reader, stdout, stderr io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	valid := (len(args) == 4 || (len(args) == 5 && args[4] == "--json")) &&
		args[0] == "import" && args[1] == "--stdin" && args[2] == "--confirm" &&
		len(args[3]) == 64 && !strings.ContainsAny(args[3], " \t\r\n")
	if !valid || input == nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_import",
			"usage: stl link import --stdin --confirm <preview-token> [--json]")
	}
	encoded, err := readSetupLink(input)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_import",
			"setup-link input is unavailable or exceeds the size limit")
	}
	offer, err := pairing.DecodeSetupLink(encoded)
	if err != nil {
		code := stlerr.CodeInvalid
		if stlerr.CodeOf(err) == stlerr.CodeUnsupported {
			code = stlerr.CodeUnsupported
		}
		return readCommandError(stdout, stderr, jsonOutput, code, "link_import",
			"setup link is invalid or unsupported")
	}
	if !importablePlaintextOffer(offer.Preview()) {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_import",
			"credential-bearing and non-GRE/IPIP pairing import require a protected backend-specific importer")
	}
	expected := setupLinkConfirmation(encoded)
	if subtle.ConstantTimeCompare([]byte(args[3]), []byte(expected)) != 1 {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_import",
			"setup link does not match the reviewed import preview confirmation")
	}
	// The Offer is initiator-oriented. Its canonical inversion is the only
	// source of receiver-oriented configuration (including GRE options).
	desired := offer.ReceiverLink()
	if err := desired.Validate(); err != nil {
		code := stlerr.CodeInvalid
		if stlerr.CodeOf(err) == stlerr.CodeUnsupported {
			code = stlerr.CodeUnsupported
		}
		return readCommandError(stdout, stderr, jsonOutput, code, "link_import",
			"receiver Link configuration is invalid or unsupported")
	}
	return executeLinkMutation("link_import", desired, desired.ID, jsonOutput, stdout, stderr, options)
}

// readSetupLink is shared by redacted preview and explicit import so their
// confirmation tokens describe exactly the same bounded stdin bytes. A
// conventional single trailing line terminator is not part of the URL.
func readSetupLink(input io.Reader) (string, error) {
	if input == nil {
		return "", fmt.Errorf("missing input")
	}
	b, err := io.ReadAll(io.LimitReader(input, pairing.MaxLinkBytes+2))
	if err != nil || len(b) == 0 || len(b) > pairing.MaxLinkBytes+1 {
		return "", fmt.Errorf("invalid setup-link input length")
	}
	encoded := strings.TrimSuffix(string(b), "\n")
	encoded = strings.TrimSuffix(encoded, "\r")
	return encoded, nil
}
