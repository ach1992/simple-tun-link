package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Render only the useful copy payload for interactive, non-secret pairing.
// Canonical export remains the sole formatter and source for Setup Link data;
// the complete noninteractive CLI output and versioned JSON are unchanged.
func menuSharePlainLink(id domain.LinkID, out, errOut io.Writer, options *runtimeOptions) int {
	var encoded bytes.Buffer
	if code := linkExportCommand([]string{"export", string(id), "--json"}, &encoded, errOut, options); code != 0 {
		return code
	}
	var exported SetupLinkExport
	if err := json.Unmarshal(encoded.Bytes(), &exported); err != nil ||
		exported.LinkID != id || exported.Sensitive || exported.HasCredential ||
		exported.SetupLink == "" {
		fmt.Fprintln(errOut, "Cannot validate the saved plaintext Setup Link. Nothing was shared.")
		return 1
	}
	menuSection(out, "Copy / complete Setup Link")
	menuNotice(out, "WARNING", "GRE/IPIP is unencrypted. Do not include private credentials.")
	fmt.Fprintln(out, "\n"+exported.SetupLink)
	fmt.Fprintln(out, "\nOTHER server: Import setup link -> GRE/IPIP -> paste -> review -> YES.")
	fmt.Fprintln(out, "The same link can be shown again later from My tunnels -> Share.")
	return 0
}
