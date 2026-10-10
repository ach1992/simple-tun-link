package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type retireFirewallInspector interface {
	HasOwnedInbound(context.Context, domain.LinkID, bool) (bool, error)
}

type wireGuardRetirementGuard struct {
	runner   linux.Runner
	firewall retireFirewallInspector
}

// VerifyUnused refuses to retire a protected credential if ANY surviving
// matching interface name, STL owner alias, live WireGuard public identity,
// or Link-owned firewall entry is present. All observations are public-only.
// A failed/unavailable probe refuses retirement rather than treating it as
// evidence of absence. Engine holds the canonical Link lock throughout.
func (g wireGuardRetirementGuard) VerifyUnused(ctx context.Context, id domain.LinkID, expectedPublic string) error {
	if g.runner == nil || g.firewall == nil {
		return fmt.Errorf("host retirement inspection unavailable")
	}
	name, err := wgbackend.InterfaceName(id)
	if err != nil {
		return err
	}
	alias, err := linux.OwnerTag(id)
	if err != nil {
		return err
	}
	rows, err := g.runner.Run(ctx, "ip", "-details", "-json", "link", "show")
	if err != nil {
		return fmt.Errorf("cannot inspect live network interface ownership")
	}
	trimmed := bytes.TrimSpace(rows.Stdout)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return fmt.Errorf("invalid interface identity inspection")
	}
	var items []map[string]json.RawMessage
	if err = json.Unmarshal(trimmed, &items); err != nil || items == nil {
		return fmt.Errorf("cannot decode interface identities")
	}
	for _, item := range items {
		var liveName, liveAlias string
		if len(item) == 0 || json.Unmarshal(item["ifname"], &liveName) != nil || liveName == "" {
			return fmt.Errorf("incomplete interface observation")
		}
		if field, ok := item["ifalias"]; ok && json.Unmarshal(field, &liveAlias) != nil {
			return fmt.Errorf("invalid interface alias observation")
		}
		if liveName == name || liveAlias == alias {
			return fmt.Errorf("WireGuard Link interface or STL owner alias remains live")
		}
	}
	peers, err := g.runner.Run(ctx, "wg", "show", "all", "public-key")
	if err != nil {
		return fmt.Errorf("cannot inspect public WireGuard identities")
	}
	for _, line := range strings.Split(string(peers.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("invalid global WireGuard public-key observation")
		}
		if fields[0] == name || fields[1] == expectedPublic {
			return fmt.Errorf("WireGuard identity is still configured on a live interface")
		}
	}
	fw, err := g.firewall.HasOwnedInbound(ctx, id, false)
	if err != nil {
		return fmt.Errorf("cannot establish absence of owned firewall rule")
	}
	if fw {
		return fmt.Errorf("owned firewall rule remains active")
	}
	return nil
}

type wireGuardCredentialRetireResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	LinkID        domain.LinkID `json:"link_id"`
	Retired       bool          `json:"retired"`
}

func canonicalWireGuardPublicConfirmation(value string) bool {
	if len(value) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		return false
	}
	for _, b := range raw {
		if b != 0 {
			return true
		}
	}
	return false
}

// Explicit, separately confirmed retirement: normal Link Remove never
// deletes credential material needed for a possible rollback. The operator
// must supply the expected public identity recorded before removing Link.
func linkCredentialCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := slices.Contains(args, "--json")
	if !((len(args) == 7 || (len(args) == 8 && args[7] == "--json")) &&
		args[0] == "credential" && args[1] == "retire" && args[3] == "--confirm" && args[5] == "--public-key" && args[2] == args[4]) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "credential_retire",
			"usage: stl link credential retire <link-id> --confirm <link-id> --public-key <local-public-key> [--json]")
	}
	id := domain.LinkID(args[2])
	expected := args[6]
	if id.Validate() != nil || !canonicalWireGuardPublicConfirmation(expected) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "credential_retire", "invalid Link ID or local WireGuard public-key confirmation")
	}
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "credential_retire", "cannot initialize local credential runtime")
		}
	}
	runtime, err := buildRuntimeEngine(*opts)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "credential_retire", "cannot initialize Engine")
	}
	keys, err := wgbackend.NewKeyStore(opts.stateRoot)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "credential_retire", "cannot initialize protected KeyStore")
	}
	runner := opts.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	guard := wireGuardRetirementGuard{runner: runner, firewall: linux.IPTablesFirewall{Runner: runner}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	retired, err := runtime.RetireWireGuardCredential(ctx, id, expected, keys, guard)
	if err != nil {
		return lifecycleFailure(out, errOut, isJSON, stlerr.CodeOf(err), "credential_retire", nil,
			"credential retirement not confirmed; Link state, live interfaces, firewall and protected key must be reconciled")
	}
	if isJSON {
		if err = json.NewEncoder(out).Encode(wireGuardCredentialRetireResponse{SchemaVersion: jsonSchemaVersion, Operation: "credential_retire", LinkID: id, Retired: retired}); err != nil {
			fmt.Fprintln(errOut, "credential retirement outcome may be completed but result could not be written")
			return 1
		}
	} else if retired {
		fmt.Fprintf(out, "Protected WireGuard credential for %s retired after committed-state and live-host absence checks.\n", id)
	} else {
		fmt.Fprintf(out, "No protected credential remains for %s; committed and live-host absence verified.\n", id)
	}
	return 0
}
