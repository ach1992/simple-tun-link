package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type wssCredentialRetirement struct {
	root  string
	host  wss.Host
	keys  *wgbackend.KeyStore
	guard wireGuardRetirementGuard
}

// This callback is called ONLY by the canonical Engine with its Link and
// maintenance locks, an exact durable post-Remove receipt and absent desired
// Link. It does not inspect or delete arbitrary host files.
func (r wssCredentialRetirement) CaptureIdentity(_ context.Context, link domain.Link) (state.WSSFileIdentity, error) {
	return wss.CaptureFileIdentity(r.root, link)
}
func (r wssCredentialRetirement) RetireAfterRemove(ctx context.Context, link domain.Link, files state.WSSFileIdentity) error {
	if r.keys == nil || link.Backend != domain.BackendWireGuardWSS || link.ID.Validate() != nil {
		return fmt.Errorf("WSS credential retirement runtime not trusted")
	}
	if err := r.guard.VerifyUnused(ctx, link.ID, link.WireGuard.LocalPublicKey); err != nil {
		return fmt.Errorf("kernel WireGuard or firewall resources may remain: %w", err)
	}
	nft, err := r.host.GuardPresent(ctx, link)
	if err != nil {
		return fmt.Errorf("cannot inspect scoped WSS nft guard: %w", err)
	}
	if nft {
		return fmt.Errorf("WSS nft guard remains live; refusing credential deletion")
	}
	sidecar, err := r.host.HelperLoaded(ctx, link)
	if err != nil {
		return fmt.Errorf("cannot inspect WSS helper: %w", err)
	}
	if sidecar {
		return fmt.Errorf("WSS helper unit remains loaded; refusing credential deletion")
	}
	if err := wss.RetireOwnedTLS(r.root, link, files); err != nil {
		return err
	}
	if _, err := r.keys.RetireExact(link.ID, link.WireGuard.LocalPublicKey); err != nil {
		return err
	}
	return nil
}

// VerifyAbsent is intentionally non-mutating. Historical retirement proof
// must not permit deletion of a subsequently reappeared private identity.
func (r wssCredentialRetirement) VerifyAbsent(ctx context.Context, link domain.Link) error {
	if err := r.guard.VerifyUnused(ctx, link.ID, link.WireGuard.LocalPublicKey); err != nil {
		return err
	}
	guard, err := r.host.GuardPresent(ctx, link)
	if err != nil || guard {
		return fmt.Errorf("retired WSS nft guard is live or unverified")
	}
	service, err := r.host.HelperLoaded(ctx, link)
	if err != nil || service {
		return fmt.Errorf("retired WSS helper is live or unverified")
	}
	absent, err := wss.TLSAbsent(r.root, link)
	if err != nil || !absent {
		return fmt.Errorf("retired WSS mTLS/bearer material reappeared or is unverified")
	}
	_, err = r.keys.LocalPublicIdentity(link.ID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("retired WSS private WG identity reappeared or is unverified")
}

func linkWSSRetireCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := len(args) == 4 && args[3] == "--json"
	if !((len(args) == 3 || isJSON) && args[1] == "--confirm" && args[0] == args[2]) {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "wss_retire",
			"usage: stl link retire-wss <link-id> --confirm <link-id> [--json]")
	}
	id := domain.LinkID(args[0])
	if id.Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "wss_retire", "invalid WSS Link ID")
	}
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "wss_retire", "runtime unavailable")
		}
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "wss_retire", "Engine unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := engine.RetireWSSCredential(ctx, id); err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeOf(err), "wss_retire",
			"WSS secret deletion not confirmed; reconcile removed Link receipt, host resources and protected files")
	}
	if isJSON {
		_ = json.NewEncoder(out).Encode(struct {
			SchemaVersion int           `json:"schema_version"`
			LinkID        domain.LinkID `json:"link_id"`
			Retired       bool          `json:"retired"`
		}{1, id, true})
	} else {
		fmt.Fprintf(out, "WSS mTLS, authorization and WireGuard credentials for Link %s confirmed retired after durable host/State absence checks.\n", id)
	}
	return 0
}
