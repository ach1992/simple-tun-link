package quicguard

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// GuardObservationStatus describes read-only evidence in ONE network namespace.
// Neither status proves who created a table; even an exact matching name,
// nonce, byte layout and object handles can come from a different actor.
type GuardObservationStatus string

const (
	GuardNotVisible           GuardObservationStatus = "not_visible_in_observed_namespace"
	GuardMatchingShapeUnowned GuardObservationStatus = "matching_shape_ownership_unverified"
)

// OriginalGuardObservation is a CURRENT read-only inspection of an unresolved
// QUIC journal's expected nft guard. It is NOT a durable original-creation
// receipt, proof of absence in other namespaces, permission to clear State,
// or authority to adopt, delete, replace or reactivate any host resource.
// Handles can be recycled even within the same kernel boot.
type OriginalGuardObservation struct {
	LinkID       domain.LinkID
	Table        string
	ListenPort   uint16
	KernelBootID string
	NetworkNS    string
	Status       GuardObservationStatus
	Handles      linux.WGIngressLiveHandles
}

// InspectPendingOriginal inspects only the original unresolved QUIC journal
// under the canonical Engine admission locks. Production reads the actual
// current kernel and nft; no caller-provided Runner or boot ID is accepted.
// A stale/missing receipt, ambiguous kernel source, changed net namespace,
// incomplete nft inventory or missing protected materials always fails closed.
// Read-only observation never consumes/updates the journal or starts a helper.
func InspectPendingOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID) (OriginalGuardObservation, error) {
	return inspectPendingOriginal(ctx, engine, id, linux.ExecRunner{},
		hostidentity.CurrentKernelBootID, currentNetworkNamespace)
}

// Package-private test seam: production observation has fixed host sources.
func inspectPendingOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID,
	runner linux.BoundedRunner, bootID func() (string, error), networkNS func() (string, error)) (OriginalGuardObservation, error) {
	if ctx == nil || engine == nil || runner == nil || bootID == nil || networkNS == nil {
		return OriginalGuardObservation{}, fmt.Errorf("original QUIC observation requires a canonical Engine and fixed host readers")
	}
	var observation OriginalGuardObservation
	err := engine.WithQUICCrashIngressAdmission(ctx, id,
		func(c context.Context, link domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
			plan, err := linux.NewQUICWGIngressPlan(link, wg.ListenPort, nonce)
			if err != nil || wg.Validate() != nil || wg.PeerPort == 0 {
				return fmt.Errorf("original QUIC journal guard identity invalid")
			}
			firstBoot, err := bootID()
			if err != nil || !hostidentity.ValidBootID(firstBoot) {
				return fmt.Errorf("original QUIC observation kernel boot identity unverified")
			}
			firstNS, err := networkNS()
			if err != nil || !validNetworkNamespaceID(firstNS) {
				return fmt.Errorf("original QUIC observation namespace unverified")
			}
			present, handles, err := linux.ReadWGIngressGuardHandles(c, runner, plan)
			if err != nil {
				return fmt.Errorf("original QUIC nft observation unavailable or incomplete")
			}
			secondBoot, bootErr := bootID()
			secondNS, nsErr := networkNS()
			if bootErr != nil || nsErr != nil || firstBoot != secondBoot || firstNS != secondNS || c.Err() != nil {
				return fmt.Errorf("original QUIC host observation changed during inspection")
			}
			status := GuardNotVisible
			if present {
				status = GuardMatchingShapeUnowned
			}
			observation = OriginalGuardObservation{
				LinkID: link, Table: plan.TableName(), ListenPort: wg.ListenPort,
				KernelBootID: firstBoot, NetworkNS: firstNS,
				Status: status, Handles: handles,
			}
			return nil
		})
	if err != nil {
		return OriginalGuardObservation{}, err
	}
	return observation, nil
}

// A namespace inode is useful as a scope LABEL, not as a cryptographic or
// permanent host-identity proof. The kernel issues net:[decimal-inode].
func validNetworkNamespaceID(value string) bool {
	if !strings.HasPrefix(value, "net:[") || !strings.HasSuffix(value, "]") {
		return false
	}
	value = strings.TrimSuffix(strings.TrimPrefix(value, "net:["), "]")
	if len(value) == 0 || len(value) > 20 || value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == value
}

func currentNetworkNamespace() (string, error) {
	id, err := os.Readlink("/proc/self/ns/net")
	if err != nil || !validNetworkNamespaceID(id) {
		return "", fmt.Errorf("current network namespace unverified")
	}
	return id, nil
}
