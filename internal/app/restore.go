package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// RestoreAll reapplies persisted desired Links through the same idempotent
// Ensure lifecycle as ordinary operations. Completed results precede a
// failure, so the CLI can report actual partial progress without concealing
// a failed reapply.
func (e *Engine) RestoreAll(ctx context.Context) ([]Result, error) {
	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "maintenance gate unavailable; no restore attempted", err)
	}
	defer maintenanceRelease()

	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot load persisted Links", err)
	}

	// A crash journal is NOT a committed, healthy Link, and an empty
	// desired-State snapshot with pending effects is not proof that the
	// host can be cleaned up or ordinary restore safely replayed.
	if len(snapshot.WSSCrashOperations) > 0 && len(snapshot.Links) == 0 {
		return nil, stlerr.New(stlerr.CodeConflict, "restore_all", "", "wireguard-wss",
			"unresolved WSS pre-effect transaction prevents empty-State restore-unit cleanup")
	}
	if len(snapshot.Links) == 0 && e.restorePersistence != nil {
		// Recheck under the same narrowly scoped lock used by every desired
		// state/persistence transition. A missing file or mount is not proof
		// that an existing reboot unit should be removed.
		release, lockErr := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
		if lockErr != nil {
			return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot lock restore persistence", lockErr)
		}
		fresh, reconcileErr := e.store.Load(ctx)
		if reconcileErr == nil && len(fresh.Links) == 0 {
			committed := false
			if witness, ok := e.store.(interface {
				HasCommittedState(context.Context) (bool, error)
			}); ok {
				committed, reconcileErr = witness.HasCommittedState(ctx)
			}
			if reconcileErr == nil {
				if committed {
					// A durable empty snapshot permits removing only STL's
					// owned unit (also retries failed last-owner cleanup).
					reconcileErr = e.restorePersistence.RemoveRestore(ctx)
				} else {
					var installed bool
					installed, reconcileErr = e.restorePersistence.IsRestoreInstalled(ctx)
					if reconcileErr == nil && installed {
						reconcileErr = stlerr.New(stlerr.CodeState, "restore_all", "", "", "restore unit exists but persisted desired state is missing")
					}
				}
			}
		}
		releaseErr := release()
		if reconcileErr != nil {
			if typed, ok := reconcileErr.(*stlerr.Error); ok {
				return nil, typed
			}
			return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot reconcile restore persistence", reconcileErr)
		}
		if releaseErr != nil {
			return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot release restore persistence lock", releaseErr)
		}
		snapshot = fresh
	}

	results := make([]Result, 0, len(snapshot.Links))
	var perLinkFailures []error
	for _, record := range snapshot.Links {
		if record.WSSSupersededBy != "" {
			// A superseded original is retained as protected State, not as a
			// desired active service. This applies even after a trusted new
			// kernel generation or a manual cold-boot witness.
			continue
		}
		if _, unresolved := snapshot.FindWSSCrashOperation(record.Desired.ID); unresolved {
			perLinkFailures = append(perLinkFailures, stlerr.New(stlerr.CodeConflict,
				"restore", string(record.Desired.ID), "wireguard-wss",
				"committed WSS Link has unfinished pre-effect operation"))
			continue
		}
		if err := ctx.Err(); err != nil {
			return results, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "restore canceled or timed out", errors.Join(err, errors.Join(perLinkFailures...)))
		}
		result, present, err := e.restorePersisted(ctx, record.Desired.ID)
		if err != nil {
			failure := contextualize(err, stlerr.CodeApply, "restore", record.Desired, "cannot restore persisted Link")
			// A failed backend is independent when rollback completed and the
			// shared state/lock system remains trustworthy. A shared-state,
			// unknown, or incomplete-rollback failure stops the batch.
			if ctx.Err() != nil || !canContinueRestore(failure) {
				return results, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "restore halted after a shared or unrecoverable failure", errors.Join(errors.Join(perLinkFailures...), failure))
			}
			perLinkFailures = append(perLinkFailures, failure)
			continue
		}
		if present {
			results = append(results, result)
		}
	}
	if len(perLinkFailures) != 0 {
		code := stlerr.CodeUnsupported
		for _, failure := range perLinkFailures {
			if stlerr.CodeOf(failure) != stlerr.CodeUnsupported {
				code = stlerr.CodeApply
				break
			}
		}
		return results, stlerr.Wrap(code, "restore_all", "", "",
			fmt.Sprintf("%d independent Link(s) could not be restored", len(perLinkFailures)), errors.Join(perLinkFailures...))
	}
	return results, nil
}

// restorePersisted holds the per-Link lock while refreshing committed intent.
// Unlike Ensure(userInput), it never replays stale intent captured before a
// concurrent Remove or update. It calls the same normal executeLocked engine.
func (e *Engine) restorePersisted(ctx context.Context, id domain.LinkID) (Result, bool, error) {
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return Result{}, false, stlerr.Wrap(stlerr.CodeState, "restore", string(id), "", "cannot lock persisted Link", err)
	}
	defer release()

	fresh, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, false, stlerr.Wrap(stlerr.CodeState, "restore", string(id), "", "cannot reload persisted Link intent", err)
	}
	record, exists := fresh.Find(id)
	if exists && record.WSSSupersededBy != "" {
		return Result{}, false, nil
	}
	if !exists {
		// Remove won before restore: skip rather than resurrecting the Link.
		return Result{}, false, nil
	}
	if err := record.Desired.Validate(); err != nil {
		return Result{}, true, contextualize(err, stlerr.CodeInvalid, "restore", record.Desired, "invalid persisted Link")
	}

	if e.restoreModules != nil {
		if prepareErr := e.restoreModules(ctx, record.Desired); prepareErr != nil {
			return Result{}, true, stlerr.Wrap(stlerr.CodeUnsupported, "restore", string(id), string(record.Desired.Backend),
				"committed Link's selected kernel dependency could not be restored", prepareErr)
		}
	}
	prior := record.Desired
	result, err := e.executeLocked(ctx, backend.Request{Operation: backend.OperationEnsure, Prior: &prior, Link: record.Desired}, record, "")
	if err != nil || record.Desired.Backend != domain.BackendIPsec {
		return result, true, err
	}
	// Native strongSwan starts with empty IKE/CHILD SAs after a host reboot.
	// Canonical Ensure restores a committed owned XFRM device and private VICI
	// profile, but does NOT initiate an IKE exchange (start_action=none).
	// Only previously committed IPsec Links may reconnect, and only after
	// exact refreshed owner claims, locks and live SA inventory are verified.
	if err := e.reconnectRestoredIPsecLocked(ctx, record.Desired); err != nil {
		return result, true, err
	}
	return result, true, nil
}

// reconnectRestoredIPsecLocked runs under RestoreAll's maintenance lease and
// per-Link lock. It never creates a Link, accepts pending Quick Link staging,
// bypasses Engine transactions or adopts a daemon. Resource locks and
// immutable committed ownership are re-checked before VICI initiation.
func (e *Engine) reconnectRestoredIPsecLocked(ctx context.Context, desired domain.Link) error {
	first, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_restore_connect", string(desired.ID), "ipsec", "committed Link state unavailable after restore")
	}
	record, found := first.Find(desired.ID)
	if !found || record.Desired != desired || len(record.OwnedResources) == 0 {
		return stlerr.New(stlerr.CodeConflict, "ipsec_restore_connect", string(desired.ID), "ipsec", "exact committed IPsec owner missing after restore")
	}
	claims, err := resourceLockClaims(record.OwnedResources)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_restore_connect", string(desired.ID), "ipsec", "committed IPsec resource locks invalid")
	}
	release, err := e.locks.Acquire(ctx, claims)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_restore_connect", string(desired.ID), "ipsec", "cannot lock restored IPsec resources")
	}
	defer release()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_restore_connect", string(desired.ID), "ipsec", "cannot recheck committed IPsec state")
	}
	exact, present := fresh.Find(desired.ID)
	if !present || exact.Desired != record.Desired ||
		!slices.EqualFunc(exact.OwnedResources, record.OwnedResources,
			func(a, b domain.ResourceClaim) bool { return a.Canonical() == b.Canonical() }) {
		return stlerr.New(stlerr.CodeConflict, "ipsec_restore_connect", string(desired.ID), "ipsec", "committed IPsec resources changed before reconnection")
	}
	if _, pending := fresh.FindPendingIPsec(desired.ID); pending {
		return stlerr.New(stlerr.CodeConflict, "ipsec_restore_connect", string(desired.ID), "ipsec", "staged IPsec credential cannot automatically connect")
	}
	if _, pending := fresh.FindIPsecReapplyOperation(desired.ID); pending {
		return stlerr.New(stlerr.CodeConflict, "ipsec_restore_connect", string(desired.ID), "ipsec", "unreconciled IPsec reapply forbids reconnection")
	}
	if _, pending := fresh.FindIPsecVICIOperation(desired.ID); pending {
		return stlerr.New(stlerr.CodeConflict, "ipsec_restore_connect", string(desired.ID), "ipsec", "unreconciled IPsec VICI transaction forbids reconnection")
	}
	impl, ok := e.backends.Get(domain.BackendIPsec)
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "ipsec_restore_connect", string(desired.ID), "ipsec", "IPsec runtime unavailable after restore")
	}
	inspector, ok := impl.(interface {
		DiagnosticState(context.Context, domain.Link) (ipsec.DiagnosticState, error)
	})
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "ipsec_restore_connect", string(desired.ID), "ipsec", "IPsec SA verification unavailable")
	}
	observed, err := inspector.DiagnosticState(ctx, exact.Desired)
	if err != nil || !observed.ConnectionConfigured || observed.IfIndex <= 0 {
		return stlerr.New(stlerr.CodeInspect, "ipsec_restore_connect", string(desired.ID), "ipsec", "restored IPsec device or SA inventory unverified")
	}
	if observed.SecurityAssociationPresent {
		// Manual restore of an already-healthy Link does not start extra IKE.
		return nil
	}
	connect, ok := impl.(interface {
		Connect(context.Context, domain.Link, []domain.ResourceClaim) error
	})
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "ipsec_restore_connect", string(desired.ID), "ipsec", "IPsec scoped connection initiation unavailable")
	}
	if err := connect.Connect(ctx, exact.Desired, exact.OwnedResources); err != nil {
		// Local Ensure committed successfully. This scoped initiation cannot
		// prove traffic: report a Link-local verification failure so independent
		// siblings still restore. Never retry an indeterminate IKE attempt or
		// expose raw peer/PSK/VICI diagnostics.
		return stlerr.New(stlerr.CodeVerify, "ipsec_restore_connect", string(desired.ID), "ipsec", "restored IPsec configuration is committed but automatic IKE initiation failed or is indeterminate; inspect live SA")
	}
	return nil
}

func canContinueRestore(err error) bool {
	switch stlerr.CodeOf(err) {
	case stlerr.CodeUnsupported, stlerr.CodeInvalid, stlerr.CodeConflict,
		stlerr.CodeInspect, stlerr.CodePlan, stlerr.CodeValidate,
		stlerr.CodeVerify:
		return true
	default:
		return false
	}
}
