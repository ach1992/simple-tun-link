package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type Locker interface {
	Acquire(context.Context, []domain.ResourceClaim) (func() error, error)
}

// MaintenanceGuard is held across an entire canonical Engine mutation. Shared
// acquisitions coexist; installer-held exclusive acquisitions block mutations.
type MaintenanceGuard interface {
	Acquire(context.Context) (func() error, error)
}

// MTUManager must apply a Link's endpoint-local managed MTU only under the
// canonical Engine locks and return a guarded rollback for every mutation.
// observedBefore identifies a pre-existing interface in the final locked
// backend observation and prevents new-link orphan adoption.
type MTUManager interface {
	Apply(context.Context, backend.Request, bool, []domain.ResourceClaim) (backend.Rollback, bool, error)
}

type Engine struct {
	mtuManager         MTUManager
	maintenance        MaintenanceGuard
	backends           *backend.Registry
	store              state.Store
	locks              Locker
	restorePersistence RestorePersistence
	restoreExecutable  string
	restoreModules     func(context.Context, domain.Link) error
	ipsecRetirement    interface {
		RetireMatching(domain.LinkID, string) error
	}
}

type Result struct {
	LinkID  domain.LinkID
	Changed bool
	Removed bool

	// Tracks whether this Engine invocation called backend Apply or host
	// restore persistence. Internal-only, never part of CLI JSON.
	hostMutationAttempted bool
}

func New(backends *backend.Registry, store state.Store, locks Locker) (*Engine, error) {
	if backends == nil || store == nil || locks == nil {
		return nil, fmt.Errorf("backends, store, and locks are required")
	}
	e := &Engine{backends: backends, store: store, locks: locks}
	if impl, exists := backends.Get(domain.BackendIPsec); exists {
		// An operational IPsec backend can be used only inside this Engine's
		// canonical mutation/journal authority, not by a parallel CLI writer.
		if admitted, ok := impl.(interface {
			SetPhaseJournal(func(context.Context, ipsec.Profile, string, string) error)
		}); ok {
			admitted.SetPhaseJournal(e.advanceIPsecVICIPhase)
		}
		if operational, ok := impl.(interface {
			SetRemoveJournal(func(context.Context, ipsec.Profile) (ipsec.RemovalCheckpoint, error), func(context.Context, ipsec.Profile, string, string) error)
		}); ok {
			operational.SetRemoveJournal(e.ipsecRemovalCheckpoint, e.advanceIPsecRemovePhase)
		}
		if operational, ok := impl.(interface {
			SetDeviceJournal(func(context.Context, ipsec.Profile, string, string, int) error)
		}); ok {
			operational.SetDeviceJournal(e.advanceIPsecXFRMPhase)
		}
	}
	return e, nil
}

// SetMTUManager configures the single Engine-owned MTU writer before any
// concurrent Link operation. Without it, a managed request fails closed.
func (e *Engine) SetMTUManager(manager MTUManager) {
	e.mtuManager = manager
}

// SetRestoreModuleBootstrap wires a typed module restorer for committed Links.
// It runs ONLY under RestoreAll's maintenance and refreshed per-Link locks,
// never while browsing a menu or creating/removing Links.
func (e *Engine) SetRestoreModuleBootstrap(fn func(context.Context, domain.Link) error) {
	e.restoreModules = fn
}

// SetIPsecRetirementStore installs the local, protected credential backend for
// post-Remove receipt-bound deletion, independent of running strongSwan.
// Configure only during Engine assembly, before concurrent operations.
func (e *Engine) SetIPsecRetirementStore(store interface {
	RetireMatching(domain.LinkID, string) error
}) {
	e.ipsecRetirement = store
}

// SetMaintenanceGuard enables the shared install/Engine exclusion for managed
// production runtimes without changing the test-only injected Engine seams.
func (e *Engine) SetMaintenanceGuard(g MaintenanceGuard) {
	e.maintenance = g
}

func (e *Engine) acquireMaintenance(ctx context.Context) (func() error, error) {
	if e.maintenance == nil {
		return func() error { return nil }, nil
	}
	return e.maintenance.Acquire(ctx)
}

func (e *Engine) Ensure(ctx context.Context, desired domain.Link) (Result, error) {
	return e.ensureWithPolicy(ctx, desired, false)
}

// EnsureImported allows a confirmed pairing import to create a new Link ID
// or re-ensure exactly its committed desired state. Unlike ordinary Ensure,
// it must never reconfigure an existing Link, even if the backend is the same.
// The check happens under the canonical per-Link lock, not in the CLI, so a
// concurrent writer cannot invalidate an earlier state preflight.
func (e *Engine) EnsureImported(ctx context.Context, desired domain.Link) (Result, error) {
	return e.ensureWithPolicy(ctx, desired, true)
}

// RecipientCredentialStore is a protected, retry-safe per-Link provisioner.
// This remains an Engine transaction extension, not a pairing-specific
// independent lifecycle or a public WireGuard secret stored in domain.Link.
type RecipientCredentialStore interface {
	EnsureRecipient(domain.LinkID, []byte, string) error
}

// EnsureImportedRecipient protects a confirmed v3 WireGuard credential under
// the SAME canonical maintenance/Link locks used by all Engine mutations.
// A failed host apply may leave a protected uncommitted key for exact-credential
// retry/reconciliation; such a key must never be blindly removed.
func (e *Engine) EnsureImportedRecipient(ctx context.Context, desired domain.Link, credential []byte, store RecipientCredentialStore) (Result, error) {
	return e.EnsureWithWireGuardCredential(ctx, desired, credential, store)
}

// EnsureWithWireGuardCredential provisions an endpoint's OWN private key and
// ensures the matching public WireGuard Link under the canonical maintenance,
// Link and resource locks. Both sender creation and receiver import use this
// single transaction; secrets never enter ordinary Link desired state.
func (e *Engine) EnsureWithWireGuardCredential(ctx context.Context, desired domain.Link, credential []byte, store RecipientCredentialStore) (Result, error) {
	if store == nil || desired.Backend != domain.BackendWireGuard ||
		desired.WireGuard == (domain.WireGuardOptions{}) ||
		desired.WireGuard.ListenPort == 0 || desired.WireGuard.PeerPort == 0 {
		return Result{}, stlerr.WithEvidence(
			stlerr.New(stlerr.CodeUnsupported, "ensure_imported", string(desired.ID), string(desired.Backend),
				"protected WireGuard recipient import requires configured v3 pairing"),
			stlerr.OperationEvidence{Stage: "preflight", HostMutation: "not_attempted",
				DesiredState: "no_commit_attempted", Rollback: "not_required"})
	}
	return e.ensureWithProvision(ctx, desired, true, func() error {
		return store.EnsureRecipient(desired.ID, credential, desired.WireGuard.LocalPublicKey)
	})
}

// EnsureWithWSSCredential stages the WireGuard key and the endpoint-local mTLS
// material under the exact same canonical Engine maintenance and Link locks
// that govern the subsequent WSS kernel/firewall/sidecar transition.
func (e *Engine) EnsureWithWSSCredential(ctx context.Context, desired domain.Link,
	credential []byte, store RecipientCredentialStore, stageTLS func() error) (Result, error) {
	if desired.Backend != domain.BackendWireGuardWSS || store == nil || stageTLS == nil ||
		desired.WireGuard.ListenPort == 0 || desired.WireGuard.PeerPort == 0 {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "wss_credential", string(desired.ID),
			string(desired.Backend), "WSS requires protected WireGuard and mTLS provisioning")
	}
	return e.ensureWithProvision(ctx, desired, true, func() error {
		if err := store.EnsureRecipient(desired.ID, credential, desired.WireGuard.LocalPublicKey); err != nil {
			return err
		}
		return stageTLS()
	})
}

func (e *Engine) ensureWithPolicy(ctx context.Context, desired domain.Link, rejectReconfiguration bool) (Result, error) {
	return e.ensureWithProvision(ctx, desired, rejectReconfiguration, nil)
}

func (e *Engine) ensureWithProvision(ctx context.Context, desired domain.Link, rejectReconfiguration bool, provision func() error) (out Result, operationErr error) {
	defer func() {
		if operationErr != nil && stlerr.EvidenceOf(operationErr) == nil {
			operationErr = stlerr.WithEvidence(operationErr, stlerr.OperationEvidence{
				Stage: "preflight", HostMutation: "not_attempted",
				DesiredState: "no_commit_attempted", Rollback: "not_required",
			})
		}
	}()
	if err := desired.Validate(); err != nil {
		return Result{}, contextualize(err, stlerr.CodeInvalid, "ensure", desired, "invalid desired Link")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "ensure", string(desired.ID), "", "maintenance gate unavailable; no mutation attempted", err)
	}
	defer release()
	return e.executeEnsure(ctx, desired, rejectReconfiguration, provision)
}

// RemoveIfUnchanged is the interactive preview-confirmed variant of Remove.
// The expected desired Link is checked *after* acquiring the same per-Link lock
// as Ensure and ordinary Remove, so a concurrent reconfiguration cannot slip
// between the confirmation check and destructive backend work. This is an
// internal Engine operation, not a new machine CLI/API contract.
func (e *Engine) RemoveIfUnchanged(ctx context.Context, expected domain.Link) (Result, error) {
	return e.remove(ctx, expected.ID, &expected, false)
}

func (e *Engine) Remove(ctx context.Context, id domain.LinkID) (Result, error) {
	return e.remove(ctx, id, nil, false)
}

func (e *Engine) remove(ctx context.Context, id domain.LinkID, expected *domain.Link, reconcileIPsec bool) (out Result, operationErr error) {
	defer func() {
		if operationErr != nil && stlerr.EvidenceOf(operationErr) == nil {
			operationErr = stlerr.WithEvidence(operationErr, stlerr.OperationEvidence{
				Stage: "preflight", HostMutation: "not_attempted",
				DesiredState: "no_commit_attempted", Rollback: "not_required",
			})
		}
	}()
	if err := id.Validate(); err != nil {
		return Result{}, contextualize(err, stlerr.CodeInvalid, "remove", domain.Link{ID: id}, "invalid Link ID")
	}

	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "remove", string(id), "", "maintenance gate unavailable; no mutation attempted", err)
	}
	defer maintenanceRelease()

	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "remove", string(id), "", "cannot lock Link", err)
	}
	defer linkRelease()

	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "remove", string(id), "", "cannot load local state", err)
	}
	record, ok := snapshot.Find(id)
	if !ok {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "remove", string(id), "", "Link is not present in local state")
	}
	if expected != nil && record.Desired != *expected {
		return Result{}, stlerr.New(stlerr.CodeConflict, "remove", string(id), "",
			"saved Link changed since confirmed preview; no removal was attempted")
	}
	prior := record.Desired
	if prior.Backend == domain.BackendIPsec {
		_, pending := snapshot.FindIPsecRemoveOperation(id)
		if pending && !reconcileIPsec {
			return Result{}, stlerr.New(stlerr.CodeConflict, "remove", string(id), "ipsec",
				"interrupted IPsec Remove is journaled; use link reconcile-ipsec with exact confirmation")
		}
		if !pending && reconcileIPsec {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_reconcile_remove", string(id), "ipsec",
				"no interrupted committed IPsec Remove transaction exists")
		}
	} else if reconcileIPsec {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "ipsec_reconcile_remove", string(id), "ipsec", "not an IPsec Link")
	}
	result, err := e.executeLocked(ctx, backend.Request{Operation: backend.OperationRemove, Prior: &prior,
		Link: record.Desired, IPsecRemoveRecovery: reconcileIPsec}, record, "")
	if err != nil {
		return result, err
	}
	// The Link-specific receipt must NOT be created during an indeterminate
	// publication, backend rollback or unsuccessful restore-unit cleanup.
	// Only a successful, durable canonical Remove reaches this point.
	if prior.Backend == domain.BackendWireGuard {
		if err := e.store.Update(ctx, func(snapshot *state.Snapshot) error {
			if _, exists := snapshot.Find(id); exists {
				return fmt.Errorf("Link reappeared before verified removal receipt")
			}
			if _, pending := snapshot.FindPendingSender(id); pending {
				return fmt.Errorf("sender pending transaction survived committed Remove")
			}
			old, exists := snapshot.FindRemovalReceipt(id)
			if exists && (old.Backend != domain.BackendWireGuard || old.LocalPublicKey != prior.WireGuard.LocalPublicKey || old.Retired) {
				return fmt.Errorf("conflicting credential removal receipt")
			}
			if !exists {
				snapshot.RemovalReceipts = append(snapshot.RemovalReceipts, state.RemovalReceipt{
					LinkID: id, Backend: domain.BackendWireGuard, LocalPublicKey: prior.WireGuard.LocalPublicKey})
			}
			return nil
		}); err != nil {
			// Receipt publication itself only touches desired state. Do not
			// mistake its failure for a host mutation or forget an earlier
			// backend Apply / restore persistence mutation.
			hostMutation := "not_attempted"
			if result.hostMutationAttempted {
				hostMutation = "attempted"
			}
			return result, stlerr.WithEvidence(
				stlerr.Wrap(stlerr.CodeState, "remove", string(id), string(prior.Backend),
					"Link removed, but durable credential retirement receipt could not be confirmed; preserve key", err),
				stlerr.OperationEvidence{Stage: "credential_retirement", HostMutation: hostMutation,
					DesiredState: "committed", Rollback: "not_attempted"})
		}
	}
	if prior.Backend == domain.BackendIPsec {
		if err := e.retireIPsecCredentialLocked(ctx, id); err != nil {
			hostMutation := "not_attempted"
			if result.hostMutationAttempted {
				hostMutation = "attempted"
			}
			return result, stlerr.WithEvidence(
				stlerr.Wrap(stlerr.CodeState, "remove", string(id), "ipsec",
					"IPsec Link is removed but protected credential retirement is unconfirmed; use exact receipt-bound retry", err),
				stlerr.OperationEvidence{Stage: "credential_retirement", HostMutation: hostMutation,
					DesiredState: "committed", Rollback: "not_attempted"})
		}
	}
	return result, nil
}

func (e *Engine) executeEnsure(ctx context.Context, desired domain.Link, rejectReconfiguration bool, provision func() error) (out Result, operationErr error) {
	defer func() {
		if operationErr != nil && stlerr.EvidenceOf(operationErr) == nil {
			operationErr = stlerr.WithEvidence(operationErr, stlerr.OperationEvidence{
				Stage: "preflight", HostMutation: "not_attempted",
				DesiredState: "no_commit_attempted", Rollback: "not_required",
			})
		}
	}()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(desired.ID)})
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "ensure", string(desired.ID), string(desired.Backend), "cannot lock Link", err)
	}
	defer linkRelease()

	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "ensure", string(desired.ID), string(desired.Backend), "cannot load local state", err)
	}
	if _, pending := snapshot.FindPendingSender(desired.ID); pending {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(desired.ID), string(desired.Backend),
			"Link has reserved WireGuard sender intent; use exact-hand-off Resume instead")
	}
	if _, pending := snapshot.FindPendingIPsec(desired.ID); pending {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(desired.ID), string(desired.Backend),
			"IPsec credential is staged for this Link; activate only after ownership-verified backend support")
	}
	if _, receipt := snapshot.FindIPsecRemovalReceipt(desired.ID); receipt {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(desired.ID), string(desired.Backend),
			"prior IPsec retirement receipt reserves this Link ID; create a fresh identity")
	}
	record, exists := snapshot.Find(desired.ID)
	// Preserve a previously managed local MTU when older automation or a
	// legacy Quick Link omits the new field. Only an explicitly versioned
	// unmanaged policy may disable it. This decision happens UNDER the Link
	// lock, so it cannot override a concurrent explicit MTU update.
	if exists && desired.MTU == (domain.MTUPolicy{}) {
		desired.MTU = record.Desired.MTU
	}
	if exists && rejectReconfiguration && record.Desired != desired {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ensure_imported", string(desired.ID),
			string(desired.Backend), "existing Link ID has different desired state; explicit reconfiguration is required")
	}
	if exists && record.Desired.Backend != desired.Backend {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "ensure", string(desired.ID), string(desired.Backend), "changing backend for an existing Link is not supported by this lifecycle yet")
	}
	// Do not persist an imported credential when the requested backend is
	// unavailable. Credential activation remains inside the Engine Link lock.
	if _, registered := e.backends.Get(desired.Backend); !registered {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "ensure_imported", string(desired.ID), string(desired.Backend), "requested backend is not registered")
	}
	// Invalidate historical removal authority BEFORE a new attempt (even
	// one which later fails apply) can stage a key or host resources. An
	// old receipt must never authorize deleting an active retry's key.
	if _, receipt := snapshot.FindRemovalReceipt(desired.ID); receipt {
		if err := e.store.Update(ctx, func(fresh *state.Snapshot) error {
			if _, pending := fresh.FindPendingSender(desired.ID); pending {
				return fmt.Errorf("pending sender holds Link identity")
			}
			fresh.DeleteRemovalReceipt(desired.ID)
			return nil
		}); err != nil {
			return Result{}, stlerr.Wrap(stlerr.CodeState, "ensure", string(desired.ID), string(desired.Backend),
				"cannot invalidate previous credential removal receipt", err)
		}
	}
	if provision != nil {
		// This callback can persist a protected local key even if it
		// subsequently fails or Engine network Apply never runs.
		if err := provision(); err != nil {
			return Result{}, stlerr.WithEvidence(
				stlerr.Wrap(stlerr.CodeState, "ensure_imported", string(desired.ID), string(desired.Backend),
					"protected recipient credential cannot be provisioned; no network mutation attempted", err),
				stlerr.OperationEvidence{Stage: "credential_provision", HostMutation: "not_attempted",
					DesiredState: "no_commit_attempted", Rollback: "not_required", CredentialProvision: "attempted"})
		}
	}
	var prior *domain.Link
	if exists {
		previous := record.Desired
		prior = &previous
	}
	result, err := e.executeLocked(ctx, backend.Request{Operation: backend.OperationEnsure, Prior: prior, Link: desired}, record, "")
	if err != nil && provision != nil {
		if observed := stlerr.EvidenceOf(err); observed != nil {
			observed.CredentialProvision = "attempted"
			err = stlerr.WithEvidence(err, *observed)
		}
	}
	return result, err
}

// senderDigest is nonempty only for a Create/Resume whose precise handoff
// SHA-256 is authorized by the durable per-Link pending-sender transaction.
func (e *Engine) executeLocked(ctx context.Context, request backend.Request, prior state.LinkRecord, senderDigest string) (Result, error) {
	return e.executeLockedWithIPsec(ctx, request, prior, senderDigest, false)
}

func (e *Engine) executeLockedWithIPsec(ctx context.Context, request backend.Request, prior state.LinkRecord, senderDigest string, activateIPsec bool) (result Result, err error) {
	// Stage evidence is derived from this Engine execution, never error text.
	// "attempted" does not assert which resources were actually changed.
	evidence := stlerr.OperationEvidence{
		Stage: "inspect", HostMutation: "not_attempted",
		DesiredState: "no_commit_attempted", Rollback: "not_required",
	}
	defer func() {
		if err != nil && stlerr.EvidenceOf(err) == nil {
			err = stlerr.WithEvidence(err, evidence)
		}
	}()
	request.OwnedResources = append([]domain.ResourceClaim(nil), prior.OwnedResources...)
	link := request.Link
	impl, ok := e.backends.Get(link.Backend)
	if !ok {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, string(request.Operation), string(link.ID), string(link.Backend), "backend is not registered")
	}

	observed, err := impl.Inspect(ctx, link)
	if err != nil {
		return Result{}, contextualize(err, stlerr.CodeInspect, string(request.Operation), link, "backend inspection failed")
	}
	evidence.Stage = "plan"
	plan, err := impl.Plan(ctx, request, observed)
	if err != nil {
		return Result{}, contextualize(err, stlerr.CodePlan, string(request.Operation), link, "backend planning failed")
	}
	if plan == nil {
		return Result{}, stlerr.New(stlerr.CodeInternal, string(request.Operation), string(link.ID), string(link.Backend), "backend returned a nil plan")
	}

	resources, err := validatedClaims(plan.Resources())
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodePlan, string(request.Operation), string(link.ID), string(link.Backend), "backend plan contains an invalid resource claim", err)
	}
	lockClaims, err := resourceLockClaims(prior.OwnedResources, resources)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot derive resource locks", err)
	}
	resourceRelease, err := e.locks.Acquire(ctx, lockClaims)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot lock Link resources", err)
	}
	defer resourceRelease()

	// Resource locks can wait behind another Link operation. Refresh observed and
	// persisted state after acquiring them so stale plans cannot silently claim a
	// resource that was committed while this operation waited.
	observed, err = impl.Inspect(ctx, link)
	if err != nil {
		return Result{}, contextualize(err, stlerr.CodeInspect, string(request.Operation), link, "backend re-inspection failed")
	}
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot reload local state", err)
	}
	if link.Backend == domain.BackendIPsec {
		if _, previousXFRM := fresh.FindIPsecXFRMOperation(link.ID); previousXFRM {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_xfrm_reconcile", string(link.ID), "ipsec",
				"unfinished XFRM creation requires explicit reconcile-xfrm-ipsec")
		}
		if _, removal := fresh.FindIPsecRemoveOperation(link.ID); removal {
			if request.Operation != backend.OperationRemove || !request.IPsecRemoveRecovery {
				return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_remove", string(link.ID), "ipsec",
					"interrupted IPsec Remove requires explicit journal reconciliation")
			}
		} else if request.IPsecRemoveRecovery {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_remove", string(link.ID), "ipsec",
				"durable IPsec Remove authorization vanished")
		}
		if _, priorTransaction := fresh.FindIPsecReapplyOperation(link.ID); priorTransaction {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_reconcile", string(link.ID), "ipsec",
				"earlier IPsec reapply journal requires owner-verified reconciliation; no host Apply")
		}
	}
	if request.Operation == backend.OperationEnsure {
		if staged, exists := fresh.FindPendingIPsec(link.ID); exists {
			if !activateIPsec || link.Backend != domain.BackendIPsec || staged.Link != link {
				return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(link.ID), string(link.Backend), "IPsec credential intent reserves Link identity")
			}
		} else if activateIPsec {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_activate", string(link.ID), "ipsec", "exact protected pending intent missing")
		}
		if activateIPsec {
			if _, exists := fresh.FindIPsecVICIOperation(link.ID); exists {
				return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_activate", string(link.ID), "ipsec", "prior IPsec daemon transaction needs explicit reconciliation")
			}
		}
		if err := rejectResourceConflicts(fresh, link.ID, resources); err != nil {
			return Result{}, err
		}
		if entry, pending := fresh.FindPendingSender(link.ID); pending {
			if senderDigest == "" || entry.Link != link || entry.HandoffSHA256 != senderDigest {
				return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(link.ID), string(link.Backend),
					"another sender transaction reserves this Link identity")
			}
		} else if senderDigest != "" {
			// A committed exact desired Link is sufficient after an earlier
			// successful commit consumed the pending record atomically.
			committed, exists := fresh.Find(link.ID)
			if !exists || committed.Desired != link {
				return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(link.ID), string(link.Backend),
					"missing exact pending sender intent")
			}
		}
		if _, removed := fresh.FindRemovalReceipt(link.ID); removed {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ensure", string(link.ID), string(link.Backend),
				"previous removal authorization was not invalidated")
		}
	}
	// The final observed inventory (after resource locks) is authoritative
	// for refusing to adopt an interface with no committed Link identity.
	mtuObservedBefore := false
	if request.Operation == backend.OperationEnsure {
		for _, claim := range observed.ObservedResources() {
			if claim.Kind == domain.ResourceInterface {
				mtuObservedBefore = true
				break
			}
		}
	}
	evidence.Stage = "validate"
	if err := impl.Validate(ctx, request, observed, plan); err != nil {
		return Result{}, contextualize(err, stlerr.CodeValidate, string(request.Operation), link, "backend validation failed")
	}

	ipsecRetirementDigest := ""
	if request.Operation == backend.OperationRemove && link.Backend == domain.BackendIPsec {
		fingerprint, ok := impl.(interface {
			CredentialDigest(domain.LinkID) (string, error)
		})
		if !ok {
			return Result{}, stlerr.New(stlerr.CodeUnsupported, "ipsec_remove", string(link.ID), "ipsec",
				"IPsec backend lacks protected credential retirement binding")
		}
		digest, err := fingerprint.CredentialDigest(link.ID)
		if err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_remove", string(link.ID), "ipsec",
				"protected IPsec rollback/retirement credential cannot be verified")
		}
		ipsecRetirementDigest = digest
	}
	changed := !plan.Empty()
	if activateIPsec {
		if !changed {
			return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_activate", string(link.ID), "ipsec", "staged IPsec activation has no vacant resources to create")
		}
		// Prepare a durable *public* journal BEFORE any VICI or kernel write.
		// This is not itself an ownership permit; Validate above must pass
		// the dedicated runtime-admission and observed-vacancy gate.
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_activate", string(link.ID), "ipsec", "cannot create private transaction nonce")
		}
		if err := e.store.Update(ctx, func(s *state.Snapshot) error {
			pending, ok := s.FindPendingIPsec(link.ID)
			if !ok || pending.Link != link {
				return fmt.Errorf("IPsec pending activation identity changed")
			}
			if _, exists := s.FindIPsecVICIOperation(link.ID); exists {
				return fmt.Errorf("previous IPsec journal exists")
			}
			if _, exists := s.Find(link.ID); exists {
				return fmt.Errorf("IPsec activation Link already committed")
			}
			s.IPsecVICIOperations = append(s.IPsecVICIOperations,
				state.IPsecVICIOperation{Intent: pending, Nonce: hex.EncodeToString(nonce[:]), Phase: state.IPsecVICIPrepared})
			return nil
		}); err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_activate", string(link.ID), "ipsec", "IPsec activation journal could not be durably prepared; no backend Apply invoked")
		}
	}
	reapplyIPsec := link.Backend == domain.BackendIPsec && request.Operation == backend.OperationEnsure &&
		!activateIPsec && changed
	requiresVICILoad := false
	if reapplyIPsec {
		if specialized, ok := plan.(interface{ NeedsIPsecVICILoad() bool }); !ok {
			return Result{}, stlerr.New(stlerr.CodeUnsupported, "ipsec_reapply", string(link.ID), "ipsec",
				"IPsec reapply plan lacks durable VICI mutation description")
		} else {
			requiresVICILoad = specialized.NeedsIPsecVICILoad()
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_reapply", string(link.ID), "ipsec", "cannot allocate IPsec reapply nonce")
		}
		// Reserve a durable committed-Link recovery identity BEFORE any
		// XFRM/VICI write. Unexpected interruption blocks future Ensure/
		// Remove/Connect, not silently adopt or reload same-name objects.
		if err := e.store.Update(ctx, func(s *state.Snapshot) error {
			current, exists := s.Find(link.ID)
			if !exists || current.Desired != link || len(s.IPsecReapplyOperations) > 4096 {
				return fmt.Errorf("IPsec committed Link identity changed")
			}
			if _, prev := s.FindIPsecReapplyOperation(link.ID); prev {
				return fmt.Errorf("IPsec reapply transaction already in progress")
			}
			if _, pending := s.FindPendingIPsec(link.ID); pending {
				return fmt.Errorf("IPsec Link not exclusively committed")
			}
			s.IPsecReapplyOperations = append(s.IPsecReapplyOperations, state.IPsecReapplyOperation{
				Intent: link, Nonce: hex.EncodeToString(nonce[:]), Phase: state.IPsecVICIPrepared})
			return nil
		}); err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_reapply", string(link.ID), "ipsec",
				"cannot durably prepare recovery transaction; no backend Apply")
		}
	}
	// Persist a per-Link XFRM creation journal before invoking the kernel.
	// The device's original ifindex is later fsynced while still unaliased.
	requiresIPsecDevice := false
	if link.Backend == domain.BackendIPsec && request.Operation == backend.OperationEnsure {
		if currentPlan, ok := plan.(interface{ NeedsIPsecXFRMCreate() bool }); ok {
			requiresIPsecDevice = currentPlan.NeedsIPsecXFRMCreate()
		}
	}
	if requiresIPsecDevice {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_xfrm", string(link.ID), "ipsec",
				"cannot allocate durable XFRM creation identity")
		}
		if err := e.store.Update(ctx, func(s *state.Snapshot) error {
			if _, exists := s.FindIPsecXFRMOperation(link.ID); exists {
				return fmt.Errorf("earlier XFRM creation is not reconciled")
			}
			if pending, exists := s.FindPendingIPsec(link.ID); exists {
				vici, ready := s.FindIPsecVICIOperation(link.ID)
				if pending.Link != link || !ready || vici.Phase != state.IPsecVICIPrepared {
					return fmt.Errorf("new XFRM device lacks protected pending transaction")
				}
			} else {
				committed, hasLink := s.Find(link.ID)
				vici, ready := s.FindIPsecReapplyOperation(link.ID)
				if !hasLink || committed.Desired != link || !ready ||
					vici.Intent != link || vici.Phase != state.IPsecVICIPrepared {
					return fmt.Errorf("restored XFRM device lacks committed owner journal")
				}
			}
			s.IPsecXFRMOperations = append(s.IPsecXFRMOperations, state.IPsecXFRMOperation{
				Intent: link, Nonce: hex.EncodeToString(nonce[:]), Phase: state.IPsecXFRMPrepared})
			return nil
		}); err != nil {
			return Result{}, stlerr.New(stlerr.CodeState, "ipsec_xfrm", string(link.ID), "ipsec",
				"XFRM pre-effect intent not durably published; no device creation attempted")
		}
	}
	// Committed IPsec Remove must be durable BEFORE the first VICI/SA/kernel
	// teardown effect. An uncertain phase cannot be automatically replayed
	// or compensated by reloading the shared PSK.
	if request.Operation == backend.OperationRemove && link.Backend == domain.BackendIPsec {
		if _, operational := impl.(*ipsec.OperationalBackend); operational && !request.IPsecRemoveRecovery {
			profile, profileErr := ipsec.NewProfile(link)
			if profileErr != nil {
				return Result{}, stlerr.New(stlerr.CodeInvalid, "ipsec_remove", string(link.ID), "ipsec", "invalid committed IPsec removal identity")
			}
			originalIndex := 0
			if o, ok := observed.(interface{ RemovalIfIndex() int }); ok {
				originalIndex = o.RemovalIfIndex()
			}
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return Result{}, stlerr.New(stlerr.CodeState, "ipsec_remove", string(link.ID), "ipsec",
					"cannot create protected IPsec Remove transaction identity")
			}
			if err := e.store.Update(ctx, func(s *state.Snapshot) error {
				rec, present := s.Find(link.ID)
				if !present || rec.Desired != link || !ipsecClaimsRecordedEngine(rec.OwnedResources, profile) {
					return fmt.Errorf("IPsec committed owner identity changed")
				}
				if _, collision := s.FindIPsecRemoveOperation(link.ID); collision {
					return fmt.Errorf("IPsec Remove transaction already exists")
				}
				s.IPsecRemoveOperations = append(s.IPsecRemoveOperations, state.IPsecRemoveOperation{
					Intent: link, Nonce: hex.EncodeToString(nonce[:]), Phase: state.IPsecRemovePrepared,
					IfIndex: originalIndex})
				return nil
			}); err != nil {
				return Result{}, stlerr.New(stlerr.CodeState, "ipsec_remove", string(link.ID), "ipsec",
					"cannot durably prepare IPsec Remove before host effect")
			}
		}
	}
	var undo backend.Rollback
	if changed {
		evidence.Stage = "apply"
		evidence.HostMutation = "attempted"
		evidence.Rollback = "unavailable"
		undo, err = impl.Apply(ctx, request, observed, plan)
		if err != nil {
			return Result{}, e.rollbackFailureAtStage(ctx, request, link, undo, evidence.Stage, evidence.HostMutation, contextualize(err, stlerr.CodeApply, string(request.Operation), link, "backend apply failed"))
		}
		if undo == nil {
			return Result{}, stlerr.New(stlerr.CodeInternal, string(request.Operation), string(link.ID), string(link.Backend), "backend changed state without providing rollback")
		}
	}

	// Apply managed MTU after the backend has created/marked its exact
	// interface, but before backend Verify, restore publication and desired
	// state commit. Legacy/unmanaged Links never call this host writer.
	if request.Operation == backend.OperationEnsure &&
		(link.MTU.Mode == domain.MTUAuto || link.MTU.Mode == domain.MTUManual) {
		evidence.Stage = "mtu_apply"
		if e.mtuManager == nil {
			return Result{}, e.rollbackFailureAtStage(ctx, request, link, undo, evidence.Stage, evidence.HostMutation,
				stlerr.New(stlerr.CodeUnsupported, "managed_mtu", string(link.ID), string(link.Backend), "Engine managed MTU writer is unavailable"))
		}
		mtuUndo, mtuChanged, mtuErr := e.mtuManager.Apply(ctx, request, mtuObservedBefore, resources)
		if mtuUndo != nil {
			backendUndo := undo
			undo = func(undoCtx context.Context) error {
				var errs []error
				errs = append(errs, mtuUndo(undoCtx))
				if backendUndo != nil {
					errs = append(errs, backendUndo(undoCtx))
				}
				return errors.Join(errs...)
			}
		}
		if mtuChanged {
			changed = true
			evidence.HostMutation = "attempted"
		}
		if mtuErr != nil {
			return Result{}, e.rollbackFailureAtStage(ctx, request, link, undo, evidence.Stage, evidence.HostMutation,
				stlerr.Wrap(stlerr.CodeApply, "managed_mtu", string(link.ID), string(link.Backend),
					"managed MTU could not be safely applied and verified", mtuErr))
		}
	}
	evidence.Stage = "verify"
	if _, err := impl.Verify(ctx, request); err != nil {
		return Result{}, e.rollbackFailureAtStage(ctx, request, link, undo, evidence.Stage, evidence.HostMutation, contextualize(err, stlerr.CodeVerify, string(request.Operation), link, "backend verification failed"))
	}

	// Serialize only the host-wide persistence transition and state commit.
	// Backend inspection/apply stays per-Link to preserve Multi-Link concurrency.
	var persistenceUndo func(context.Context) error
	if e.restorePersistence != nil {
		evidence.Stage = "persistence"
		persistenceRelease, lockErr := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
		if lockErr != nil {
			return Result{}, e.rollbackFailureAtStage(ctx, request, link, undo, evidence.Stage, evidence.HostMutation,
				stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot lock restore persistence", lockErr))
		}
		defer persistenceRelease()

		if request.Operation == backend.OperationEnsure {
			// Host restore-unit publication may have been attempted even if
			// no backend Apply was needed.
			evidence.HostMutation = "attempted"
			var ensureErr error
			persistenceUndo, _, ensureErr = e.restorePersistence.EnsureRestore(ctx, e.restoreExecutable)
			if ensureErr != nil {
				return Result{}, e.rollbackFailureAtStage(ctx, request, link, undo, evidence.Stage, evidence.HostMutation,
					stlerr.Wrap(stlerr.CodeState, "ensure", string(link.ID), string(link.Backend), "cannot activate restore persistence", ensureErr))
			}
		}
	}

	evidence.Stage = "state_commit"
	evidence.DesiredState = "commit_attempted"
	remaining := -1
	commitErr := e.store.Update(ctx, func(snapshot *state.Snapshot) error {
		switch request.Operation {
		case backend.OperationEnsure:
			if requiresIPsecDevice {
				device, exists := snapshot.FindIPsecXFRMOperation(link.ID)
				if !exists || device.Intent != link || device.Phase != state.IPsecXFRMConfigured ||
					!snapshot.DeleteIPsecXFRMOperation(link.ID) {
					return fmt.Errorf("IPsec XFRM original ifindex/configuration not durably verified")
				}
			}
			if reapplyIPsec {
				op, exists := snapshot.FindIPsecReapplyOperation(link.ID)
				expectedPhase := state.IPsecVICIPrepared
				if requiresVICILoad {
					expectedPhase = state.IPsecVICIConnectionSeen
				}
				if !exists || op.Intent != link || op.Phase != expectedPhase {
					return fmt.Errorf("IPsec reapply transaction is unverified or missing")
				}
				if !snapshot.DeleteIPsecReapplyOperation(link.ID) {
					return fmt.Errorf("IPsec reapply transaction cannot be committed")
				}
			}
			if activateIPsec {
				pending, exists := snapshot.FindPendingIPsec(link.ID)
				op, recorded := snapshot.FindIPsecVICIOperation(link.ID)
				if !exists || pending.Link != link || !recorded || op.Intent != pending ||
					op.Phase != state.IPsecVICIConnectionSeen {
					return fmt.Errorf("IPsec activation journal is not fully observed")
				}
				for i, item := range snapshot.IPsecVICIOperations {
					if item.Intent.Link.ID == link.ID {
						snapshot.IPsecVICIOperations = append(snapshot.IPsecVICIOperations[:i],
							snapshot.IPsecVICIOperations[i+1:]...)
						break
					}
				}
				if !snapshot.DeletePendingIPsec(link.ID) {
					return fmt.Errorf("IPsec pending intent could not be consumed")
				}
			} else if _, staged := snapshot.FindPendingIPsec(link.ID); staged {
				return fmt.Errorf("IPsec credential intent reserves Link identity")
			}
			if err := rejectResourceConflicts(*snapshot, link.ID, resources); err != nil {
				return err
			}
			if pending, exists := snapshot.FindPendingSender(link.ID); exists {
				if senderDigest == "" || pending.Link != link || pending.HandoffSHA256 != senderDigest {
					return fmt.Errorf("pending sender intent changed before commit")
				}
				snapshot.DeletePendingSender(link.ID)
			} else if senderDigest != "" {
				committed, exists := snapshot.Find(link.ID)
				if !exists || committed.Desired != link {
					return fmt.Errorf("missing exact sender transaction before commit")
				}
			}
			if _, removed := snapshot.FindRemovalReceipt(link.ID); removed {
				return fmt.Errorf("obsolete removal receipt survives ensure")
			}
			snapshot.Upsert(state.LinkRecord{Desired: link, OwnedResources: resources})
		case backend.OperationRemove:
			if _, operational := impl.(*ipsec.OperationalBackend); operational && link.Backend == domain.BackendIPsec {
				journal, present := snapshot.FindIPsecRemoveOperation(link.ID)
				if !present || journal.Intent != link || journal.Phase != state.IPsecRemoveDeviceAbsent ||
					!snapshot.DeleteIPsecRemoveOperation(link.ID) {
					return fmt.Errorf("IPsec Remove still requires durable owner-scoped reconciliation")
				}
			}
			if !snapshot.Delete(link.ID) {
				return state.ErrNotFound
			}
			if link.Backend == domain.BackendIPsec {
				if ipsecRetirementDigest == "" {
					return fmt.Errorf("missing protected IPsec retirement identity")
				}
				if _, exists := snapshot.FindIPsecRemovalReceipt(link.ID); exists {
					return fmt.Errorf("IPsec retirement authorization already exists")
				}
				// Persist the receipt in EXACTLY the same state transaction
				// that removes the committed Link, never in a best-effort
				// follow-up that can be lost across a crash.
				snapshot.IPsecRemovalReceipts = append(snapshot.IPsecRemovalReceipts,
					state.IPsecRemovalReceipt{LinkID: link.ID, PSKSHA256: ipsecRetirementDigest})
			}
		default:
			return fmt.Errorf("unsupported operation %q", request.Operation)
		}
		remaining = len(snapshot.Links)
		return nil
	})
	if commitErr != nil {
		commitPublic := contextualize(commitErr, stlerr.CodeState, string(request.Operation), link, "cannot commit local state")
		// A state update can publish state.json before its metadata/directory
		// fsync fails. Compare the visible state under the existing Link and
		// persistence locks before compensating any host changes. If there is
		// ambiguity, retain the host state and report a non-success requiring
		// reconciliation; blindly undoing a published intent is destructive.
		visible, loadErr := e.store.Load(context.WithoutCancel(ctx))
		published := loadErr == nil && stateMatchesOperation(visible, request, resources)
		oldState := loadErr == nil && stateMatchesPrior(visible, link.ID, prior)
		var publicationErr *state.PublicationError
		indeterminate := errors.As(commitErr, &publicationErr)
		if published || indeterminate || !oldState {
			evidence.DesiredState = "visible_unconfirmed"
			evidence.Rollback = "not_attempted"
			if changed || persistenceUndo != nil {
				evidence.HostMutation = "retained"
			}
			return Result{LinkID: link.ID, Changed: changed, Removed: request.Operation == backend.OperationRemove},
				stlerr.WithEvidence(stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend),
					"desired-state commit outcome is uncertain; host changes retained for reconciliation", errors.Join(commitErr, loadErr)), evidence)
		}
		evidence.DesiredState = "prior_verified"
		if e.restorePersistence != nil {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if persistenceUndo != nil {
				if rollbackErr := persistenceUndo(rollbackCtx); rollbackErr != nil {
					commitPublic = stlerr.Wrap(stlerr.CodeRollback, string(request.Operation), string(link.ID), string(link.Backend),
						"state commit failed and restore persistence rollback did not complete", errors.Join(commitPublic, rollbackErr))
				}
			}
			compensationErr := e.rollbackWithContextAtStage(rollbackCtx, request, link, undo,
				"state_commit", evidence.HostMutation, commitPublic)
			return Result{}, stlerr.WithEvidence(compensationErr,
				stlerr.OperationEvidence{Stage: "state_commit", HostMutation: evidence.HostMutation, DesiredState: "prior_verified",
					Rollback: rollbackStatus(undo, persistenceUndo != nil, compensationErr)})
		}
		failed := e.rollbackFailure(ctx, request, link, undo, commitPublic)
		return Result{}, stlerr.WithEvidence(failed,
			stlerr.OperationEvidence{Stage: "state_commit", HostMutation: evidence.HostMutation, DesiredState: "prior_verified",
				Rollback: rollbackStatus(undo, false, failed)})
	}

	// After the desired state is durably committed, owned backend rollback
	// callbacks from Apply must not be invoked by post-commit cleanup. A
	// callback was returned by the successful non-empty Apply, so reporting
	// the earlier pre-Apply "unavailable" value would misstate the outcome.
	evidence.DesiredState = "committed"
	if undo != nil {
		evidence.Rollback = "not_attempted"
	}
	// After the final desired Link is durably deleted, its owned reboot unit
	// is no longer needed. An uncertain cleanup is reported as partial failure;
	// never roll a removed Link back solely to conceal a unit cleanup error.
	evidence.Stage = "persistence_cleanup"
	if request.Operation == backend.OperationRemove && remaining == 0 && e.restorePersistence != nil {
		// The final owned unit cleanup may mutate systemd/unit files even
		// when Remove's backend Plan was a verified no-op.
		evidence.HostMutation = "attempted"
		if err := e.restorePersistence.RemoveRestore(ctx); err != nil {
			return Result{LinkID: link.ID, Changed: changed, Removed: true},
				stlerr.Wrap(stlerr.CodeState, "remove", string(link.ID), string(link.Backend),
					"Link removed, but restore persistence cleanup failed", err)
		}
	}

	return Result{
		LinkID:                link.ID,
		Changed:               changed,
		Removed:               request.Operation == backend.OperationRemove,
		hostMutationAttempted: evidence.HostMutation != "not_attempted",
	}, nil
}

// Every compensation of mutated backend resources receives its own bounded,
// cancellation-detached cleanup context, even on non-systemd hosts. The
// original cancellation/failure stays observable in the result.
func (e *Engine) rollbackFailure(ctx context.Context, request backend.Request, link domain.Link, undo backend.Rollback, original error) error {
	return e.rollbackFailureAtStage(ctx, request, link, undo, "rollback", "attempted", original)
}

func (e *Engine) rollbackFailureAtStage(ctx context.Context, request backend.Request, link domain.Link,
	undo backend.Rollback, stage, mutation string, original error) error {
	if undo == nil {
		rollback := "unavailable"
		if mutation == "not_attempted" {
			rollback = "not_required"
		}
		return stlerr.WithEvidence(original, stlerr.OperationEvidence{
			Stage: stage, HostMutation: mutation, DesiredState: "no_commit_attempted", Rollback: rollback,
		})
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return e.rollbackWithContextAtStage(rollbackCtx, request, link, undo, stage, mutation, original)
}

// The caller passes the exact Engine stage reached. Error code and prose are
// not lifecycle evidence. Reuse the shared rollback context where a unit
// compensation has already started.
func (e *Engine) rollbackWithContextAtStage(ctx context.Context, request backend.Request, link domain.Link,
	undo backend.Rollback, stage, mutation string, original error) error {
	evidence := stlerr.OperationEvidence{Stage: stage, HostMutation: mutation,
		DesiredState: "no_commit_attempted", Rollback: "unavailable"}
	if undo == nil {
		return stlerr.WithEvidence(original, evidence)
	}
	if err := undo(ctx); err != nil {
		evidence.Rollback = "incomplete"
		return stlerr.WithEvidence(stlerr.Wrap(stlerr.CodeRollback, string(request.Operation), string(link.ID), string(link.Backend),
			"operation failed and rollback did not complete", errors.Join(original, err)), evidence)
	}
	// Callback success is not a second independent kernel/state verification.
	evidence.Rollback = "completed_unverified"
	return stlerr.WithEvidence(original, evidence)
}

// rollbackStatus conservatively projects the typed result of the actual
// compensation call, without claiming independent verification.
func rollbackStatus(undo backend.Rollback, persistenceCompensated bool, operationErr error) string {
	// Persistence-unit compensation may fail even when backend Apply had
	// nothing to undo. Never hide that failure behind "not_required".
	if stlerr.CodeOf(operationErr) == stlerr.CodeRollback {
		return "incomplete"
	}
	if undo == nil && !persistenceCompensated {
		return "not_required"
	}
	// Neither successful callback alone proves full host convergence.
	return "completed_unverified"
}

// reservationClaimsForConflict includes compatibility-only reservations
// derivable from committed intent. Old GRE state lacks the shared gre/rx claim,
// but its desired tunnel still reserves that receive identity even when the
// kernel interface is absent (e.g., before recovery). Never persist or use
// these inferred claims as ownership proof for Remove or rollback.
func reservationClaimsForConflict(record state.LinkRecord) []domain.ResourceClaim {
	claims := record.OwnedResources
	if record.Desired.Backend == domain.BackendGRE {
		receive := domain.GREReceiveClaim(record.Desired.Underlay, record.Desired.GRE)
		if !slices.Contains(claims, receive) {
			claims = append(slices.Clone(claims), receive)
		}
	}
	return claims
}

func rejectResourceConflicts(snapshot state.Snapshot, id domain.LinkID, wanted []domain.ResourceClaim) error {
	for _, record := range snapshot.Links {
		if record.Desired.ID == id {
			continue
		}
		for _, wantedClaim := range wanted {
			for _, ownedClaim := range reservationClaimsForConflict(record) {
				conflict, err := domain.ResourceClaimsConflict(wantedClaim, ownedClaim)
				if err != nil {
					return stlerr.Wrap(stlerr.CodeState, "validate_resources", string(id), "", "cannot compare resource ownership", err)
				}
				if conflict {
					return stlerr.New(
						stlerr.CodeConflict,
						"validate_resources",
						string(id),
						"",
						fmt.Sprintf("resource %s conflicts with Link %s", wantedClaim.Kind, record.Desired.ID),
					)
				}
			}
		}
	}
	// Uncommitted IPsec PSK reservations are canonical public Link intents.
	// Their claims must block all other backends until an explicit, owned
	// activation/reconciliation path exists; file names alone grant no rights.
	for _, pending := range snapshot.PendingIPsec {
		if pending.Link.ID == id {
			continue
		}
		profile, err := ipsec.NewProfile(pending.Link)
		if err != nil {
			return stlerr.New(stlerr.CodeState, "validate_resources", string(id), "", "invalid reserved IPsec resource identity")
		}
		for _, wantedClaim := range wanted {
			for _, pendingClaim := range profile.ResourceClaims() {
				conflict, err := domain.ResourceClaimsConflict(wantedClaim, pendingClaim)
				if err != nil {
					return stlerr.Wrap(stlerr.CodeState, "validate_resources", string(id), "", "cannot compare reserved IPsec ownership", err)
				}
				if conflict {
					return stlerr.New(stlerr.CodeConflict, "validate_resources", string(id), "", "resource reserved by pending IPsec Link")
				}
			}
		}
	}
	// Existing WireGuard pending senders reserve their public Link Addresses
	// before any peer handoff is published, even before backend Apply.
	for _, pending := range snapshot.PendingSenders {
		if pending.Link.ID == id {
			continue
		}
		link := pending.Link
		addressClaims := []domain.ResourceClaim{
			{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
			{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
		}
		for _, wantedClaim := range wanted {
			for _, reservation := range addressClaims {
				conflict, err := domain.ResourceClaimsConflict(wantedClaim, reservation)
				if err != nil {
					return stlerr.Wrap(stlerr.CodeState, "validate_resources", string(id), "", "cannot compare reserved WireGuard addresses", err)
				}
				if conflict {
					return stlerr.New(stlerr.CodeConflict, "validate_resources", string(id), "", "Link Address reserved by pending WireGuard sender")
				}
			}
		}
	}
	return nil
}

func contextualize(err error, fallback stlerr.Code, operation string, link domain.Link, detail string) error {
	var typed *stlerr.Error
	if errors.As(err, &typed) {
		safeDetail := typed.Detail
		if safeDetail == "" {
			safeDetail = detail
		}
		wrapped := stlerr.Wrap(typed.Code, operation, string(link.ID), string(link.Backend), safeDetail, err)
		wrapped.ReasonCode, wrapped.NextStep, wrapped.Evidence = typed.ReasonCode, typed.NextStep, typed.Evidence
		return wrapped
	}
	return stlerr.Wrap(fallback, operation, string(link.ID), string(link.Backend), detail, err)
}

func linkLock(id domain.LinkID) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: "stl-link", Key: string(id)}
}

func resourceLockClaims(groups ...[]domain.ResourceClaim) ([]domain.ResourceClaim, error) {
	claims := unionClaims(groups...)
	for _, claim := range claims {
		switch claim.Kind {
		case domain.ResourceLinkAddress, domain.ResourceLinkSubnet:
			family, err := addressFamily(claim)
			if err != nil {
				return nil, err
			}
			claims = append(claims, domain.ResourceClaim{Kind: "stl-address-space", Key: family})
		}
	}
	return unionClaims(claims), nil
}

func addressFamily(claim domain.ResourceClaim) (string, error) {
	if err := claim.Validate(); err != nil {
		return "", err
	}
	var addr netip.Addr
	switch claim.Kind {
	case domain.ResourceLinkAddress:
		addr, _ = netip.ParseAddr(claim.Key)
	case domain.ResourceLinkSubnet:
		prefix, _ := netip.ParsePrefix(claim.Key)
		addr = prefix.Addr()
	default:
		return "", fmt.Errorf("resource kind %q has no address family", claim.Kind)
	}
	if addr.Is4() {
		return "ipv4", nil
	}
	return "ipv6", nil
}

func validatedClaims(claims []domain.ResourceClaim) ([]domain.ResourceClaim, error) {
	out := unionClaims(claims)
	for _, claim := range out {
		if err := claim.Validate(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(claim.Kind, "stl-") {
			return nil, fmt.Errorf("resource claim kind %q is reserved by the core engine", claim.Kind)
		}
	}
	return out, nil
}

func unionClaims(groups ...[]domain.ResourceClaim) []domain.ResourceClaim {
	set := make(map[string]domain.ResourceClaim)
	for _, claims := range groups {
		for _, claim := range claims {
			set[claim.Canonical()] = claim
		}
	}
	out := make([]domain.ResourceClaim, 0, len(set))
	for _, claim := range set {
		out = append(out, claim)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Canonical() < out[j].Canonical() })
	return out
}

// restoreLockClaim protects the host-wide unit lifecycle and desired-state
// transition without serializing the independent backend apply steps.
func restoreLockClaim() domain.ResourceClaim {
	return domain.ResourceClaim{Kind: "stl-restore-unit", Key: "host"}
}

// stateMatchesOperation proves the attempted desired-state record became
// visible; equality covers both requested intent and all owned resource claims.
func stateMatchesOperation(snapshot state.Snapshot, request backend.Request, resources []domain.ResourceClaim) bool {
	record, exists := snapshot.Find(request.Link.ID)
	if request.Operation == backend.OperationRemove {
		return !exists
	}
	return exists && record.Desired == request.Link && slices.Equal(record.OwnedResources, resources)
}

func stateMatchesPrior(snapshot state.Snapshot, id domain.LinkID, prior state.LinkRecord) bool {
	record, exists := snapshot.Find(id)
	if prior.Desired.ID == "" {
		return !exists
	}
	return exists && record.Desired == prior.Desired && slices.Equal(record.OwnedResources, prior.OwnedResources)
}
