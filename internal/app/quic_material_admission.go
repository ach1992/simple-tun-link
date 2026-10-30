package app

import (
	"context"
	"reflect"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// InspectQUICCrashMaterials is a read-only, source-only trust check for an
// existing durable QUIC pre-effect journal. It derives the exact public
// Hysteria Plan, protected State root and executable path from the journal.
// Under maintenance -> Link -> resource locks it rechecks current State and
// all seven immutable credential/config/executable identities.
//
// A clean observation does NOT bind the executable's future process lifetime,
// prove host/kernel ownership or peer trust, unblock the journal, stage files,
// start a helper or authorize any backend effect.
func (e *Engine) InspectQUICCrashMaterials(ctx context.Context, id domain.LinkID) error {
	const action = "quic_inspect_crash_materials"
	return e.withQUICCrashMaterialLocks(ctx, id, action, func(root string, plan quic.Plan,
		port uint16, op state.QUICCrashOperation) error {
		expected := quicExpectedMaterialIdentity(op)
		// Receipt and semantic credentials/config must belong to the same
		// pinned directory generation, including a final canonical path
		// and inode re-attestation before any successful read-only result.
		got, err := quic.InspectJournalGeneration(root, plan, port, op.ExecutablePath, op.Nonce, expected)
		if err != nil || ctx.Err() != nil {
			return stlerr.New(stlerr.CodeState, action, string(id), "quic",
				"protected QUIC generation ownership, material or pinned executable cannot be verified")
		}
		if got != expected {
			return stlerr.New(stlerr.CodeConflict, action, string(id), "quic",
				"QUIC material identities differ from the immutable journal")
		}
		return nil
	})
}

// Only tests supply the read-only inspector; production always verifies the
// actual protected files and officially pinned executable.
func (e *Engine) inspectQUICCrashMaterials(ctx context.Context, id domain.LinkID,
	inspect func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error)) error {
	const action = "quic_inspect_crash_materials"
	if inspect == nil {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic", "material inspector is required")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action, func(root string, plan quic.Plan,
		port uint16, op state.QUICCrashOperation) error {
		identity, err := inspect(root, plan, port, op.ExecutablePath)
		if err != nil || ctx.Err() != nil {
			// Underlying filesystem/certificate errors may carry sensitive paths.
			return stlerr.New(stlerr.CodeState, action, string(id), "quic",
				"protected QUIC credentials, helper config or pinned executable are not verifiably present")
		}
		if identity != quicExpectedMaterialIdentity(op) {
			return stlerr.New(stlerr.CodeConflict, action, string(id), "quic",
				"protected QUIC material differs from the immutable pre-effect journal")
		}
		return nil
	})
}

// StageQUICCrashMaterials is the SOURCE-ONLY canonical Engine entry point for
// journal-bound protected QUIC credential and helper-config publication.
// The complete immutable pre-effect journal must ALREADY exist. The operation
// rechecks it under canonical locks and refuses any supplied secret, Plan or
// pinned helper identity differing from the recorded seven fingerprints
// BEFORE the first protected file write. Existing no-replace 0600 staging and
// strict readback are reused without opening a second material owner.
//
// On any failure the original journal and all possible partial artifacts stay
// quarantined for future exact-owned recovery. Success does not consume the
// journal, start Hysteria, install services, create WG/nft, certify a foreign
// host owner, or enable a runnable QUIC Link.
func (e *Engine) StageQUICCrashMaterials(ctx context.Context, id domain.LinkID, bundle quic.CredentialBundle) error {
	const action = "quic_stage_crash_materials"
	return e.withQUICCrashMaterialLocks(ctx, id, action, func(root string, plan quic.Plan,
		port uint16, op state.QUICCrashOperation) error {
		expected := quicExpectedMaterialIdentity(op)
		actual, err := quic.StageJournalGeneration(ctx, root, plan, port, op.ExecutablePath,
			op.Nonce, bundle, expected)
		if err != nil || ctx.Err() != nil {
			return stlerr.New(stlerr.CodeState, action, string(id), "quic",
				"QUIC material generation staging or create-time ownership is uncertain; preserve journal and files")
		}
		if actual != expected {
			return stlerr.New(stlerr.CodeConflict, action, string(id), "quic",
				"QUIC staged material identity does not match the immutable journal")
		}
		return nil
	})
}

// Test-only seam. The public path always executes real protected and pinned
// executable admission. An injected stage cannot relax journal/lock checks.
func (e *Engine) stageQUICCrashMaterials(ctx context.Context, id domain.LinkID,
	bundle quic.CredentialBundle,
	stage func(context.Context, string, quic.Plan, uint16, string, quic.CredentialBundle, quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error)) error {
	const action = "quic_stage_crash_materials"
	if stage == nil {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic", "protected QUIC stager is required")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action, func(root string, plan quic.Plan,
		port uint16, op state.QUICCrashOperation) error {
		expected := quicExpectedMaterialIdentity(op)
		actual, err := stage(ctx, root, plan, port, op.ExecutablePath, bundle, expected)
		if err != nil || ctx.Err() != nil {
			return stlerr.New(stlerr.CodeState, action, string(id), "quic",
				"protected QUIC staging failed or is uncertain; preserve pre-effect journal and any private files")
		}
		if actual != expected {
			return stlerr.New(stlerr.CodeConflict, action, string(id), "quic",
				"staged QUIC material did not match immutable pre-effect journal")
		}
		return nil
	})
}

func quicExpectedMaterialIdentity(op state.QUICCrashOperation) quic.HelperConfigIdentity {
	return quic.HelperConfigIdentity{
		ConfigSHA256: op.HelperConfigSHA256,
		Credentials: quic.CredentialIdentity{
			CertificateSHA256:   op.CertificateSHA256,
			TrustCASHA256:       op.TrustCASHA256,
			AuthorizationSHA256: op.AuthorizationSHA256,
			ObfuscationSHA256:   op.ObfuscationSHA256,
		},
		Executable: pinnedexec.Identity{
			SHA256: op.ExecutableSHA256,
			Device: op.ExecutableDevice,
			Inode:  op.ExecutableInode,
		},
	}
}

// withQUICCrashMaterialLocks is the single Engine authority for both
// read-only attestation and protected-file staging. Both reconstruct the
// exact immutable Plan and use maintenance -> Link -> resource locks. The
// shared restore-persistence lock is unnecessary here: the already-durable,
// unresolved journal remains unchanged and continues to prevent last-owner
// restore-unit retirement. No caller is permitted to clear or replay it.
func (e *Engine) withQUICCrashMaterialLocks(ctx context.Context, id domain.LinkID, action string,
	use func(string, quic.Plan, uint16, state.QUICCrashOperation) error) error {
	invalid := func(detail string) error {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic", detail)
	}
	unavailable := func(detail string) error {
		return stlerr.New(stlerr.CodeState, action, string(id), "quic", detail)
	}
	conflict := func(detail string) error {
		return stlerr.New(stlerr.CodeConflict, action, string(id), "quic", detail)
	}
	if e == nil || ctx == nil || use == nil || id.Validate() != nil {
		return invalid("canonical Engine, valid Link ID and material operation are required")
	}
	rootProvider, ok := e.store.(interface{ RootDir() string })
	if !ok {
		return unavailable("canonical private State root is unavailable")
	}
	root := rootProvider.RootDir()
	if root == "" {
		return unavailable("canonical private State root is unavailable")
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return unavailable("maintenance gate unavailable")
	}
	defer maintenance()
	releaseLink, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return unavailable("Link lock unavailable")
	}
	defer releaseLink()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return unavailable("protected State could not be read")
	}
	op, exists := snapshot.FindQUICCrashOperation(id)
	if !exists {
		return conflict("no exact unresolved QUIC pre-effect journal exists")
	}
	if err := op.Validate(); err != nil {
		return unavailable("durable QUIC journal is not internally valid")
	}
	locks, err := resourceLockClaims(op.Resources)
	if err != nil {
		return unavailable("QUIC journal resource locks are invalid")
	}
	releaseResources, err := e.locks.Acquire(ctx, locks)
	if err != nil {
		return unavailable("QUIC journal resource locks unavailable")
	}
	defer releaseResources()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return unavailable("protected State could not be rechecked under locks")
	}
	if op.Managed != nil {
		return conflict("managed QUIC operations cannot enter source-only admission")
	}
	latest, present := fresh.FindQUICCrashOperation(id)
	if !present || !reflect.DeepEqual(latest, op) {
		return conflict("QUIC journal changed while acquiring its resource locks")
	}
	// Reconstruct the full public Hysteria topology from the durable binding,
	// never accept an alternate role, peer, TLS name, local port or binary path.
	local := op.Plan.Local
	plan := quic.Plan{
		LinkID: id, Role: quic.Role(local.Role),
		Underlay: op.Plan.Physical, TLSName: op.Plan.TLSName, Obfuscation: op.Plan.Obfuscation,
	}
	switch local.Role {
	case composition.Dial:
		plan.LocalForwardUDPPort = local.LocalHelperUDPPort
		plan.PeerWGUDPPort = local.RemoteWGUDPPort
	case composition.Listen:
		plan.LocalWGUDPPort = local.LocalWGUDPPort
	default:
		return unavailable("QUIC journal role is invalid")
	}
	roundTrip, err := plan.HostPlan(local.LocalWGUDPPort)
	if err != nil || roundTrip != op.Plan {
		return unavailable("QUIC journal cannot reconstruct the exact protected helper topology")
	}
	if ctx.Err() != nil {
		return unavailable("QUIC material operation interrupted")
	}
	return use(root, plan, local.LocalWGUDPPort, op)
}
