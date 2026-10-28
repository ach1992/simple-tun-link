package app

import (
	"context"
	"reflect"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// InspectQUICCrashMaterials is a read-only, source-only trust check for an
// existing durable QUIC pre-effect journal. It derives the exact public
// Hysteria Plan, protected State root, and executable path from the journal,
// NOT from caller-supplied replacements. Under maintenance -> Link ->
// resource locks it inspects the actual no-follow, role-private credentials,
// regenerated helper config and officially pinned executable, then compares
// every returned public identity against the immutable journal.
//
// A clean observation does NOT bind the executable's future process lifetime,
// prove foreign host/kernel ownership or peer trust, unblock the journal,
// stage files, start a helper or authorize any backend effect. A future
// effectful transaction must reattest at the actual operation boundary.
func (e *Engine) InspectQUICCrashMaterials(ctx context.Context, id domain.LinkID) error {
	return e.inspectQUICCrashMaterials(ctx, id, quic.InspectHelperConfig)
}

// The sole injection is a test-only read-only inspection seam. The exported
// Engine entry point always uses QUIC's actual pinned-file verifier.
func (e *Engine) inspectQUICCrashMaterials(ctx context.Context, id domain.LinkID,
	inspect func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error)) error {
	const action = "quic_inspect_crash_materials"
	invalid := func(detail string) error {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic", detail)
	}
	unavailable := func(detail string) error {
		return stlerr.New(stlerr.CodeState, action, string(id), "quic", detail)
	}
	conflict := func(detail string) error {
		return stlerr.New(stlerr.CodeConflict, action, string(id), "quic", detail)
	}
	if e == nil || ctx == nil || inspect == nil || id.Validate() != nil {
		return invalid("canonical Engine, valid Link ID and material inspector are required")
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
	latest, present := fresh.FindQUICCrashOperation(id)
	if !present || !reflect.DeepEqual(latest, op) {
		return conflict("QUIC journal changed while acquiring its resource locks")
	}
	// Rebuild exactly the source Plan already validated by the Hysteria
	// renderer. The durable projection must round-trip without any invented
	// role, TLS SAN, local port or remote destination.
	local := op.Plan.Local
	plan := quic.Plan{
		LinkID: id, Role: quic.Role(local.Role),
		Underlay: op.Plan.Physical, TLSName: op.Plan.TLSName,
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
		return unavailable("QUIC material inspection interrupted")
	}
	identity, err := inspect(root, plan, local.LocalWGUDPPort, op.ExecutablePath)
	if err != nil || ctx.Err() != nil {
		// Never include underlying filesystem/certificate errors: they can
		// contain sensitive file paths or credential-bearing diagnostics.
		return unavailable("protected QUIC credentials, helper config or pinned executable are not verifiably present")
	}
	if identity.Credentials.CertificateSHA256 != op.CertificateSHA256 ||
		identity.Credentials.TrustCASHA256 != op.TrustCASHA256 ||
		identity.Credentials.AuthorizationSHA256 != op.AuthorizationSHA256 ||
		identity.ConfigSHA256 != op.HelperConfigSHA256 ||
		identity.Executable.SHA256 != op.ExecutableSHA256 ||
		identity.Executable.Device != op.ExecutableDevice ||
		identity.Executable.Inode != op.ExecutableInode {
		return conflict("protected QUIC material differs from the immutable pre-effect journal")
	}
	return nil
}
