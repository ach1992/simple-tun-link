package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// RuntimeAdmission is independent of daemon/VICI/kernel vacancy checks.
// Authorize must prove a currently STL-exclusive strongSwan process, loaded
// configuration/logging, protected socket, and sole writer ownership. A
// valid Link ID, same-name VICI object or protected PSK is NOT such proof.
// The production adapter MUST fail closed if even one fact is uncertain.
type RuntimeAdmission interface {
	Authorize(context.Context) error
}

type OperationalOptions struct {
	Admission RuntimeAdmission
	Runner    BoundedCommandRunner
	Routes    HostRouteResolver
	Keys      *PSKStore
	Writer    ScopedWriter
	XFRM      XFRMVacancyInspector

	IPBinary string
	Index    func(string) (int, error)
	SetAlias func(context.Context, int, string) error
	AddAddr  func(context.Context, int, netip.Prefix) error
	SetUp    func(context.Context, int) error
	Delete   func(context.Context, int) error
}

// OperationalBackend uses canonical Engine resource locks and state commits.
// The required admission interface makes it impossible to enable this with
// only public underlay addresses or an IPsec-looking kernel interface.
type OperationalBackend struct {
	OperationalOptions
	phaseJournal func(context.Context, Profile, string, string) error
}

// SetPhaseJournal binds an Engine-owned durable phase transition to the
// backend. It must be set once at runtime assembly before concurrent calls.
func (b *OperationalBackend) SetPhaseJournal(fn func(context.Context, Profile, string, string) error) {
	b.phaseJournal = fn
}

func NewOperationalBackend(opts OperationalOptions) (*OperationalBackend, error) {
	if opts.Admission == nil || opts.Runner == nil || opts.Routes == nil || opts.Keys == nil ||
		opts.Writer.validate() != nil || opts.XFRM.Runner == nil {
		return nil, fmt.Errorf("protected IPsec backend requires admitted daemon, private keys and inspected kernel")
	}
	if opts.IPBinary == "" {
		opts.IPBinary = "ip"
	}
	if opts.Index == nil {
		opts.Index = func(name string) (int, error) {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return 0, fmt.Errorf("cannot resolve IPsec interface index")
			}
			return iface.Index, nil
		}
	}
	if opts.SetAlias == nil || opts.AddAddr == nil || opts.SetUp == nil || opts.Delete == nil {
		return nil, fmt.Errorf("IPsec requires explicit index-pinned Linux netlink operations")
	}
	return &OperationalBackend{OperationalOptions: opts}, nil
}

func (*OperationalBackend) Kind() domain.Backend { return domain.BackendIPsec }

// CredentialDigest only computes a non-secret identity of the exact
// protected 256-bit PSK. It does not authorize deletion; Engine must publish
// its durable post-Remove receipt under canonical locks first.
func (b *OperationalBackend) CredentialDigest(id domain.LinkID) (string, error) {
	if b == nil || b.Keys == nil {
		return "", fmt.Errorf("protected IPsec credential source unavailable")
	}
	return b.Keys.Digest(id)
}

// RetireCredential is called only after Engine has verified the durable
// post-Remove receipt and holds the same maintenance/Link lock. Do not
// require a running daemon for secure file retirement after host teardown.
func (b *OperationalBackend) RetireCredential(id domain.LinkID, digest string) error {
	if b == nil || b.Keys == nil {
		return fmt.Errorf("protected IPsec credential source unavailable")
	}
	return b.Keys.RetireMatching(id, digest)
}

// CheckAdmission is an observational, fail-closed prerequisite. It performs
// no connection or credential writes and cannot start a service.
func (b *OperationalBackend) CheckAdmission(ctx context.Context) error {
	if b == nil {
		return fmt.Errorf("operational IPsec runtime unavailable")
	}
	return b.authorize(ctx)
}

// DiagnosticState is deliberately public/secret-free. An installed SA does
// not prove remote packet reachability.
type DiagnosticState struct {
	Interface                  string `json:"interface"`
	IfIndex                    int    `json:"if_index"`
	XFRMID                     uint32 `json:"xfrm_id"`
	ConnectionConfigured       bool   `json:"connection_configured"`
	SecurityAssociationPresent bool   `json:"security_association_present"`
}

func (b *OperationalBackend) DiagnosticState(ctx context.Context, l domain.Link) (DiagnosticState, error) {
	state, err := b.Inspect(ctx, l)
	if err != nil {
		return DiagnosticState{}, err
	}
	o := state.(operationalObservation)
	if !o.Iface.matches(o.Profile) || !o.Connection || !o.Shared {
		return DiagnosticState{}, fmt.Errorf("IPsec observed identity or configuration is not verified")
	}
	sa, err := b.hasIPsecSA(ctx, o.Profile)
	if err != nil {
		return DiagnosticState{}, fmt.Errorf("IPsec SA inventory unavailable")
	}
	return DiagnosticState{Interface: o.Profile.InterfaceName, IfIndex: o.Iface.Index,
		XFRMID: o.Profile.InterfaceID, ConnectionConfigured: true,
		SecurityAssociationPresent: sa}, nil
}

type operationalObservation struct {
	Profile    Profile
	Iface      xfrmLink
	Connection bool
	Shared     bool
}

func (o operationalObservation) ObservedResources() []domain.ResourceClaim {
	if !o.Iface.Exists {
		return nil
	}
	return o.Profile.ResourceClaims()
}

type operationalPlan struct {
	Profile Profile
	Claims  []domain.ResourceClaim
	Create  bool
	Load    bool
	Remove  bool
}

func (p operationalPlan) Empty() bool              { return !p.Create && !p.Load && !p.Remove }
func (p operationalPlan) NeedsIPsecVICILoad() bool { return p.Load }

func (p operationalPlan) Resources() []domain.ResourceClaim {
	return append([]domain.ResourceClaim(nil), p.Claims...)
}

func (b *OperationalBackend) authorize(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("IPsec context unavailable")
	}
	if err := b.Admission.Authorize(ctx); err != nil {
		// The gate's raw error may contain sensitive process details.
		return fmt.Errorf("exclusive IPsec daemon origin, runtime logging or writer boundary is unverified")
	}
	return nil
}

func (b *OperationalBackend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	if err := b.authorize(ctx); err != nil {
		return nil, err
	}
	p, err := NewProfile(link)
	if err != nil {
		return nil, err
	}
	iface, err := b.inspectDevice(ctx, p)
	if err != nil {
		return nil, err
	}
	objects, err := b.Writer.Inspect(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("private strongSwan inventory unavailable")
	}
	return operationalObservation{Profile: p, Iface: iface, Connection: objects.ConnectionNamePresent, Shared: objects.SecretNamePresent}, nil
}

func (b *OperationalBackend) Plan(ctx context.Context, req core.Request, observed core.Observation) (core.Plan, error) {
	o, ok := observed.(operationalObservation)
	if !ok {
		return nil, fmt.Errorf("invalid IPsec observation")
	}
	if o.Profile.Link != req.Link {
		return nil, fmt.Errorf("IPsec observed Link identity changed")
	}
	if req.Prior != nil && *req.Prior != req.Link {
		return nil, fmt.Errorf("IPsec reconfiguration/rekey is not supported; use a new Link")
	}
	p := operationalPlan{Profile: o.Profile, Claims: o.Profile.ResourceClaims()}
	switch req.Operation {
	case core.OperationEnsure:
		key, err := b.Keys.Load(req.Link.ID)
		if err != nil {
			return nil, fmt.Errorf("protected IPsec credential not available or unsafe")
		}
		key.Zeroize()
		if o.Connection != o.Shared {
			return nil, fmt.Errorf("ambiguous partial VICI object set; explicit reconciliation required")
		}
		if o.Iface.Exists && !o.Iface.matches(o.Profile) {
			return nil, fmt.Errorf("existing IPsec interface is not provably owned")
		}
		if (o.Iface.Exists || o.Connection) && req.Prior == nil {
			return nil, fmt.Errorf("IPsec name occupied without a committed Link; no adoption")
		}
		if o.Connection && req.Prior != nil && !ipsecClaimsRecorded(req.OwnedResources, o.Profile) {
			return nil, fmt.Errorf("committed IPsec daemon ownership claims are incomplete")
		}
		// Disallow one-sided kernel/daemon adoption on first Ensure.
		p.Create = !o.Iface.Exists
		p.Load = !o.Connection
	case core.OperationRemove:
		// A successful Remove may require rollback of the previous
		// scoped VICI objects. Validate the protected credential BEFORE
		// terminating/unloading anything; missing/corrupt PSK is not an
		// acceptable irreversible partial-cleanup condition.
		key, loadErr := b.Keys.Load(req.Link.ID)
		if loadErr != nil {
			return nil, fmt.Errorf("cannot safely remove IPsec without its protected rollback credential")
		}
		key.Zeroize()
		if req.Prior == nil || !ipsecClaimsRecorded(req.OwnedResources, o.Profile) {
			return nil, fmt.Errorf("cannot remove IPsec resources without exact committed ownership")
		}
		if o.Iface.Exists && !o.Iface.matches(o.Profile) {
			return nil, fmt.Errorf("refusing removal of unowned IPsec interface")
		}
		if o.Connection != o.Shared {
			return nil, fmt.Errorf("partial VICI state cannot be safely removed")
		}
		p.Remove = o.Iface.Exists || o.Connection
	default:
		return nil, fmt.Errorf("unsupported IPsec operation")
	}
	return p, nil
}

func ipsecClaimsRecorded(owned []domain.ResourceClaim, p Profile) bool {
	for _, required := range p.ResourceClaims() {
		found := false
		for _, c := range owned {
			if c.Canonical() == required.Canonical() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (b *OperationalBackend) Validate(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) error {
	if err := b.authorize(ctx); err != nil {
		return err
	}
	o, ok := observed.(operationalObservation)
	p, valid := candidate.(operationalPlan)
	if !ok || !valid || p.Profile != o.Profile || p.Profile.Link != req.Link {
		return fmt.Errorf("IPsec operation plan identity invalid")
	}
	fresh, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return err
	}
	if current := fresh.(operationalObservation); current.Iface != o.Iface || current.Connection != o.Connection || current.Shared != o.Shared {
		return fmt.Errorf("IPsec kernel or VICI identity changed during operation")
	}
	if p.Create {
		if err := b.XFRM.RequireVacant(ctx, p.Profile); err != nil {
			return fmt.Errorf("IPsec XFRM identity not vacant or inventory uncertain")
		}
	}
	// Ensure must prove a concrete route/source before creating XFRM.
	// Remove must remain available when the underlay was disconnected or
	// the peer/provider disappeared; deletion is guarded by exact committed
	// resource claims, interface owner tag+ifindex and private VICI names,
	// not by continued reachability to the remote endpoint.
	if req.Operation == core.OperationEnsure {
		route, err := b.Routes.Resolve(ctx, req.Link.Underlay.Peer)
		if err != nil || route.Source != req.Link.Underlay.Local || route.Device == "" {
			return fmt.Errorf("IPsec underlay route/source could not be verified")
		}
	}
	if err := b.authorize(ctx); err != nil {
		return err
	}
	return nil
}

func (b *OperationalBackend) Apply(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) (core.Rollback, error) {
	p, ok := candidate.(operationalPlan)
	if !ok || p.Profile.Link != req.Link {
		return nil, fmt.Errorf("invalid IPsec Apply plan")
	}
	if err := b.authorize(ctx); err != nil {
		return nil, err
	}
	switch req.Operation {
	case core.OperationEnsure:
		return b.applyEnsure(ctx, p)
	case core.OperationRemove:
		return b.applyRemove(ctx, p)
	default:
		return nil, errors.New("unsupported IPsec Apply operation")
	}
}

func (b *OperationalBackend) Verify(ctx context.Context, req core.Request) (core.Observation, error) {
	current, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, err
	}
	o := current.(operationalObservation)
	switch req.Operation {
	case core.OperationEnsure:
		if !o.Iface.matches(o.Profile) || !o.Connection || !o.Shared {
			return nil, fmt.Errorf("IPsec interface or private VICI profile could not be verified")
		}
	case core.OperationRemove:
		if o.Iface.Exists || o.Connection || o.Shared {
			return nil, fmt.Errorf("removed IPsec resources still present")
		}
		if err := b.XFRM.RequireVacant(ctx, o.Profile); err != nil {
			return nil, fmt.Errorf("removed IPsec XFRM policy or SA identity could not be verified vacant")
		}
	default:
		return nil, fmt.Errorf("unsupported IPsec verify operation")
	}
	return o, nil
}

// Connect must only be reached through a canonical Engine method that has
// acquired the maintenance, Link and resource locks and rechecked persisted
// ownership. It does not replace missing credentials or implicit globals.
func (b *OperationalBackend) Connect(ctx context.Context, link domain.Link, owned []domain.ResourceClaim) error {
	if err := b.authorize(ctx); err != nil {
		return err
	}
	p, err := NewProfile(link)
	if err != nil {
		return err
	}
	if !ipsecClaimsRecorded(owned, p) {
		return fmt.Errorf("IPsec Link is not committed with exact owned claims")
	}
	o, err := b.Inspect(ctx, link)
	if err != nil {
		return err
	}
	state := o.(operationalObservation)
	if !state.Iface.matches(p) || !state.Connection || !state.Shared {
		return fmt.Errorf("IPsec connection is not configured and owned")
	}
	if err := b.authorize(ctx); err != nil {
		return err
	}
	if err := b.Writer.Initiate(ctx, p); err != nil {
		return err
	}
	return nil
}

func (b *OperationalBackend) applyEnsure(ctx context.Context, p operationalPlan) (core.Rollback, error) {
	profile := p.Profile
	progress := ipsecProgress{}
	undo := func(undoCtx context.Context) error {
		return b.rollbackCreation(undoCtx, profile, progress)
	}
	if p.Create {
		var err error
		progress, err = b.createDevice(ctx, profile)
		if err != nil {
			return undo, err
		}
	}
	if p.Load {
		// A previously started transaction is not replayable merely because
		// the daemon names now appear vacant. Every potentially sensitive
		// effect has an adjacent durable, Engine-owned issuing phase.
		if err := b.authorize(ctx); err != nil {
			return undo, err
		}
		before, err := b.Writer.Inspect(ctx, profile)
		if err != nil || before.ConnectionNamePresent || before.SecretNamePresent {
			return undo, fmt.Errorf("scoped VICI occupancy changed; refusing replacement")
		}
		key, err := b.Keys.Load(profile.Link.ID)
		if err != nil {
			return undo, fmt.Errorf("protected IPsec PSK unavailable")
		}
		defer key.Zeroize()
		if b.phaseJournal == nil {
			return nil, fmt.Errorf("IPsec Engine phase journal unavailable")
		}
		if err = b.phaseJournal(ctx, profile, "prepared", "issuing-shared"); err != nil {
			return nil, fmt.Errorf("cannot durably prepare IPsec shared credential load")
		}
		if err = b.Writer.LoadShared(ctx, profile, &key); err != nil {
			return nil, fmt.Errorf("IPsec key load uncertain; preserve resources for reconciliation")
		}
		progress.Shared = true
		if err = b.phaseJournal(ctx, profile, "issuing-shared", "shared-observed"); err != nil {
			return nil, fmt.Errorf("cannot durably observe IPsec shared credential")
		}
		if err = b.phaseJournal(ctx, profile, "shared-observed", "issuing-connection"); err != nil {
			return nil, fmt.Errorf("cannot durably prepare IPsec connection load")
		}
		if err = b.Writer.LoadConnection(ctx, profile); err != nil {
			return nil, fmt.Errorf("IPsec connection load uncertain; preserve resources for reconciliation")
		}
		progress.Connection = true
		if err = b.phaseJournal(ctx, profile, "issuing-connection", "connection-observed"); err != nil {
			return nil, fmt.Errorf("cannot durably observe created IPsec connection")
		}
	}
	return undo, nil
}

func (b *OperationalBackend) applyRemove(ctx context.Context, p operationalPlan) (core.Rollback, error) {
	profile := p.Profile
	progress := ipsecProgress{}
	// Once any VICI mutation is uncertain, do not claim to have reversed it.
	if p.Remove {
		current, err := b.Inspect(ctx, profile.Link)
		if err != nil {
			return nil, err
		}
		o := current.(operationalObservation)
		if o.Connection {
			active, saErr := b.hasIPsecSA(ctx, profile)
			if saErr != nil {
				return nil, fmt.Errorf("cannot inspect owned IPsec SA before removal")
			}
			if active {
				if err = b.Writer.Terminate(ctx, profile); err != nil {
					// An SA may already have been removed by the peer; explicit
					// reconciliation is safer than a wildcard termination.
					return nil, fmt.Errorf("scoped IPsec termination uncertain")
				}
			}
			if err = b.Writer.UnloadConnection(ctx, profile); err != nil {
				return nil, fmt.Errorf("IPsec unload connection uncertain")
			}
			progress.Connection = true
			if err = b.Writer.UnloadShared(ctx, profile); err != nil {
				return nil, fmt.Errorf("IPsec unload key uncertain")
			}
			progress.Shared = true
		}
		if o.Iface.Exists {
			fresh, err := b.inspectDevice(ctx, profile)
			if err != nil || !fresh.matches(profile) || fresh.Index != o.Iface.Index {
				return nil, fmt.Errorf("IPsec interface ownership changed before deletion")
			}
			if err = b.Delete(ctx, fresh.Index); err != nil {
				return nil, fmt.Errorf("IPsec owned interface delete unconfirmed")
			}
			progress.Deleted = true
		}
	}
	undo := func(undoCtx context.Context) error {
		if progress.Deleted {
			_, err := b.createDevice(undoCtx, profile)
			if err != nil {
				return err
			}
		}
		if progress.Shared {
			key, err := b.Keys.Load(profile.Link.ID)
			if err != nil {
				return fmt.Errorf("protected rollback PSK unavailable")
			}
			defer key.Zeroize()
			if err = b.Writer.LoadShared(undoCtx, profile, &key); err != nil {
				return err
			}
		}
		if progress.Connection {
			if err := b.Writer.LoadConnection(undoCtx, profile); err != nil {
				return err
			}
		}
		return nil
	}
	return undo, nil
}

type ipsecProgress struct {
	Created                     bool
	Index                       int
	Shared, Connection, Deleted bool
}

func (b *OperationalBackend) createDevice(ctx context.Context, p Profile) (ipsecProgress, error) {
	progress := ipsecProgress{}
	route, err := b.Routes.Resolve(ctx, p.Link.Underlay.Peer)
	if err != nil || route.Source != p.Link.Underlay.Local || route.Device == "" {
		return progress, fmt.Errorf("IPsec route changed before XFRM creation")
	}
	if err = b.XFRM.RequireVacant(ctx, p); err != nil {
		return progress, fmt.Errorf("XFRM resources no longer vacant")
	}
	if err = b.authorize(ctx); err != nil {
		return progress, err
	}
	_, err = b.Runner.RunBounded(ctx, CaptureLimits{Stdout: 4096, Stderr: 1024},
		b.IPBinary, "link", "add", "name", p.InterfaceName, "type", "xfrm",
		"dev", route.Device, "if_id", strconv.FormatUint(uint64(p.InterfaceID), 10))
	if err != nil {
		return progress, fmt.Errorf("XFRM device create failed or uncertain")
	}
	progress.Created = true
	idx, err := b.Index(p.InterfaceName)
	if err != nil || idx <= 0 {
		return progress, fmt.Errorf("cannot identify freshly created XFRM ifindex")
	}
	progress.Index = idx
	observed, err := b.inspectDevice(ctx, p)
	if err != nil || !observed.Exists || observed.Index != idx || observed.ID != p.InterfaceID || observed.Alias != "" {
		return progress, fmt.Errorf("XFRM creation identity uncertain")
	}
	tag, _ := domain.OwnerTag(p.Link.ID)
	if err = b.SetAlias(ctx, idx, tag); err != nil {
		return progress, fmt.Errorf("cannot mark XFRM device owner")
	}
	observed, err = b.inspectDevice(ctx, p)
	if err != nil || observed.Index != idx || observed.Alias != tag || observed.ID != p.InterfaceID {
		return progress, fmt.Errorf("XFRM ownership marking incomplete")
	}
	if err = b.AddAddr(ctx, idx, p.Link.Addresses.Local); err != nil {
		return progress, fmt.Errorf("cannot assign IPsec Link Address")
	}
	if err = b.SetUp(ctx, idx); err != nil {
		return progress, fmt.Errorf("cannot activate XFRM device")
	}
	observed, err = b.inspectDevice(ctx, p)
	if err != nil || !observed.matches(p) || observed.Index != idx {
		return progress, fmt.Errorf("created IPsec XFRM device differs from exact intent")
	}
	return progress, nil
}

func (b *OperationalBackend) rollbackCreation(ctx context.Context, p Profile, progress ipsecProgress) error {
	if err := b.authorize(ctx); err != nil {
		return err
	}
	if progress.Connection {
		if err := b.Writer.UnloadConnection(ctx, p); err != nil {
			return fmt.Errorf("cannot reconcile created IPsec connection")
		}
	}
	if progress.Shared {
		if err := b.Writer.UnloadShared(ctx, p); err != nil {
			return fmt.Errorf("cannot reconcile created IPsec PSK")
		}
	}
	if progress.Created {
		current, err := b.inspectDevice(ctx, p)
		if err != nil {
			return err
		}
		if current.Exists && current.Index == progress.Index && current.ID == p.InterfaceID &&
			(current.Alias == "" || current.matches(p)) {
			if err := b.Delete(ctx, current.Index); err != nil {
				return fmt.Errorf("cannot remove created XFRM device")
			}
		} else if current.Exists {
			return fmt.Errorf("XFRM device replaced during attempted rollback")
		}
	}
	return nil
}
