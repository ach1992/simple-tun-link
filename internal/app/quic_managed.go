package app

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type quicProvisionKey struct{}
type quicProvision struct {
	key            []byte
	store          RecipientCredentialStore
	bundle         quic.CredentialBundle
	publishHandoff func() error
}

// EnsureWithQUICCredential is the only managed first-creation material path.
// It joins the existing Engine transaction; publication of its exact journal
// precedes protected key/TLS/config writes and every Linux/systemd effect.
// publishHandoff is only the command's protected no-clobber handoff writer.
func (e *Engine) EnsureWithQUICCredential(ctx context.Context, desired domain.Link, key []byte,
	store RecipientCredentialStore, bundle quic.CredentialBundle, publishHandoff func() error) (Result, error) {
	if ctx == nil || desired.Backend != domain.BackendWireGuardQUIC || store == nil || len(key) == 0 {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "quic_credential", string(desired.ID), string(desired.Backend), "QUIC requires protected local key and endpoint credentials")
	}
	copyKey := append([]byte(nil), key...)
	defer clear(copyKey)
	p := &quicProvision{key: copyKey, store: store, bundle: bundle, publishHandoff: publishHandoff}
	return e.ensureWithPolicy(context.WithValue(ctx, quicProvisionKey{}, p), desired, true)
}

func quicNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("cannot allocate managed QUIC transaction identity")
	}
	return hex.EncodeToString(nonce[:]), nil
}

func (e *Engine) quicInitialContext(ctx context.Context, link domain.Link, prior state.LinkRecord) (context.Context, error) {
	var nonce string
	if prior.Desired.ID == link.ID {
		if prior.Desired != link || prior.QUICGeneration.Validate(link) != nil {
			return nil, fmt.Errorf("committed QUIC identity differs; provision a fresh Link for reconfiguration")
		}
		nonce = prior.QUICGeneration.OriginNonce
		ctx = backend.WithQUICGeneration(ctx, prior.QUICGeneration)
	} else {
		var err error
		nonce, err = quicNonce()
		if err != nil {
			return nil, err
		}
		if _, ok := ctx.Value(quicProvisionKey{}).(*quicProvision); !ok {
			return nil, fmt.Errorf("new managed QUIC Link requires protected credential admission")
		}
	}
	var err error
	ctx, err = backend.WithQUICOrigin(ctx, nonce)
	if err != nil {
		return nil, err
	}
	boot, err := e.kernelBootID()
	if err != nil || !hostidentity.ValidBootID(boot) {
		return nil, fmt.Errorf("managed QUIC requires a trusted host kernel generation")
	}
	if prior.Desired.ID == link.ID && prior.QUICGeneration.KernelBootID != boot {
		return backend.WithQUICColdBootExtinct(ctx, link.ID)
	}
	return ctx, nil
}

func (e *Engine) managedQUICRoot() (string, error) {
	provider, ok := e.store.(interface{ RootDir() string })
	if !ok || provider.RootDir() == "" {
		return "", fmt.Errorf("canonical managed QUIC private root unavailable")
	}
	return provider.RootDir(), nil
}

func quicPlanForManagedLink(link domain.Link) (quic.Plan, error) {
	host, err := composition.QUICHostPlanForLink(link)
	if err != nil {
		return quic.Plan{}, err
	}
	p := quic.Plan{LinkID: link.ID, Role: quic.Role(host.Local.Role), Underlay: host.Physical, TLSName: host.TLSName}
	if host.Local.Role == composition.Dial {
		p.LocalForwardUDPPort = host.Local.LocalHelperUDPPort
		p.PeerWGUDPPort = host.Local.RemoteWGUDPPort
	} else {
		p.LocalWGUDPPort = host.Local.LocalWGUDPPort
	}
	return p, nil
}

func (e *Engine) prepareManagedQUIC(ctx context.Context, req backend.Request, prior state.LinkRecord, resources []domain.ResourceClaim, changed bool) (context.Context, state.QUICCrashOperation, error) {
	root, err := e.managedQUICRoot()
	if err != nil {
		return nil, state.QUICCrashOperation{}, err
	}
	p, err := quicPlanForManagedLink(req.Link)
	if err != nil {
		return nil, state.QUICCrashOperation{}, err
	}
	host, err := composition.QUICHostPlanForLink(req.Link)
	if err != nil {
		return nil, state.QUICCrashOperation{}, err
	}
	provision, _ := ctx.Value(quicProvisionKey{}).(*quicProvision)
	committed := prior.Desired.ID == req.Link.ID
	var expected quic.HelperConfigIdentity
	if committed {
		g := prior.QUICGeneration
		expected = quicExpectedMaterialIdentity(state.QUICCrashOperation{CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization, HelperConfigSHA256: g.Files.HelperConfig,
			ExecutablePath: g.ExecutablePath, ExecutableSHA256: g.ExecutableSHA256, ExecutableDevice: g.ExecutableDevice, ExecutableInode: g.ExecutableInode})
		inspect := e.quicInspectGeneration
		if inspect == nil {
			inspect = quic.InspectJournalGeneration
		}
		actual, err := inspect(root, p, req.Link.WireGuard.ListenPort, quic.DefaultExecutable, g.MaterialNonce, expected)
		if err != nil || actual != expected {
			return nil, state.QUICCrashOperation{}, fmt.Errorf("committed QUIC protected generation differs")
		}
	}
	if provision != nil {
		if committed && !quicProvidedKeyMatches(provision.key, req.Link.WireGuard.LocalPublicKey) {
			return nil, state.QUICCrashOperation{}, fmt.Errorf("provided QUIC WireGuard key differs from committed identity")
		}
		preview := e.quicPreviewMaterial
		if preview == nil {
			preview = quic.PreviewHelperConfig
		}
		provided, err := preview(root, p, req.Link.WireGuard.ListenPort, quic.DefaultExecutable, provision.bundle)
		if err != nil {
			return nil, state.QUICCrashOperation{}, fmt.Errorf("QUIC provided material or approved executable invalid")
		}
		if committed && provided != expected {
			return nil, state.QUICCrashOperation{}, fmt.Errorf("provided QUIC credentials differ from committed issuance")
		}
		expected = provided
	} else if !committed {
		return nil, state.QUICCrashOperation{}, fmt.Errorf("fresh QUIC credential generation unavailable")
	}
	if !changed && req.Operation == backend.OperationEnsure {
		return ctx, state.QUICCrashOperation{}, nil
	}
	nonce := backend.QUICOrigin(ctx)
	if committed {
		nonce, err = quicNonce()
		if err != nil {
			return nil, state.QUICCrashOperation{}, err
		}
	}
	claims := append([]domain.ResourceClaim(nil), resources...)
	if req.Operation == backend.OperationRemove {
		claims = append([]domain.ResourceClaim(nil), prior.OwnedResources...)
	}
	op := state.QUICCrashOperation{Plan: host, Addresses: req.Link.Addresses, WireGuard: req.Link.WireGuard, Nonce: nonce, Resources: claims,
		CertificateSHA256: expected.Credentials.CertificateSHA256, TrustCASHA256: expected.Credentials.TrustCASHA256, AuthorizationSHA256: expected.Credentials.AuthorizationSHA256, HelperConfigSHA256: expected.ConfigSHA256,
		ExecutablePath: quic.DefaultExecutable, ExecutableSHA256: expected.Executable.SHA256, ExecutableDevice: expected.Executable.Device, ExecutableInode: expected.Executable.Inode,
		Managed: &state.QUICManagedOperation{Version: 1, Intent: req.Link, Operation: string(req.Operation), HadCommittedLink: committed, OriginalGeneration: prior.QUICGeneration}}
	if err := op.Validate(); err != nil {
		return nil, state.QUICCrashOperation{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, state.QUICCrashOperation{}, err
	}
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
	if err != nil {
		return nil, state.QUICCrashOperation{}, err
	}
	err = e.store.Update(ctx, func(s *state.Snapshot) error {
		if _, exists := s.FindQUICCrashOperation(req.Link.ID); exists {
			return fmt.Errorf("existing QUIC journal is quarantined")
		}
		if !stateMatchesPrior(*s, req.Link.ID, prior) {
			return fmt.Errorf("QUIC owner changed before journal")
		}
		if err := rejectResourceConflicts(*s, req.Link.ID, claims); err != nil {
			return err
		}
		s.QUICCrashOperations = append(s.QUICCrashOperations, op)
		return nil
	})
	release()
	if err != nil {
		return nil, state.QUICCrashOperation{}, stlerr.Wrap(stlerr.CodeState, "quic_prepare", string(req.Link.ID), string(req.Link.Backend), "managed QUIC journal durability unverified; no host effect attempted", err)
	}
	ctx, err = backend.WithQUICManagedOperation(ctx, op)
	if err != nil {
		return nil, op, err
	}
	if !committed {
		// A matching pre-existing key is never adopted as first creation.
		writer, ok := provision.store.(interface {
			PutRecipient(domain.LinkID, []byte, string) error
		})
		if !ok {
			return nil, op, fmt.Errorf("QUIC key store lacks exclusive original creation")
		}
		if err := writer.PutRecipient(req.Link.ID, provision.key, req.Link.WireGuard.LocalPublicKey); err != nil {
			return nil, op, fmt.Errorf("QUIC private key creation failed; preserve journal")
		}
		stage := e.quicStageGeneration
		if stage == nil {
			stage = quic.StageJournalGeneration
		}
		actual, err := stage(ctx, root, p, req.Link.WireGuard.ListenPort, quic.DefaultExecutable, op.Nonce, provision.bundle, expected)
		if err != nil || actual != expected {
			return nil, op, fmt.Errorf("QUIC protected generation creation uncertain; preserve journal and files")
		}
	}
	return ctx, op, nil
}

func sameQUICOperation(a, b state.QUICCrashOperation) bool { return reflect.DeepEqual(a, b) }

func quicProvidedKeyMatches(encoded []byte, expectedPublic string) bool {
	if len(encoded) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil {
		return false
	}
	defer clear(raw)
	if len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != string(encoded) {
		return false
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	return err == nil && base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) == expectedPublic
}

func consumeManagedQUIC(s *state.Snapshot, expected state.QUICCrashOperation) error {
	if expected.Managed == nil {
		return nil
	}
	current, ok := s.FindQUICCrashOperation(expected.Plan.Local.LinkID)
	if !ok || !sameQUICOperation(current, expected) || !s.DeleteQUICManagedOperation(expected.Plan.Local.LinkID) {
		return fmt.Errorf("managed QUIC journal changed before atomic completion")
	}
	return nil
}

func sameQUICRecord(a, b state.LinkRecord) bool {
	return a.Desired == b.Desired && a.QUICGeneration == b.QUICGeneration && slices.Equal(a.OwnedResources, b.OwnedResources)
}

func quicPublished(s state.Snapshot, req backend.Request, resources []domain.ResourceClaim, generation state.QUICGeneration, prior state.LinkRecord, termination string) bool {
	if _, pending := s.FindQUICCrashOperation(req.Link.ID); pending {
		return false
	}
	if req.Operation == backend.OperationEnsure {
		r, ok := s.Find(req.Link.ID)
		return ok && r.Desired == req.Link && r.QUICGeneration == generation && slices.Equal(r.OwnedResources, resources)
	}
	if _, present := s.Find(req.Link.ID); present {
		return false
	}
	r, ok := s.FindRemovalReceipt(req.Link.ID)
	return ok && r.QUICLink == req.Link && r.QUICGeneration == prior.QUICGeneration && r.QUICOriginalTermination == termination && state.ValidQUICOriginalTerminationProof(termination)
}
