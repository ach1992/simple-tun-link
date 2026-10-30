package backend

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type quicOriginKey struct{}
type quicGenerationKey struct{}
type quicOperationKey struct{}
type quicDeletedKey struct{}
type quicColdBootKey struct{}
type quicProof struct {
	id    domain.LinkID
	nonce string
}

func QUICOrigin(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(quicOriginKey{}).(string)
	return s
}
func WithQUICOrigin(ctx context.Context, nonce string) (context.Context, error) {
	b, err := hex.DecodeString(nonce)
	if ctx == nil || err != nil || len(b) != 16 || hex.EncodeToString(b) != nonce {
		return nil, fmt.Errorf("invalid QUIC original-object nonce")
	}
	return context.WithValue(ctx, quicOriginKey{}, nonce), nil
}
func WithQUICGeneration(ctx context.Context, g state.QUICGeneration) context.Context {
	return context.WithValue(ctx, quicGenerationKey{}, g)
}
func QUICGenerationFromContext(ctx context.Context) (state.QUICGeneration, bool) {
	if ctx == nil {
		return state.QUICGeneration{}, false
	}
	g, ok := ctx.Value(quicGenerationKey{}).(state.QUICGeneration)
	return g, ok && g.Version == 1
}
func WithQUICManagedOperation(ctx context.Context, op state.QUICCrashOperation) (context.Context, error) {
	if ctx == nil || op.Validate() != nil || op.ValidateManaged() != nil {
		return nil, fmt.Errorf("canonical managed QUIC journal missing")
	}
	op.Resources = append([]domain.ResourceClaim(nil), op.Resources...)
	m := *op.Managed
	op.Managed = &m
	return context.WithValue(ctx, quicOperationKey{}, op), nil
}
func QUICManagedOperation(ctx context.Context) (state.QUICCrashOperation, bool) {
	if ctx == nil {
		return state.QUICCrashOperation{}, false
	}
	op, ok := ctx.Value(quicOperationKey{}).(state.QUICCrashOperation)
	if !ok || op.Managed == nil {
		return state.QUICCrashOperation{}, false
	}
	op.Resources = append([]domain.ResourceClaim(nil), op.Resources...)
	m := *op.Managed
	op.Managed = &m
	return op, true
}
func WithQUICWGDeleted(ctx context.Context, id domain.LinkID) (context.Context, error) {
	if ctx == nil || id.Validate() != nil || QUICOrigin(ctx) == "" {
		return nil, fmt.Errorf("QUIC original WG deletion witness missing")
	}
	return context.WithValue(ctx, quicDeletedKey{}, quicProof{id, QUICOrigin(ctx)}), nil
}
func HasQUICWGDeletionWitness(ctx context.Context, id domain.LinkID) bool {
	if ctx == nil {
		return false
	}
	p, ok := ctx.Value(quicDeletedKey{}).(quicProof)
	return ok && p.id == id && p.nonce != "" && p.nonce == QUICOrigin(ctx)
}
func WithQUICColdBootExtinct(ctx context.Context, id domain.LinkID) (context.Context, error) {
	if ctx == nil || id.Validate() != nil || QUICOrigin(ctx) == "" {
		return nil, fmt.Errorf("QUIC trusted kernel extinction witness missing")
	}
	return context.WithValue(ctx, quicColdBootKey{}, quicProof{id, QUICOrigin(ctx)}), nil
}
func HasQUICColdBootExtinctionWitness(ctx context.Context, id domain.LinkID) bool {
	if ctx == nil {
		return false
	}
	p, ok := ctx.Value(quicColdBootKey{}).(quicProof)
	return ok && p.id == id && p.nonce != "" && p.nonce == QUICOrigin(ctx)
}

// ManagedQUICBackend adds only the retained transaction scope required by the
// concrete QUIC composition. Close releases descriptors; it never rolls back.
type ManagedQUICBackend interface {
	BeginQUIC(context.Context, domain.Link, *state.QUICGeneration) (context.Context, func() error, error)
	AttestQUIC(context.Context, domain.Link) (state.QUICGeneration, error)
	QUICHostVacant(context.Context, domain.Link) (bool, error)
}

type QUICDiagnostic struct {
	Interface           string `json:"interface"`
	IfIndex             int    `json:"ifindex"`
	KernelPresent       bool   `json:"kernel_present"`
	GuardActive         bool   `json:"guard_active"`
	HelperActive        bool   `json:"helper_active"`
	HelperLoaded        bool   `json:"helper_loaded"`
	LatestHandshakeUnix int64  `json:"latest_handshake_unix"`
	RXBytes             uint64 `json:"rx_bytes"`
	TXBytes             uint64 `json:"tx_bytes"`
}
