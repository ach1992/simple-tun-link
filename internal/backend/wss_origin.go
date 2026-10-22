package backend

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// WSSOrigin carries an already-durable nonsecret per-Link creation nonce.
// It is NEVER an authorization by itself: the owner State and actual original
// host-object marker/readback must also agree under canonical Engine locks.
// The typed key prevents environment/CLI values from being used implicitly.
type wssOriginKey struct{}

func WSSOrigin(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(wssOriginKey{}).(string)
	return v
}
func WithWSSOrigin(ctx context.Context, nonce string) (context.Context, error) {
	raw, err := hex.DecodeString(nonce)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != nonce {
		return nil, ErrInvalidWSSOrigin
	}
	return context.WithValue(ctx, wssOriginKey{}, nonce), nil
}

// ErrInvalidWSSOrigin cannot expose private material in an error.
var ErrInvalidWSSOrigin = errors.New("invalid WSS original-object nonce")

// wssWGDeletionProof is a call-local, non-persisted witness produced only
// after the canonical backend has authenticated the ORIGINAL WG ifindex/alias
// and successfully dispatched its index-targeted deletion. Absence of a
// namespace-local interface or UDP socket is never this proof.
type wssWGDeletionProof struct {
	id    domain.LinkID
	nonce string
}
type wssWGDeletionKey struct{}

// WithWSSWGDeleted marks the active original Link generation as having
// completed its verified kernel-deletion step during THIS transaction.
// This is not a durable crash-recovery certificate and is never inferred
// from matching public names, missing sockets or a stored journal.
func WithWSSWGDeleted(ctx context.Context, id domain.LinkID) (context.Context, error) {
	if ctx == nil || id.Validate() != nil || WSSOrigin(ctx) == "" {
		return nil, errors.New("WSS original WG deletion witness missing")
	}
	return context.WithValue(ctx, wssWGDeletionKey{}, wssWGDeletionProof{
		id: id, nonce: WSSOrigin(ctx),
	}), nil
}

func HasWSSWGDeletionWitness(ctx context.Context, id domain.LinkID) bool {
	if ctx == nil {
		return false
	}
	proof, ok := ctx.Value(wssWGDeletionKey{}).(wssWGDeletionProof)
	return ok && proof.id == id && proof.nonce != "" && proof.nonce == WSSOrigin(ctx)
}
