package backend

import (
	"context"
	"encoding/hex"
	"errors"
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
