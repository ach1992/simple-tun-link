package quic

import "context"

// WithPinnedJournalGeneration retains the original protected directory chain
// and every role/config/receipt file descriptor across one original helper
// effect. It prevents inode recycling during the operation, not privileged
// in-place writes or recovery by matching shape. Admission locks are required.
func WithPinnedJournalGeneration(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity, perform func() error) error {
	return withPinnedJournalGeneration(ctx, root, plan, port, binary, nonce, expected, perform, InspectPinnedHysteria)
}

func withPinnedJournalGeneration(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity, perform func() error, verify helperVerifier) error {
	pin, err := openPinnedGeneration(ctx, root, plan, port, binary, nonce, expected, verify)
	if err != nil {
		return err
	}
	defer pin.Close()
	if perform == nil {
		return errInvalidPinnedOperation
	}
	if err := perform(); err != nil {
		return err
	}
	return pin.Verify(ctx)
}
