package ipsec

import (
	"context"
	"fmt"
	"time"
)

// waitForIPsecSAAbsence is a bounded, read-only post-VICI termination
// observation. A successful VICI response alone does not prove that all
// matching kernel XFRM SAs have been retired. Never retry termination,
// unload credentials, delete interfaces or advance a journal here.
func waitForIPsecSAAbsence(ctx context.Context, observe func(context.Context) (bool, error)) error {
	if ctx == nil || observe == nil {
		return fmt.Errorf("IPsec SA termination observation unavailable")
	}
	if ctx.Err() != nil {
		return fmt.Errorf("IPsec SA termination observation interrupted")
	}
	const window = 1200 * time.Millisecond
	const interval = 40 * time.Millisecond
	settleCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := settleCtx.Err(); err != nil {
			return ipsecRemovalObservationDeadline(ctx)
		}
		present, err := observe(settleCtx)
		if err != nil {
			// Never expose raw XFRM, daemon errors or key material.
			return fmt.Errorf("IPsec SA termination readback unverified")
		}
		if settleCtx.Err() != nil {
			return ipsecRemovalObservationDeadline(ctx)
		}
		if !present {
			return nil
		}
		select {
		case <-settleCtx.Done():
			return ipsecRemovalObservationDeadline(ctx)
		case <-tick.C:
		}
	}
}

func ipsecRemovalObservationDeadline(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("IPsec SA termination observation interrupted")
	}
	return fmt.Errorf("IPsec SA termination not yet observed; explicit reconciliation required")
}
