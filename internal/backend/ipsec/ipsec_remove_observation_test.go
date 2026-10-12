package ipsec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIPsecRemoveWaitsForAcknowledgedTerminationSAReadback(t *testing.T) {
	reads := 0
	err := waitForIPsecSAAbsence(context.Background(), func(context.Context) (bool, error) {
		reads++
		// Native XFRM can still show the own SA after VICI returns success.
		// A one-shot readback fails the same transient, but two extra
		// read-only inspections settle without any repeated VICI mutation.
		return reads < 3, nil
	})
	if err != nil || reads != 3 {
		t.Fatalf("short lived SA readback was not observed: reads=%d err=%v", reads, err)
	}
}

func TestIPsecRemoveVacancyReadbackImmediate(t *testing.T) {
	reads := 0
	err := waitForIPsecSAAbsence(context.Background(), func(context.Context) (bool, error) {
		reads++
		return false, nil
	})
	if err != nil || reads != 1 {
		t.Fatalf("verified absence should finish immediately: reads=%d err=%v", reads, err)
	}
}

func TestIPsecRemoveReadbackFailsClosedForPersistentSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 95*time.Millisecond)
	defer cancel()
	reads := 0
	err := waitForIPsecSAAbsence(ctx, func(context.Context) (bool, error) {
		reads++
		return true, nil
	})
	if err == nil || reads < 2 {
		t.Fatalf("persistent SA incorrectly accepted: reads=%d err=%v", reads, err)
	}
}

func TestIPsecRemoveReadbackNeverRetriesUnknownInventory(t *testing.T) {
	reads := 0
	err := waitForIPsecSAAbsence(context.Background(), func(context.Context) (bool, error) {
		reads++
		return false, errors.New("SECRET_FIXTURE_DO_NOT_ECHO")
	})
	if err == nil || reads != 1 || strings.Contains(err.Error(), "SECRET_FIXTURE_DO_NOT_ECHO") {
		t.Fatalf("ambiguous inventory accepted, retried or disclosed: reads=%d err=%v", reads, err)
	}
}

func TestIPsecRemoveReadbackHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reads := 0
	err := waitForIPsecSAAbsence(ctx, func(context.Context) (bool, error) {
		reads++
		return false, nil
	})
	if err == nil || reads != 0 {
		t.Fatalf("cancelled context treated as success: reads=%d err=%v", reads, err)
	}
}

func TestIPsecRemoveReadbackRejectsMissingObserver(t *testing.T) {
	if waitForIPsecSAAbsence(context.Background(), nil) == nil ||
		waitForIPsecSAAbsence(nil, func(context.Context) (bool, error) { return false, nil }) == nil {
		t.Fatal("nil context or observer accepted")
	}
}

func TestIPsecRemoveReadbackRejectsCancelledFalseObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := waitForIPsecSAAbsence(ctx, func(context.Context) (bool, error) {
		cancel()
		return false, nil
	})
	if err == nil {
		t.Fatal("cancellation during an absence read may not be committed")
	}
}

func TestIPsecRemoveReadbackBoundsBlockedInspector(t *testing.T) {
	start := time.Now()
	err := waitForIPsecSAAbsence(context.Background(), func(ctx context.Context) (bool, error) {
		<-ctx.Done()
		return false, ctx.Err()
	})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("uninspectable XFRM state was not bounded and fail-closed: %v", err)
	}
}
