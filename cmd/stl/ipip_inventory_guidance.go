package main

import (
	"context"
	"errors"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// These read-only projections accept only the IPIP adapter's typed inspection
// reason. Raw command/OS errors and arbitrary backend Details never become
// ordinary operator or JSON output; interruption always takes precedence.
func isIPIPInventoryUnverified(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	public := stlerr.Public(err)
	return public.Code == stlerr.CodeInspect &&
		public.Backend == string(domain.BackendIPIP) &&
		public.ReasonCode == "ipip_kernel_inventory_unverified"
}

const ipipInventoryReadSummary = "IPIP kernel inventory is unavailable or incomplete; live Link identity was not verified."
const ipipInventoryReadNext = "On THIS server check ip -details -json link show type ipip and the ipip module. Correct kernel/iproute2 readiness before repeating this read-only check. Do not infer a free interface, erase State or change unrelated Links."

func ipipInventoryReadPublicError(operation string, id domain.LinkID) *stlerr.Error {
	public := stlerr.New(stlerr.CodeInspect, operation, string(id), string(domain.BackendIPIP), ipipInventoryReadSummary)
	public.ReasonCode = "ipip_kernel_inventory_unverified"
	public.NextStep = ipipInventoryReadNext
	return public
}
