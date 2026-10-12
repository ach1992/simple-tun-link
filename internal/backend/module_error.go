package backend

import "github.com/ach1992/simple-tun-link/internal/stlerr"

// KernelModuleNotLoaded is a narrow, evidence-backed inspection failure.
// It is deliberately still an inspect error, preserving v1 exit behavior:
// the failed inventory was not an empty inventory or proof of a free port.
func KernelModuleNotLoaded(module string) *stlerr.Error {
	out := stlerr.New(stlerr.CodeInspect, "kernel_module_probe", "", "",
		"required kernel module is available on disk but not loaded; live inventory was not verified")
	out.ReasonCode = "kernel_module_not_loaded"
	out.NextStep = "Check installed kernel module and host capability; load it only with operator authorization, then retry read-only inspection."
	return out
}
