package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const ipsecDoctorTimeout = 8 * time.Second

const ipsecUnregisteredHelp = "IPsec operational runtime is not available in this build; run stl doctor ipsec for read-only prerequisites and safe next steps"

// ipsecDoctorCommand is observational. It must never call the application
// Engine, enable a service, fetch keys, invoke VICI writes or touch the host.
// Its diagnostic result is not an IPsec activation authorization.
func ipsecDoctorCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	if !(len(args) == 1 && args[0] == "ipsec") &&
		!(len(args) == 2 && args[0] == "ipsec" && args[1] == "--json") {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "doctor_ipsec",
			"usage: stl doctor ipsec [--json]")
	}
	runner := linux.Runner(linux.ExecRunner{})
	if options != nil && options.probeRunner != nil {
		runner = options.probeRunner
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsecDoctorTimeout)
	defer cancel()
	report, err := diagnostics.InspectIPsecHost(ctx, runner)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "doctor_ipsec",
			"read-only IPsec host inspection did not complete; no activation was attempted")
	}
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, "cannot encode safe diagnostic report")
			return 1
		}
	} else {
		fmt.Fprintln(stdout, "IPsec native-exclusive: NOT READY (read-only checks; no host changes)")
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "- [%s] %s (%s): %s\n", check.Status, check.Name, check.ReasonCode, check.Summary)
			fmt.Fprintf(stdout, "  Next: %s\n", check.NextStep)
		}
		fmt.Fprintln(stdout, "Other registered backends are independent of this IPsec limitation.")
	}
	// A successful inspection is not successful IPsec readiness. Use the
	// stable unsupported-capability exit code until operationally enabled.
	return 4
}
