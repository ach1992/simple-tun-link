package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const ipsecDoctorTimeout = 8 * time.Second

const ipsecDoctorNextStep = "stl doctor ipsec"

const ipsecUnregisteredHelp = "IPsec operational runtime is not available in this build; run " + ipsecDoctorNextStep + " for read-only prerequisites and safe next steps"

// ipsecUnregisteredError uses the normal v1 error JSON/human/exit path but
// adds the validated Link identity and a specific stable recovery reason.
// No probe runs here; the operator can choose the read-only doctor explicitly.
func ipsecUnregisteredError(stdout, stderr io.Writer, jsonOutput bool, operation string, id domain.LinkID) int {
	public := stlerr.New(stlerr.CodeUnsupported, operation, string(id), string(domain.BackendIPsec), ipsecUnregisteredHelp)
	public.ReasonCode = diagnostics.IPsecRuntimeNotRegisteredReason
	public.NextStep = ipsecDoctorNextStep
	return readCommandPublicError(stdout, stderr, jsonOutput, public)
}

// Render a compact, read-only human triage. The versioned JSON remains the
// complete per-check reason/next-step report. A missing admitted runtime is
// NOT evidence that another process or service is foreign-owned.
func renderIPsecDoctorHuman(out io.Writer, report diagnostics.IPsecHostReport) {
	if report.ActivationAllowed {
		menuSection(out, "IPsec / runtime VERIFIED")
		menuNotice(out, "OK", "STL native-exclusive ownership is currently admitted (read-only observation).")
		menuProse(out, "Readiness is time-local; Link traffic still requires peer negotiation and verification.")
		menuCopyLine(out, "Details / every observed check", "stl doctor ipsec --json")
		return
	}

	menuSection(out, "IPsec / NOT READY")
	var observed, unknown int
	var blocked, uncertain []diagnostics.IPsecHostCheck
	var conflict, runtimeMissing bool
	var nativePreflight *diagnostics.IPsecHostCheck
	for _, check := range report.Checks {
		if check.Name == "provisioning_readiness" {
			current := check
			nativePreflight = &current
		}
		switch check.Status {
		case "observed":
			observed++
		case "blocked":
			if check.Name == "operational_runtime" {
				runtimeMissing = true
			} else {
				blocked = append(blocked, check)
			}
			switch check.ReasonCode {
			case "charon_process_observed", "ike_udp_ports_observed",
				"native_systemd_unit_conflict", "ipsec_provisioning_daemon_conflict",
				"ipsec_provisioning_ports_conflict":
				conflict = true
			}
		default:
			unknown++
			uncertain = append(uncertain, check)
		}
	}
	blockedCount := len(blocked)
	if runtimeMissing {
		blockedCount++
	}
	menuField(out, "Checks", fmt.Sprintf("%d observed / %d blocked / %d unknown",
		observed, blockedCount, unknown))
	if runtimeMissing {
		menuField(out, "Runtime", "Not admitted; no service was started")
	}
	if nativePreflight != nil {
		menuField(out, "Native preflight", nativePreflight.ReasonCode)
	}
	// Show at most two examples per category; details are opt-in in JSON.
	// The proven-conflict decision considers ALL checks, not just examples.
	for _, group := range []struct {
		label  string
		checks []diagnostics.IPsecHostCheck
	}{
		{"Blocked", blocked}, {"Unknown", uncertain},
	} {
		for i, check := range group.checks {
			if i >= 2 {
				menuField(out, group.label, fmt.Sprintf("%d more checks; see JSON details", len(group.checks)-2))
				break
			}
			menuField(out, group.label, check.Name+" ("+check.ReasonCode+")")
		}
	}
	menuSection(out, "Next: one safe action")
	switch {
	case conflict:
		menuProse(out, "A conflicting or unowned process, service or IKE port was observed. Do not stop or adopt it; inspect ownership or choose another backend.")
	case nativePreflight != nil && nativePreflight.Status == "blocked":
		menuProse(out, nativePreflight.NextStep)
	case nativePreflight != nil && nativePreflight.Status == "observed":
		menuProse(out, "Private provisioning prerequisites pass right now, but the STL-only IPsec service is not active. Continue through a fresh, confirmed PREPARE.")
	case unknown > 0:
		menuProse(out, "Resolve incomplete read-only host observations before IPsec preparation. Inspect the full JSON report.")
	default:
		menuProse(out, "Run sudo stl menu, select IPsec, then review the scoped PREPARE plan. Service ownership must qualify independently.")
	}
	menuCopyLine(out, "Details / all reason codes and next steps", "stl doctor ipsec --json")
	menuProse(out, "Other registered backends are independent of this IPsec limitation.")
}

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
	// Prefer a complete currently admitted native-exclusive runtime when
	// available. The older source-only prerequisites deliberately treat
	// EVERY charon/UDP listener as foreign because they have no PID/socket
	// ownership proofs, so combining those checks with admitted state would
	// give a contradictory report.
	if options == nil {
		resolved, err := productionRuntimeOptions()
		if err == nil {
			options = resolved
		}
	}
	if options != nil {
		admissionCtx, cancel := context.WithTimeout(context.Background(), ipsecDoctorTimeout)
		_, admitted := activeIPsecBackend(admissionCtx, options)
		cancel()
		if admitted == nil {
			report := diagnostics.IPsecHostReport{
				SchemaVersion: 1, Backend: "ipsec", RuntimeMode: "native_exclusive",
				ActivationAllowed: true,
				Checks: []diagnostics.IPsecHostCheck{{
					Name: "operational_runtime", Status: "observed",
					ReasonCode: "ipsec_native_exclusive_owner_admitted",
					Summary:    "Current STL-created unit, process, logging configuration, private VICI peer and IKE ports were attested read-only.",
					NextStep:   "Use explicit create/import/activate and verify the negotiated SA and Link Address traffic. Reapply admission before each mutation.",
				}},
			}
			if jsonOutput {
				if err := json.NewEncoder(stdout).Encode(report); err != nil {
					fmt.Fprintln(stderr, "cannot encode qualified native IPsec status")
					return 1
				}
			} else {
				renderIPsecDoctorHuman(stdout, report)
			}
			return 0
		}
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
	// Production doctor now reports the SAME read-only native provisioning
	// gate that PREPARE uses. Older file-presence checks can report a
	// service-file observation without knowing whether it is active or
	// disabled; this complete gate exposes the actual failed prerequisite.
	// Fake-runner tests retain their hermetic contract and do not inspect
	// the real host. No result here grants authority to change a service.
	if options == nil || options.probeRunner == nil {
		preflightCtx, preflightCancel := context.WithTimeout(context.Background(), 12*time.Second)
		readiness := ipsecbackend.NativeProvisionReadiness(preflightCtx)
		preflightCancel()
		report.Checks = append(report.Checks, ipsecReadinessCheck(readiness))
	}
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, "cannot encode safe diagnostic report")
			return 1
		}
	} else {
		renderIPsecDoctorHuman(stdout, report)
	}
	// A successful inspection is not successful IPsec readiness. Use the
	// stable unsupported-capability exit code until operationally enabled.
	return 4
}
