package main

// Finite, manually started background operations managed by Linux systemd.
// No daemon is installed/enabled, and no network operation is auto-resumed.
// Closing an SSH terminal cannot stop an already accepted system service.
// Signed receiver/sender evidence stays in the underlying tool's private files.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

var finiteUnitID = regexp.MustCompile(`^sdx-[0-9a-f]{16}\.service$`)

func jobOperationLimits(argv []string) (int, error) {
	if len(argv) < 2 {
		return 0, errors.New("detached job requires explicit allowed command and operation")
	}
	switch argv[0] + " " + argv[1] {
	case "field observe":
		window := 0
		for i := 2; i < len(argv); i++ {
			if argv[i] == "--window-seconds" && i+1 < len(argv) {
				v, e := strconv.Atoi(argv[i+1])
				if e != nil {
					return 0, e
				}
				window = v
			} else if strings.HasPrefix(argv[i], "--window-seconds=") {
				v, e := strconv.Atoi(strings.TrimPrefix(argv[i], "--window-seconds="))
				if e != nil {
					return 0, e
				}
				window = v
			}
		}
		if window < 1 || window > passiveMaxWindowSeconds {
			return 0, errors.New("field observe job requires finite --window-seconds 1..14400")
		}
		return window + 120, nil
	case "field send", "field listen", "field accept", "campaign send", "campaign receive":
		// Legacy strict signed Field runs have their own exact grant TTL,
		// per-run sample limits, and replay ledger; this is ONLY a supervisor.
		return 1200, nil
	case "exchange analyze", "exchange import", "exchange export", "exchange inspect":
		return 86400, nil
	default:
		return 0, errors.New("job start supports only finite field observe/send/listen/accept, campaign send/receive, and offline exchange analysis/import/export/inspect")
	}
}

func jobScope() ([]string, error) {
	if os.Geteuid() == 0 {
		return nil, nil // system transient service under root, no user-session dependency
	}
	me, err := user.Current()
	if err != nil {
		return nil, err
	}
	// A rootless user service must have linger enabled to survive logout.
	c := exec.Command("loginctl", "show-user", me.Username, "--property=Linger", "--value")
	b, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("cannot verify systemd user linger (run loginctl enable-linger with admin approval): %w", err)
	}
	if strings.TrimSpace(string(b)) != "yes" {
		return nil, errors.New("user systemd linger disabled: cannot promise survival after logout; administrator must explicitly enable-linger for this user")
	}
	return []string{"--user"}, nil
}

func runSystemCommand(name string, argv ...string) (string, error) {
	c := exec.Command(name, argv...)
	output, err := c.CombinedOutput()
	if len(output) > 256<<10 {
		output = output[:256<<10]
	}
	if err != nil {
		return "", fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func jobCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: job start|status|logs|stop (only finite sdx-* transient systemd units)")
	}
	verb := args[0]
	scope, err := jobScope()
	if err != nil {
		return err
	}
	switch verb {
	case "start":
		f := flag.NewFlagSet("job start", flag.ContinueOnError)
		allowedSeconds := f.Int("runtime-seconds", 0, "optional explicit max runtime in seconds; cannot exceed operation policy")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		operation := f.Args()
		capSeconds, err := jobOperationLimits(operation)
		if err != nil {
			return err
		}
		maxSeconds := capSeconds
		if *allowedSeconds != 0 {
			if *allowedSeconds < 1 || *allowedSeconds > capSeconds {
				return fmt.Errorf("job runtime must be 1..%d seconds for selected operation", capSeconds)
			}
			maxSeconds = *allowedSeconds
		}
		nonce, err := randomHex(8)
		if err != nil {
			return err
		}
		id := "sdx-" + nonce + ".service"
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		if !strings.HasPrefix(executable, "/") {
			return errors.New("absolute signed binary location required for detached execution")
		}
		systemArgs := append([]string{}, scope...)
		systemArgs = append(systemArgs,
			"--no-block", "--no-ask-password", "--remain-after-exit", "--same-dir",
			"--unit="+strings.TrimSuffix(id, ".service"),
			"--description=SpoofDiag operator-started finite diagnostic",
			"--property=Type=exec", "--property=Restart=no",
			"--property=UMask=0077",
			"--property=RuntimeMaxSec="+strconv.Itoa(maxSeconds)+"s",
			"--", executable)
		systemArgs = append(systemArgs, operation...)
		if _, err := runSystemCommand("systemd-run", systemArgs...); err != nil {
			return err
		}
		return pretty(map[string]any{
			"status": "JOB_START_REQUESTED_NOT_PEER_READY",
			"unit":   id, "max_runtime_seconds": maxSeconds,
			"operation": operation[:2],
			"next":      "job status --unit " + id,
			"note":      "systemd accepted a finite job; receiver socket readiness and peer reachability are NOT proven",
		})
	case "status", "logs", "stop":
		f := flag.NewFlagSet("job "+verb, flag.ContinueOnError)
		unit := f.String("unit", "", "exact SpoofDiag systemd service ID returned by job start")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if !finiteUnitID.MatchString(*unit) {
			return errors.New("job operation requires a valid exact sdx-16hex.service unit ID")
		}
		if len(f.Args()) != 0 {
			return errors.New("unexpected job arguments")
		}
		switch verb {
		case "status":
			cmdArgs := append([]string{}, scope...)
			cmdArgs = append(cmdArgs, "show", "--no-pager",
				"--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,ExecMainStartTimestamp,ExecMainExitTimestamp,InvocationID", *unit)
			out, err := runSystemCommand("systemctl", cmdArgs...)
			if err != nil {
				return err
			}
			props := map[string]string{}
			for _, line := range strings.Split(out, "\n") {
				p := strings.SplitN(line, "=", 2)
				if len(p) == 2 {
					props[p[0]] = p[1]
				}
			}
			state := "UNKNOWN"
			switch {
			case props["LoadState"] == "not-found":
				state = "UNKNOWN_UNIT"
			case props["ActiveState"] == "activating":
				state = "STARTING"
			case props["ActiveState"] == "active" && props["SubState"] == "running":
				state = "RUNNING"
			case props["ActiveState"] == "active" && props["SubState"] == "exited" && props["Result"] == "success":
				state = "FINISHED"
			case props["Result"] == "timeout":
				state = "EXPIRED"
			case props["Result"] == "exit-code":
				state = "FAILED"
			case props["ActiveState"] == "failed":
				state = "FAILED"
			case props["ActiveState"] == "inactive":
				state = "INACTIVE_CHECK_SIGNED_ARTIFACT"
			}
			return pretty(map[string]any{"unit": *unit, "status": state, "systemd": props,
				"note": "FINISHED means subprocess exit, not successful packet delivery; verify saved signed evidence"})
		case "logs":
			cmdArgs := append([]string{}, scope...)
			cmdArgs = append(cmdArgs, "--no-pager", "--output=short-iso", "-n", "150", "-u", *unit)
			out, err := runSystemCommand("journalctl", cmdArgs...)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		case "stop":
			cmdArgs := append([]string{}, scope...)
			cmdArgs = append(cmdArgs, "stop", *unit)
			if _, err := runSystemCommand("systemctl", cmdArgs...); err != nil {
				return err
			}
			return pretty(map[string]any{"unit": *unit, "status": "STOP_REQUESTED",
				"note": "read signed evidence and job status; no automatic resume/retry of network operations"})
		}
	default:
		return errors.New("job expects start|status|logs|stop")
	}
	return errors.New("unsupported job action")
}
