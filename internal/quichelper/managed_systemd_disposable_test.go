//go:build linux

package quichelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"golang.org/x/sys/unix"
)

// This native PID1 fixture exercises the real managed systemd/process policy.
// It deliberately uses only a bounded harmless canonical sleep executable;
// complete Engine+Hysteria+WG traffic acceptance is a separate two-peer test.
func TestQUICHelperDisposableSystemdManaged(t *testing.T) {
	if os.Getenv("STL_QUIC_HELPER_DISPOSABLE_SYSTEMD") != "approved" {
		t.Skip("requires an explicitly approved disposable systemd runner")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("GITHUB_REPOSITORY") != "ach1992/simple-tun-link" || os.Geteuid() != 0 {
		t.Fatal("disposable GitHub-hosted root fixture required")
	}
	if raw, err := os.ReadFile("/proc/1/comm"); err != nil || strings.TrimSpace(string(raw)) != "systemd" {
		t.Fatal("native disposable PID1 systemd required")
	}
	run, attempt := disposableRunNumber(t, "GITHUB_RUN_ID"), disposableRunNumber(t, "GITHUB_RUN_ATTEMPT")
	digest := sha256.Sum256([]byte("quic-managed-systemd:" + run + ":" + attempt))
	id := fmt.Sprintf("%x", digest[:6])
	spec := unitSpec{Name: "stl-quic-managed-" + id + ".service", Description: fmt.Sprintf("STL-QUIC-MANAGED-LAB-%s:origin:%x", id, digest[:16]), Binary: "/usr/bin/sleep", Args: []string{"60"}}
	_, executable := pinDisposableExecutable(t)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	if os.Getenv("STL_QUIC_MANAGED_FIXTURE_CHILD") == "start" {
		vacant, err := inspectManagedUnit(ctx, spec)
		if err != nil || vacant.Loaded {
			logDisposableManagerEnvironment(t, ctx)
			t.Fatalf("managed child target not independently vacant: %v", err)
		}
		if err := startDisposableManagedWithLimit(ctx, spec); err != nil {
			t.Fatalf("managed child start failed or uncertain: %v", err)
		}
		return // The launcher process actually exits before parent observation.
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQUICHelperDisposableSystemdManaged$", "-test.count=1", "-test.v")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "GITHUB_REPOSITORY=ach1992/simple-tun-link",
		"GITHUB_RUN_ID=" + run, "GITHUB_RUN_ATTEMPT=" + attempt, "STL_QUIC_HELPER_DISPOSABLE_SYSTEMD=approved", "STL_QUIC_MANAGED_FIXTURE_CHILD=start"}
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil || output.overflow {
		t.Fatalf("managed launcher failed before a positive fixture start: %v; %s", err, output.String())
	}
	var retained []*processPin
	// The exact per-run unit was positively created by our completed child.
	// Cleanup still requires the production policy/process readback. A name
	// collision or drift never grants a stop; the sleep exits by itself.
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		obs, err := inspectManagedUnit(cleanup, spec)
		if err == nil && obs.Loaded {
			if obs.Process != nil {
				retained = append(retained, obs.Process)
			}
			if managedTerminalFailure(obs) {
				if err := resetFailedManagedUnit(cleanup, spec); err != nil {
					t.Errorf("verified terminal managed fixture collection failed: %v", err)
				}
			} else if _, err = managerCommand(cleanup, "systemctl", "--system", "stop", spec.Name, "--no-pager"); err != nil {
				t.Errorf("verified managed fixture stop failed: %v", err)
			}
		} else if err != nil {
			t.Errorf("managed fixture identity changed; no name cleanup: %v", err)
		}
		for _, pin := range retained {
			if err := pin.Close(); err != nil {
				t.Errorf("close retained managed process: %v", err)
			}
		}
	})
	first, err := inspectManagedUnit(ctx, spec)
	if err != nil || !first.Active || first.Process == nil {
		t.Fatalf("fresh caller could not verify the post-launcher managed process: %v", err)
	}
	retained = append(retained, first.Process)
	limitRaw, err := managerCommand(ctx, "systemctl", "--system", "show", spec.Name, "--property=StartLimitIntervalUSec,StartLimitBurst", "--no-pager", "--all")
	if err != nil {
		t.Fatalf("fixture start-limit readback failed: %v", err)
	}
	limits, err := parseProperties(limitRaw)
	if err != nil || limits["StartLimitIntervalUSec"] != "1min" || limits["StartLimitBurst"] != "2" {
		t.Fatal("fixture's exact two-start per-minute limit was not independently observed")
	}
	if first.Process.Observation.ExecutableDevice != uint64(executable.Dev) || first.Process.Observation.ExecutableInode != executable.Ino {
		t.Fatal("managed process is not the original canonical executable")
	}
	if err := verifyUnitProperties(first.Values, spec); err == nil {
		t.Fatal("managed restart/journal policy was promoted into source-only verifier")
	}
	for _, property := range []string{"ExecStartPost", "UpheldBy", "TriggeredBy"} {
		altered := make(map[string]string, len(first.Values))
		for key, value := range first.Values {
			altered[key] = value
		}
		altered[property] = "foreign.service"
		if err := verifyManagedUnitProperties(altered, spec, true); err == nil {
			t.Fatal("managed verifier admitted unknown lifecycle authority:", property)
		}
	}
	if err := resetFailedManagedUnit(ctx, spec); err == nil || errors.Is(err, core.ErrIndeterminateHostEffect) {
		t.Fatal("active managed unit was not refused before reset dispatch")
	}
	if err := unix.PidfdSendSignal(first.Process.fd, unix.SIGKILL, nil, 0); err != nil {
		t.Fatalf("signal exact original fixture pidfd: %v", err)
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var restarted managedUnitObservation
	for {
		values, readErr := queryManagedUnit(ctx, spec.Name)
		if readErr != nil || verifyManagedUnitProperties(values, spec, false) != nil {
			t.Fatalf("managed restart policy/readback drifted: %v", readErr)
		}
		// The original SIGKILL creates an expected short dead-PID interval.
		// Wait on exact manager state first; never turn an arbitrary process
		// verifier error into permission to adopt another invocation.
		if values["ActiveState"] == "active" && values["InvocationID"] != first.Process.Observation.InvocationID {
			restarted, err = inspectManagedUnit(ctx, spec)
			if err != nil {
				t.Fatalf("new managed invocation could not be verified: %v", err)
			}
			if restarted.Process != nil {
				retained = append(retained, restarted.Process)
				break
			}
		}
		select {
		case <-deadline.C:
			t.Fatal("on-failure managed restart was not observed")
		case <-ticker.C:
		}
	}
	if !restarted.Active || restarted.Process.Observation.PID == first.Process.Observation.PID || first.Process.alive() == nil {
		t.Fatal("managed restart did not create a distinct current invocation")
	}
	if n, err := canonicalUint(restarted.Values["NRestarts"]); err != nil || n == 0 {
		t.Fatal("manager did not attest its automatic retry")
	}
	if restarted.Process.Observation.ExecutableDevice != uint64(executable.Dev) || restarted.Process.Observation.ExecutableInode != executable.Ino {
		t.Fatal("managed restart changed canonical executable identity")
	}
	// The fixture-only limit permits the initial invocation and one automatic
	// restart. Killing this exact second pidfd reaches a real terminal failure
	// on both systemd249 and newer, while the production GC policy is unchanged.
	if err := unix.PidfdSendSignal(restarted.Process.fd, unix.SIGKILL, nil, 0); err != nil {
		t.Fatalf("signal exact second fixture invocation: %v", err)
	}
	failed := waitDisposableManagedTerminalFailure(t, ctx, spec)
	// systemd v249/v255 service_enter_dead preserves an earlier non-success
	// result. After SIGKILL the denied restart can therefore retain "signal";
	// the separately verified limit and two queued retries prove exhaustion.
	result := failed.Values["Result"]
	resultKnown := result == "signal" || result == "start-limit-hit"
	if !resultKnown || failed.Values["NRestarts"] != "2" || failed.Values["MainPID"] != "0" || failed.Values["CollectMode"] != "inactive" {
		t.Fatalf("fixture terminal evidence differs: result_known=%t retries_two=%t main_pid_zero=%t collect_inactive=%t", resultKnown, failed.Values["NRestarts"] == "2", failed.Values["MainPID"] == "0", failed.Values["CollectMode"] == "inactive")
	}
	t.Logf("terminal failure after verified start-limit exhaustion: result=%s retries=2 main_pid_zero=true", result)
	if _, err := managerCommand(ctx, "systemctl", "--system", "stop", spec.Name, "--no-pager"); err != nil {
		t.Fatalf("verified terminal fixture stop request failed: %v", err)
	}
	stillFailed, err := inspectManagedUnit(ctx, spec)
	if stillFailed.Process != nil {
		retained = append(retained, stillFailed.Process)
	}
	if err != nil || !managedTerminalFailure(stillFailed) {
		t.Fatalf("stop did not demonstrate the retained failed-unit condition: %v", err)
	}
	// Exercise the exact production reset/collection primitive used by both
	// managed Remove and controlled Start, including its second full policy
	// and dependency admission and strict unloaded readback.
	if err := resetFailedManagedUnit(ctx, spec); err != nil {
		t.Fatalf("verified terminal managed collection failed: %v", err)
	}
	vacant, err := inspectManagedUnit(ctx, spec)
	if vacant.Process != nil {
		retained = append(retained, vacant.Process)
	}
	if err != nil || vacant.Loaded {
		t.Fatalf("terminal collection did not independently prove unit vacancy: %v", err)
	}
	// The old transient definition is gone. Recovery must send the canonical
	// full definition again; systemctl start on the old name is insufficient.
	if err := startManagedUnit(ctx, spec); err != nil {
		t.Fatalf("canonical managed recreation after terminal collection failed: %v", err)
	}
	recovered, err := inspectManagedUnit(ctx, spec)
	if recovered.Process != nil {
		retained = append(retained, recovered.Process)
	}
	if err != nil || !recovered.Active || recovered.Process == nil ||
		recovered.Process.Observation.InvocationID == restarted.Process.Observation.InvocationID ||
		recovered.Process.Observation.ExecutableDevice != uint64(executable.Dev) || recovered.Process.Observation.ExecutableInode != executable.Ino {
		t.Fatalf("recreated managed invocation was not independently verified: %v", err)
	}
	if _, err := managerCommand(ctx, "systemctl", "--system", "stop", spec.Name, "--no-pager"); err != nil {
		t.Fatalf("verified explicit managed stop failed: %v", err)
	}
	for {
		after, err := inspectManagedUnit(ctx, spec)
		if after.Process != nil {
			retained = append(retained, after.Process)
		}
		if err != nil {
			t.Fatalf("managed stop readback failed: %v", err)
		}
		if !after.Loaded {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("managed unit was not collected after explicit stop")
		case <-ticker.C:
		}
	}
	t.Log("managed canonical launch survived launcher exit; real journal environment, pidfd-bound restart, terminal start-limit retention, scoped reset with strict collection, canonical recreation and explicit stop verified")
}

func startDisposableManagedWithLimit(ctx context.Context, spec unitSpec) error {
	// Only this disposable fixture chooses a small deterministic start limit.
	// Reuse every production launch argument, especially CollectMode=inactive;
	// never add a drop-in or change a running unit's execution policy.
	args := append([]string{"--property=StartLimitIntervalSec=1min", "--property=StartLimitBurst=2"}, managedStartArguments(spec)...)
	_, err := managerCommand(ctx, "systemd-run", args...)
	return err
}

func waitDisposableManagedTerminalFailure(t *testing.T, ctx context.Context, spec unitSpec) managedUnitObservation {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		values, err := queryManagedUnit(ctx, spec.Name)
		if err != nil {
			t.Fatalf("terminal fixture manager readback failed: %v", err)
		}
		if err := verifyManagedUnitProperties(values, spec, false); err != nil {
			t.Fatalf("terminal fixture identity/policy drifted: %v", err)
		}
		if values["ActiveState"] == "failed" && values["SubState"] == "failed" {
			obs, err := inspectManagedUnit(ctx, spec)
			if obs.Process != nil {
				_ = obs.Process.Close()
			}
			if err != nil || !managedTerminalFailure(obs) {
				t.Fatalf("terminal fixture effective graph or identity could not be verified: %v", err)
			}
			return obs
		}
		select {
		case <-ctx.Done():
			t.Fatal("terminal fixture context expired")
		case <-deadline.C:
			t.Fatal("fixture did not reach its terminal start limit")
		case <-ticker.C:
		}
	}
}
