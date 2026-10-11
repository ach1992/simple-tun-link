package linux

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerPassesArgumentsWithoutShellInterpolation(t *testing.T) {
	runner := ExecRunner{Timeout: time.Second}
	literal := `one; echo SHOULD-NOT-RUN $HOME $(id)`
	result, err := runner.Run(context.Background(), "/bin/echo", literal)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(result.Stdout)); got != literal {
		t.Fatalf("stdout = %q, want literal argument %q", got, literal)
	}
}

func TestExecRunnerTimeoutIsContextAware(t *testing.T) {
	runner := ExecRunner{Timeout: 20 * time.Millisecond}
	_, err := runner.Run(context.Background(), "/bin/sleep", "1")
	if err == nil {
		t.Fatal("expected timeout")
	}
	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("error type = %T, want *CommandError", err)
	}
	if !commandErr.TimedOut || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout classification = %#v; err=%v", commandErr, err)
	}
}

func TestCommandErrorDoesNotEchoArgumentsOrStderr(t *testing.T) {
	runner := ExecRunner{Timeout: time.Second}
	secretPath := "/definitely-not-present/PRIVATE-CONTENT"
	result, err := runner.Run(context.Background(), "/bin/ls", secretPath)
	if err == nil {
		t.Fatal("expected command failure")
	}
	if !strings.Contains(string(result.Stderr), "PRIVATE-CONTENT") {
		t.Fatalf("test command did not produce expected stderr: %q", result.Stderr)
	}
	if strings.Contains(err.Error(), "PRIVATE-CONTENT") || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("public error leaked arguments/stderr: %q", err)
	}
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.ExitCode <= 0 {
		t.Fatalf("command error = %#v, want positive exit code", commandErr)
	}
}

// An untrusted command may emit far more data than its diagnostic can parse.
// Verify the subprocess capture boundary, not merely a parser fed a large
// preallocated slice. Both stdout and stderr must be independently bounded.
func TestExecRunnerBoundedCaptureStopsOversizedProcessOutput(t *testing.T) {
	runner := ExecRunner{Timeout: 3 * time.Second}
	cases := []struct {
		name   string
		script string
	}{
		{"stdout", "head -c 200000 /dev/zero"},
		{"stderr", "head -c 200000 /dev/zero >&2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			result, err := runner.RunBounded(context.Background(), CaptureLimits{Stdout: 4096, Stderr: 1024},
				"/bin/sh", "-c", tc.script)
			if !errors.Is(err, ErrOutputLimit) {
				t.Fatalf("oversized stream was not rejected by capture boundary: %v", err)
			}
			if len(result.Stdout) != 0 || len(result.Stderr) != 0 {
				t.Fatal("overflow leaked partial command output")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("oversized output did not cause prompt subprocess termination")
			}
			if strings.Contains(err.Error(), "/dev/zero") {
				t.Fatal("command error exposed argv")
			}
		})
	}
}

func TestExecRunnerBoundedCaptureAcceptsExactLimits(t *testing.T) {
	runner := ExecRunner{Timeout: time.Second}
	result, err := runner.RunBounded(context.Background(), CaptureLimits{Stdout: 5, Stderr: 4},
		"/bin/sh", "-c", "printf 12345; printf abcd >&2")
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "12345" || string(result.Stderr) != "abcd" {
		t.Fatalf("unexpected bounded streams: %q %q", result.Stdout, result.Stderr)
	}
	for _, limits := range []CaptureLimits{{}, {Stdout: -1, Stderr: 2}, {Stdout: 5}} {
		if _, err := runner.RunBounded(context.Background(), limits, "/bin/echo", "unsafe"); err == nil {
			t.Fatal("accepted a missing/invalid capture limit")
		}
	}
}
