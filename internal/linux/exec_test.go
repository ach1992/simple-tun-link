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
