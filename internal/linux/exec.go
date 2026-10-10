package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultCommandTimeout = 10 * time.Second

// CommandResult keeps stdout and stderr separate so callers can parse expected
// machine output without turning arbitrary command text into a public error.
type CommandResult struct {
	Stdout []byte
	Stderr []byte
}

// Runner is the narrow process-execution seam used by Linux integration.
// Implementations receive a binary name and already-separated argv entries;
// callers must never build a shell command string from untrusted input.
type Runner interface {
	Run(context.Context, string, ...string) (CommandResult, error)
}

// FileRunner is an optional execution seam for tools needing validated file
// descriptors (not secret-bearing argv, stdin or temporary config paths).
// File descriptors are inherited as /proc/self/fd/3, /proc/self/fd/4, etc.
type FileRunner interface {
	Runner
	RunWithFiles(context.Context, string, []*os.File, ...string) (CommandResult, error)
}

// ExecRunner executes Linux tools directly with os/exec. Timeout applies only
// when the caller's context does not expire sooner.
type ExecRunner struct {
	Timeout time.Duration
}

// CommandError deliberately omits argv, stdout, and stderr from Error(). Later
// backends may handle credential material, so generic process failures must not
// accidentally reflect command arguments or tool output into logs/JSON.
type CommandError struct {
	Command  string
	ExitCode int
	TimedOut bool
	Canceled bool

	cause error
}

func (e *CommandError) Error() string {
	if e == nil {
		return ""
	}
	switch {
	case e.TimedOut:
		return fmt.Sprintf("command %q timed out", e.Command)
	case e.Canceled:
		return fmt.Sprintf("command %q canceled", e.Command)
	case e.ExitCode >= 0:
		return fmt.Sprintf("command %q failed with exit code %d", e.Command, e.ExitCode)
	default:
		return fmt.Sprintf("command %q failed", e.Command)
	}
}

func (e *CommandError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	return r.run(ctx, name, nil, args...)
}

func (r ExecRunner) RunWithFiles(ctx context.Context, name string, files []*os.File, args ...string) (CommandResult, error) {
	if len(files) > 4 {
		return CommandResult{}, fmt.Errorf("too many inherited command files")
	}
	for _, file := range files {
		if file == nil {
			return CommandResult{}, fmt.Errorf("invalid inherited command file")
		}
	}
	return r.run(ctx, name, files, args...)
}

func (r ExecRunner) run(ctx context.Context, name string, files []*os.File, args ...string) (CommandResult, error) {
	if ctx == nil {
		return CommandResult{}, fmt.Errorf("context is required")
	}
	if strings.TrimSpace(name) == "" {
		return CommandResult{}, fmt.Errorf("command name is required")
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.ExtraFiles = files
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := CommandResult{
		Stdout: append([]byte(nil), stdout.Bytes()...),
		Stderr: append([]byte(nil), stderr.Bytes()...),
	}
	if err == nil {
		return result, nil
	}

	commandErr := &CommandError{Command: name, ExitCode: -1}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		commandErr.ExitCode = exitErr.ExitCode()
	}

	if ctx.Err() != nil {
		commandErr.Canceled = true
		commandErr.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		commandErr.cause = errors.Join(err, ctx.Err())
		return result, commandErr
	}
	if runCtx.Err() != nil {
		commandErr.Canceled = true
		commandErr.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
		commandErr.cause = errors.Join(err, runCtx.Err())
		return result, commandErr
	}

	commandErr.cause = err
	return result, commandErr
}
