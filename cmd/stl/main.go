package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"github.com/ach1992/simple-tun-link/internal/version"
)

const usage = "simple-tun-link (stl)\n\nUsage:\n  stl help\n  stl version [--json]\n  stl link list [--json]\n  stl link status <link-id> [--json]\n  stl link diagnose <link-id> [--mtu <bytes>] [--json]\n  stl link preview --stdin [--json]\n  stl link import --stdin --confirm <preview-token> [--json]\n  stl link export <link-id> [--json]\n  stl link ensure --stdin [--json]\n  stl link remove <link-id> --confirm <link-id> [--json]\n  stl link restore --all\n\nAdditional Link commands will be added through tracked GitHub Issues.\n"

const jsonSchemaVersion = 1

// Leave room for orderly, bounded owned rollback before systemd's 35-minute
// oneshot startup ceiling (see the generated restore unit).
const restoreOperationTimeout = 30 * time.Minute

type runtimeOptions struct {
	stateRoot          string
	backends           []backend.Backend
	probeRunner        linux.Runner
	restorePersistence app.RestorePersistence
	executable         string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithRuntime(args, stdout, stderr, nil)
}

// runWithRuntime keeps the production CLI and tests on the same assembly path.
// Broader lifecycle CLI/JSON ergonomics belong to Issue #10.
func runWithRuntime(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	return runWithRuntimeInput(args, os.Stdin, stdout, stderr, options)
}

// Stdin is explicit for data-only desired Link JSON and for sensitive,
// read-only pairing previews. Existing Engine/restore paths remain shared.
func runWithRuntimeInput(args []string, input io.Reader, stdout, stderr io.Writer, options *runtimeOptions) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[0] {
	case "version":
		if len(args) == 2 && args[1] == "--json" {
			payload := struct {
				SchemaVersion int    `json:"schema_version"`
				Version       string `json:"version"`
				Commit        string `json:"commit"`
				Date          string `json:"date"`
			}{
				SchemaVersion: jsonSchemaVersion,
				Version:       version.Version,
				Commit:        version.Commit,
				Date:          version.Date,
			}
			if err := json.NewEncoder(stdout).Encode(payload); err != nil {
				fmt.Fprintf(stderr, "encode version: %v\n", err)
				return 1
			}
			return 0
		}
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: stl version [--json]")
			return 2
		}
		fmt.Fprintf(stdout, "stl %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return 0
	case "link":
		if len(args) >= 2 && (args[1] == "list" || args[1] == "status") {
			return linkReadCommand(args[1:], stdout, stderr, options)
		}
		if len(args) >= 2 && args[1] == "diagnose" {
			return linkDiagnoseCommand(args[1:], stdout, stderr, options)
		}
		if len(args) >= 2 && (args[1] == "ensure" || args[1] == "remove") {
			return linkLifecycleCommand(args[1:], input, stdout, stderr, options)
		}
		if len(args) >= 2 && args[1] == "preview" {
			return linkPreviewCommand(args[1:], input, stdout, stderr)
		}
		if len(args) >= 2 && args[1] == "import" {
			return linkImportCommand(args[1:], input, stdout, stderr, options)
		}
		if len(args) >= 2 && args[1] == "export" {
			return linkExportCommand(args[1:], stdout, stderr, options)
		}
		if len(args) != 3 || args[1] != "restore" || args[2] != "--all" {
			fmt.Fprintln(stderr, "usage: stl link restore --all")
			return 2
		}
		if options == nil {
			var err error
			options, err = productionRuntimeOptions()
			if err != nil {
				fmt.Fprintln(stderr, "restore runtime unavailable")
				return 1
			}
		}
		ctx, cancel := restoreRunContext()
		defer cancel()
		return restoreWithContext(ctx, *options, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// Assemble the same registered backends for restore and normal lifecycle CLI.
// Missing backends fail explicitly, not silently.
func productionRuntimeOptions() (*runtimeOptions, error) {
	options := &runtimeOptions{stateRoot: state.DefaultRoot}
	runner := linux.ExecRunner{}
	locks := state.NewLockManager(options.stateRoot)
	routes := linux.RouteResolver{Runner: runner}
	firewall := linux.IPTablesFirewall{Runner: runner, Locks: locks}
	collisions := linux.CollisionInspector{Snapshotter: linux.HostSnapshotter{Runner: runner}}
	gre, err := grebackend.New(grebackend.Options{
		Runner: runner, Routes: routes, Firewall: firewall, Collisions: collisions,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize GRE backend: %w", err)
	}
	ipip, err := ipipbackend.New(ipipbackend.Options{
		Runner: runner, Routes: routes, Firewall: firewall, Collisions: collisions,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize IPIP backend: %w", err)
	}
	options.backends = []backend.Backend{gre, ipip}

	info, err := os.Stat("/run/systemd/system")
	switch {
	case err == nil && info.IsDir():
		executable, execErr := os.Executable()
		if execErr != nil {
			return nil, fmt.Errorf("locate STL executable: %w", execErr)
		}
		executable, execErr = canonicalSTLExecutable(executable)
		if execErr != nil {
			return nil, execErr
		}
		options.restorePersistence = linux.SystemdPersistence{Runner: linux.ExecRunner{}}
		options.executable = executable
	case errors.Is(err, os.ErrNotExist):
		// Manual restore is still available without systemd.
	case err != nil:
		return nil, fmt.Errorf("inspect systemd availability: %w", err)
	default:
		return nil, fmt.Errorf("invalid systemd runtime directory")
	}
	return options, nil
}

func buildRuntimeEngine(options runtimeOptions) (*app.Engine, error) {
	if options.stateRoot == "" {
		return nil, fmt.Errorf("state root is required")
	}
	registry, err := backend.NewRegistry(options.backends...)
	if err != nil {
		return nil, err
	}
	store := state.NewFileStore(options.stateRoot)
	locks := state.NewLockManager(options.stateRoot)
	if options.restorePersistence != nil {
		return app.NewWithRestorePersistence(registry, store, locks, options.restorePersistence, options.executable)
	}
	return app.New(registry, store, locks)
}

// An installer may expose the same executable under the stlink convenience
// alias. The owned unit must still reference the canonical installed stl
// identity, never a different or unproven sibling executable.
func canonicalSTLExecutable(executable string) (string, error) {
	if !filepath.IsAbs(executable) {
		return "", fmt.Errorf("STL executable path must be absolute")
	}
	if filepath.Base(executable) == "stl" {
		return executable, nil
	}
	canonical := filepath.Join(filepath.Dir(executable), "stl")
	source, err := os.Stat(executable)
	if err != nil {
		return "", fmt.Errorf("inspect executable identity: %w", err)
	}
	target, err := os.Stat(canonical)
	if err != nil || !os.SameFile(source, target) {
		return "", fmt.Errorf("restore requires a durable canonical stl executable beside its alias")
	}
	return canonical, nil
}

// Systemd sends SIGTERM when the service is stopped/times out. Deliver the
// signal as graceful Engine cancellation rather than interrupting host-state
// cleanup, and bound ordinary restores independently of systemd.
func restoreRunContext() (context.Context, context.CancelFunc) {
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(signalCtx, restoreOperationTimeout)
	return ctx, func() { cancel(); stop() }
}

func restoreWithContext(ctx context.Context, options runtimeOptions, stdout, stderr io.Writer) int {
	engine, err := buildRuntimeEngine(options)
	if err != nil {
		fmt.Fprintln(stderr, "cannot initialize restore runtime")
		return 1
	}
	results, err := engine.RestoreAll(ctx)
	if err != nil {
		// Report partial progress, but keep backend/command causes secret-safe.
		fmt.Fprintf(stderr, "restore failed after %d link(s): %v\n", len(results), stlerr.Public(err))
		return 1
	}
	fmt.Fprintf(stdout, "restored %d link(s)\n", len(results))
	return 0
}
