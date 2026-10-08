package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"github.com/ach1992/simple-tun-link/internal/version"
)

const usage = "simple-tun-link (stl)\n\nUsage:\n  stl help\n  stl version [--json]\n  stl link restore --all\n\nAdditional Link commands will be added through tracked GitHub Issues.\n"

const jsonSchemaVersion = 1

type runtimeOptions struct {
	stateRoot          string
	backends           []backend.Backend
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
		engine, err := buildRuntimeEngine(*options)
		if err != nil {
			fmt.Fprintln(stderr, "cannot initialize restore runtime")
			return 1
		}
		results, err := engine.RestoreAll(context.Background())
		if err != nil {
			// Never emit sensitive backend/command causes; report partial progress.
			fmt.Fprintf(stderr, "restore failed after %d link(s): %v\n", len(results), stlerr.Public(err))
			return 1
		}
		fmt.Fprintf(stdout, "restored %d link(s)\n", len(results))
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// When real backend adapters land, register them here for restore and for
// the normal lifecycle CLI. Missing backends fail explicitly, not silently.
func productionRuntimeOptions() (*runtimeOptions, error) {
	options := &runtimeOptions{stateRoot: state.DefaultRoot}
	info, err := os.Stat("/run/systemd/system")
	switch {
	case err == nil && info.IsDir():
		executable, execErr := os.Executable()
		if execErr != nil {
			return nil, fmt.Errorf("locate STL executable: %w", execErr)
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
