package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ach1992/simple-tun-link/internal/version"
)

const usage = "simple-tun-link (stl)\n\nUsage:\n  stl help\n  stl version [--json]\n\nTunnel commands will be added through tracked GitHub Issues.\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[0] {
	case "version":
		if len(args) == 2 && args[1] == "--json" {
			payload := map[string]string{
				"version": version.Version,
				"commit":  version.Commit,
				"date":    version.Date,
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
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
