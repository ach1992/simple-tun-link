package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
)

// Internal-only helper entrypoint for a single Engine-supervised dial role.
// Secrets are read from a root-only config file and never accepted in argv.
// This command is deliberately absent from general operator help until the
// complete managed Carrier, including the listener, passes acceptance.
func masqueHelperCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 3 || (args[0] != "dial" && args[0] != "listen") || args[1] != "--config" || args[2] == "" {
		fmt.Fprintln(stderr, "usage: stl masque-helper dial|listen --config <protected-file>")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "MASQUE helper requires selected privileged service execution")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "dial":
		var config masque.DialAgentConfig
		config, err = masque.ReadProtectedAgentConfig(args[2])
		if err == nil {
			err = masque.RunDialAgent(ctx, config)
		}
	case "listen":
		var config masque.ListenAgentConfig
		config, err = masque.ReadProtectedListenConfig(args[2])
		if err == nil {
			err = masque.RunListenAgent(ctx, config)
		}
	}
	if err != nil {
		// The operator-visible stage is preserved without disclosing any
		// secret bytes from the protected configuration or private key.
		fmt.Fprintf(stderr, "MASQUE helper failure: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "MASQUE helper stopped")
	return 0
}
