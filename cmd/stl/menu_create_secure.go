package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"unicode"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func askPortDefault(p createPrompts, prompt string, fallback uint16) (uint16, error) {
	for {
		input, err := p.ask(prompt)
		if err != nil {
			return 0, err
		}
		if input == "" {
			return fallback, nil
		}
		value, err := strconv.ParseUint(input, 10, 16)
		if err == nil && value != 0 {
			return uint16(value), nil
		}
		fmt.Fprintln(p.out, "Use a UDP port number between 1 and 65535.")
	}
}

func askPrivateHandoffPath(p createPrompts, options *runtimeOptions, id domain.LinkID) (string, error) {
	// On real root-operated hosts the private handoff belongs under
	// /root, NOT the parent of State (/var/lib), which is usually 0755
	// and must never be used as a private receiver-credential directory.
	parent := "/root"
	if os.Geteuid() != 0 && options != nil && options.stateRoot != "" {
		// Non-root isolated tests/development may use their own private
		// temporary directory. The final trusted-parent preflight below
		// still rejects any unwritable/unsafe directory.
		parent = filepath.Dir(options.stateRoot)
	}
	suggested := filepath.Join(parent, "stl-setup-"+string(id)+".txt")
	for {
		fmt.Fprintln(p.out, "The OTHER server will receive a private one-time setup file.")
		fmt.Fprintf(p.out, "Save it here by default: %s\n", suggested)
		value, err := p.ask("Press Enter to use this path, or enter a different private absolute filename (q=back): ")
		if err != nil {
			return "", err
		}
		if value == "" {
			value = suggested
		}
		if len(value) > menuInputLimit || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
			fmt.Fprintln(p.out, "Use a full absolute filename inside a private directory (for example /root/stl-setup.txt).")
			continue
		}
		control := false
		for _, r := range value {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				control = true
				break
			}
		}
		if control {
			fmt.Fprintln(p.out, "Filename contains unsupported characters.")
			continue
		}
		if err := checkSensitiveHandoffDestination(value); err != nil {
			fmt.Fprintln(p.out, "That filename cannot be safely used. Choose a new file inside a private 0700-owned directory.")
			continue
		}
		return value, nil
	}
}
