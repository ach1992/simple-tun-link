package main

import (
	"fmt"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// The guided sender path is deterministic: one protected receiver handoff
// per immutable Link ID, not a user-entered path likely to be forgotten.
func askPrivateHandoffPath(p createPrompts, options *runtimeOptions, id domain.LinkID) (string, error) {
	path, err := protectedMenuHandoffPath(options, id)
	if err != nil {
		return "", fmt.Errorf("cannot choose safe protected receiver file")
	}
	fmt.Fprintln(p.out, "The OTHER server's sensitive Setup Link will be kept securely by STL.")
	fmt.Fprintln(p.out, "Later use My tunnels -> Share Setup Link; no filename to remember.")
	return path, nil
}

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
		fmt.Fprintln(p.out, "Use a port number between 1 and 65535.")
	}
}
