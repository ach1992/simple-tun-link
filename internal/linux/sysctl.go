package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

type interfaceSysctlRule struct {
	families map[string]bool
	values   map[string]bool
}

var allowedInterfaceSysctls = map[string]interfaceSysctlRule{
	"rp_filter": {
		families: map[string]bool{"ipv4": true},
		values:   map[string]bool{"0": true, "1": true, "2": true},
	},
	"disable_policy": {
		families: map[string]bool{"ipv4": true, "ipv6": true},
		values:   map[string]bool{"0": true, "1": true},
	},
	"disable_xfrm": {
		families: map[string]bool{"ipv4": true, "ipv6": true},
		values:   map[string]bool{"0": true, "1": true},
	},
}

type InterfaceSysctl struct {
	ProcRoot string
}

// Set changes exactly one per-interface sysctl and returns an undo function for
// the owned delta. Global pseudo-interfaces such as all/default are rejected.
func (s InterfaceSysctl) Set(ctx context.Context, family, ifName, name, value string) (func(context.Context) error, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if family != "ipv4" && family != "ipv6" {
		return nil, false, fmt.Errorf("unsupported sysctl family %q", family)
	}
	if err := validateInterfaceSegment(ifName); err != nil {
		return nil, false, err
	}
	if ifName == "all" || ifName == "default" {
		return nil, false, fmt.Errorf("global sysctl pseudo-interface %q is not allowed", ifName)
	}
	rule, ok := allowedInterfaceSysctls[name]
	if !ok {
		return nil, false, fmt.Errorf("unsupported per-interface sysctl %q", name)
	}
	if !rule.families[family] {
		return nil, false, fmt.Errorf("sysctl %q is not supported for family %q", name, family)
	}
	if !rule.values[value] {
		return nil, false, fmt.Errorf("unsupported value for per-interface sysctl %q", name)
	}
	root := s.ProcRoot
	if root == "" {
		root = "/proc/sys"
	}
	path := filepath.Join(root, "net", family, "conf", ifName, name)
	originalBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read per-interface sysctl: %w", err)
	}
	original := strings.TrimSpace(string(originalBytes))
	if original == value {
		return func(context.Context) error { return nil }, false, nil
	}
	if err := writeSysctlValue(ctx, path, value); err != nil {
		return nil, false, err
	}
	undo := func(undoCtx context.Context) error {
		return writeSysctlValue(undoCtx, path, original)
	}
	return undo, true, nil
}

func validateInterfaceSegment(name string) error {
	if !interfaceNamePattern.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("invalid interface name")
	}
	return nil
}

func writeSysctlValue(ctx context.Context, path, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("open per-interface sysctl: %w", err)
	}
	_, writeErr := file.WriteString(value)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write per-interface sysctl: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close per-interface sysctl: %w", closeErr)
	}
	return nil
}
