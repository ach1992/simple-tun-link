package linux

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// WSSGlobalWGKernelVacant proves that no kernel WireGuard interface holds
// either a protected WSS Link public key or its UDP listen port. All three
// independent, bounded wg inventories must agree on the exact interface set.
// This is the last fail-closed gate for EVERY owned WSS nft guard deletion.
// It does not prove resource ownership, and it must run after helper/kernel
// retirement and immediately before the nft delete transaction.
func WSSGlobalWGKernelVacant(ctx context.Context, runner BoundedRunner, wgBinary, publicKey string, port uint16) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if wgBinary == "" || port == 0 || !validWSSWGPublicKey(publicKey) {
		return false, fmt.Errorf("invalid WSS WG guard vacancy identity")
	}
	probe := func(args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, err := runner.RunBounded(ctx,
			CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10}, wgBinary, args...)
		if err != nil || ctx.Err() != nil || len(out.Stdout) > 1<<20 || len(out.Stderr) > 64<<10 {
			return nil, fmt.Errorf("global WG inventory incomplete or canceled")
		}
		return out.Stdout, nil
	}
	namesRaw, err := probe("show", "interfaces")
	if err != nil {
		return false, err
	}
	names := make(map[string]struct{})
	for _, name := range strings.Fields(string(namesRaw)) {
		if !validWSSWGInterfaceName(name) {
			return false, fmt.Errorf("malformed global WG interface inventory")
		}
		if _, exists := names[name]; exists {
			return false, fmt.Errorf("duplicate global WG interface identity")
		}
		names[name] = struct{}{}
	}
	occupied := false
	for _, field := range []string{"public-key", "listen-port"} {
		raw, err := probe("show", "all", field)
		if err != nil {
			return false, err
		}
		seen := make(map[string]struct{}, len(names))
		if strings.TrimSpace(string(raw)) != "" {
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				parts := strings.Fields(line)
				if len(parts) != 2 || !validWSSWGInterfaceName(parts[0]) {
					return false, fmt.Errorf("malformed global WG %s inventory", field)
				}
				if _, exists := names[parts[0]]; !exists {
					return false, fmt.Errorf("unknown global WG %s interface", field)
				}
				if _, exists := seen[parts[0]]; exists {
					return false, fmt.Errorf("duplicate global WG %s interface", field)
				}
				seen[parts[0]] = struct{}{}
				switch field {
				case "public-key":
					if parts[1] != "(none)" && !validWSSWGPublicKey(parts[1]) {
						return false, fmt.Errorf("malformed global WG public key")
					}
					occupied = occupied || parts[1] == publicKey
				case "listen-port":
					if parts[1] == "off" {
						break
					}
					number, err := strconv.ParseUint(parts[1], 10, 16)
					if err != nil || strconv.FormatUint(number, 10) != parts[1] {
						return false, fmt.Errorf("malformed global WG listen port")
					}
					occupied = occupied || uint16(number) == port
				}
			}
		}
		if len(seen) != len(names) {
			return false, fmt.Errorf("incomplete global WG %s inventory", field)
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return !occupied, nil
}

func validWSSWGInterfaceName(name string) bool {
	return len(name) > 0 && len(name) <= 15 && !strings.ContainsAny(name, " /:\x00\r\n\t")
}

func validWSSWGPublicKey(key string) bool {
	if len(key) != 44 {
		return false
	}
	data, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(data) != 32 || base64.StdEncoding.EncodeToString(data) != key {
		return false
	}
	for _, b := range data {
		if b != 0 {
			return true
		}
	}
	return false
}
