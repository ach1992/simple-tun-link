package linux

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// WSSGlobalWGKernelVacant combines namespace-local WireGuard interface
// inventories with the socket inventory of the CALLING (nft-guard) network
// namespace. WireGuard interfaces can migrate to another namespace while
// their ciphertext UDP socket remains in their birthplace namespace:
// 'wg show all' in the birthplace namespace cannot see those interfaces.
// Requiring a separate complete UDP socket census there prevents a live
// migrated interface from making the protective guard look disposable.
// All checks fail closed and run immediately before guard removal or
// crash/credential vacancy reconciliation. No interface-name lookup alone
// proves global host absence, provenance or authority to delete a socket.
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
		if err != nil || ctx.Err() != nil || len(out.Stdout) > 1<<20 || len(out.Stderr) != 0 {
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
					// wireguard-tools show.c prints a decimal uint16, even
					// for an unconfigured interface (0). "off" is a fwmark
					// representation, not a valid listen-port inventory.
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
	// A moved kernel WireGuard interface is invisible to every 'wg show'
	// inventory above, yet its *active UDP socket* is still in the original
	// guard namespace. Never infer protected port vacancy from wg interface
	// enumeration alone. ss uses kernel socket diagnostics in this namespace
	// (both IPv4 and IPv6); any listener at the protected port blocks deletion,
	// whether WireGuard or foreign. A failure, stderr diagnostic, truncation
	// or malformed row is UNKNOWN, not vacant.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	sockets, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10},
		"ss", "-H", "-u", "-l", "-n")
	if err != nil || ctx.Err() != nil || len(sockets.Stdout) > 1<<20 ||
		len(sockets.Stderr) != 0 {
		return false, fmt.Errorf("guard-namespace UDP socket inventory incomplete or canceled")
	}
	ports, err := parseUDPListeners(string(sockets.Stdout))
	if err != nil {
		return false, fmt.Errorf("guard-namespace UDP socket inventory malformed")
	}
	if _, used := ports[port]; used {
		occupied = true
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

// QUICWGAllStateUDPPortVacant is read-only. A prior journal-time vacancy
// cannot attest a socket at the actual effect boundary. Connected UDP
// sockets must be included, not just listeners from ss -l. Any diagnostic,
// malformed row or canceled inventory is UNKNOWN, never empty.
func QUICWGAllStateUDPPortVacant(ctx context.Context, runner BoundedRunner, port uint16) (bool, error) {
	if ctx == nil || runner == nil || port == 0 || ctx.Err() != nil {
		return false, fmt.Errorf("current QUIC UDP socket inventory requires valid inputs")
	}
	out, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 1 << 20, Stderr: 64 << 10}, "ss", "-H", "-u", "-a", "-n")
	if err != nil || ctx.Err() != nil || len(out.Stdout) > 1<<20 || len(out.Stderr) != 0 {
		return false, fmt.Errorf("current QUIC UDP socket inventory incomplete or unavailable")
	}
	ports, err := parseUDPListeners(string(out.Stdout))
	if err != nil {
		return false, fmt.Errorf("current QUIC UDP socket inventory malformed")
	}
	_, occupied := ports[port]
	return !occupied, nil
}
