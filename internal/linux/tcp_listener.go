package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// TCPListenerProbe is a fail-closed, passive reservation probe for a future
// individually owned WSS listener. It conservatively treats a TCP port as
// exclusive host-wide (including v4/v6 wildcard listeners), so two STL
// Links may not claim the same port just because their bind IPs differ.
// It does not confer removal/ownership authority over arbitrary processes.
type TCPListenerProbe struct {
	Runner   Runner
	SSBinary string
}

func (p TCPListenerProbe) InspectResource(ctx context.Context, claim domain.ResourceClaim) ([]ObservedResource, error) {
	if claim.Kind != domain.ResourceTCPListenPort {
		return nil, fmt.Errorf("TCP listener probe requires a tcp-listen-port claim")
	}
	if err := claim.Validate(); err != nil {
		return nil, err
	}
	if p.Runner == nil {
		return nil, fmt.Errorf("TCP listener inspector is unavailable")
	}
	binary := p.SSBinary
	if binary == "" {
		binary = "ss"
	}
	r, err := p.Runner.Run(ctx, binary, "-H", "-t", "-l", "-n")
	if err != nil {
		return nil, fmt.Errorf("cannot inspect TCP listener reservations: %w", err)
	}
	ports, err := parseTCPListeners(string(r.Stdout))
	if err != nil {
		return nil, err
	}
	n, _ := strconv.ParseUint(claim.Key, 10, 16)
	if _, exists := ports[uint16(n)]; exists {
		return []ObservedResource{{Claim: claim, Source: "ss-tcp"}}, nil
	}
	return nil, nil
}

// parseTCPListeners inspects only LISTEN sockets. A surprising or malformed
// ss output cannot be treated as proof a port is unused.
func parseTCPListeners(text string) (map[uint16]struct{}, error) {
	ports := make(map[uint16]struct{})
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			return nil, fmt.Errorf("unrecognized ss TCP listener row")
		}
		local := fields[3]
		colon := strings.LastIndexByte(local, ':')
		if colon < 0 || colon == len(local)-1 {
			return nil, fmt.Errorf("invalid TCP listener endpoint")
		}
		number := local[colon+1:]
		port, err := strconv.ParseUint(number, 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != number {
			return nil, fmt.Errorf("invalid TCP listener port")
		}
		ports[uint16(port)] = struct{}{}
	}
	return ports, nil
}
