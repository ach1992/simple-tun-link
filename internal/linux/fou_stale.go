package linux

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// VacantFOUDevice recognizes iproute2's exact "ifNN" rendering for an
// FOU/GUE mapping whose original bound interface index no longer exists.
// Never treat an arbitrary device name as stale. Both the old numeric index
// and the literal name must be vacant: iproute2 accepts "dev ifNN" as that
// index, but a new actual interface called ifNN would change its meaning.
func VacantFOUDevice(name string) (bool, error) {
	if !strings.HasPrefix(name, "if") {
		return false, nil
	}
	index, err := strconv.Atoi(strings.TrimPrefix(name, "if"))
	if err != nil || index <= 0 || name != "if"+strconv.Itoa(index) {
		return false, nil
	}
	current, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("cannot verify vacant FOU interface index: %w", err)
	}
	for _, iface := range current {
		if iface.Index == index || iface.Name == name {
			return false, nil
		}
	}
	return true, nil
}
