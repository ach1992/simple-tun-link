package ipsec

import (
	"bytes"
	"fmt"
)

// NativeExclusiveConfigPath is the future private strongswan.conf identity.
// It is NOT installed or trusted merely because this path can be constructed.
// Future provisioning must verify every parent, inode, service unit, process,
// port, VICI socket and external writer before executing charon-systemd.
const NativeExclusiveConfigPath = "/var/lib/simple-tun-link/ipsec/strongswan.conf"

// NativeExclusiveVICIPath is the proposed STL-only Unix VICI endpoint.
// A matching socket pathname is not ownership proof or a no-clobber lock.
const NativeExclusiveVICIPath = "/run/simple-tun-link/ipsec/charon.vici"

// The proposed config uses STRONGSWAN_CONF to avoid inheriting the host's
// /etc/strongswan.conf and its includes. Its explicit journald CFG ceiling
// is intentionally below DBG4, which can disclose shared keys in VICI
// credential-loading traces on verified strongSwan versions. No
// filelog/syslog/custom logger or includes are declared.
// Config BYTES alone cannot attest an actual daemon's effective log policy:
// future operational admission additionally needs pinned process/service
// identity, a private writable boundary, and reload/change control.
const nativeExclusiveConfigV1 = `# simple-tun-link native-exclusive strongSwan profile v1
# No external configuration overlays. Not a daemon activation permit.
charon {
    install_routes = no
    install_virtual_ip = no
}
charon-systemd {
    install_routes = no
    install_virtual_ip = no
    journal {
        default = 1
        cfg = 1
    }
    plugins {
        vici {
            socket = unix:///run/simple-tun-link/ipsec/charon.vici
        }
    }
}
`

// NativeExclusiveConfigV1 returns a new copy of the bounded, reviewable
// daemon configuration. It never touches disk, systemd, VICI or the kernel.
func NativeExclusiveConfigV1() []byte {
	return []byte(nativeExclusiveConfigV1)
}

// CheckNativeExclusiveConfigV1 is a LOCAL byte-equivalence prerequisite,
// rejecting includes, injected loggers and CFG debug-policy drift. It is
// deliberately not called "effective logging attestation": a safe file on
// disk does not establish which config a running process loaded.
func CheckNativeExclusiveConfigV1(actual []byte) error {
	if !bytes.Equal(actual, []byte(nativeExclusiveConfigV1)) {
		return fmt.Errorf("native-exclusive strongSwan config differs from the reviewed secure profile")
	}
	return nil
}
