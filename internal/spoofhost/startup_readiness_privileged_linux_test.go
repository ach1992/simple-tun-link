//go:build linux

package spoofhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// Run only in explicitly opted-in private mount and network namespaces with a
// fresh sysfs mount: plain unshare --net leaves /sys/class/net on the host netns.
// Allow loopback and only the checked DOWN/addressless kernel GRE templates,
// with no main-table IPv4 routes. The test creates one nonpersistent TUN and
// its private route inside that namespace; it sends no packets.
func TestPrivilegedSpoofTUNReadinessWaitsForPeerRoute(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("STL_SPOOF_STARTUP_ACCEPTANCE") != "1" {
		t.Skip("requires root and explicit disposable network namespace opt-in")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == initial {
		t.Fatalf("requires a network namespace separate from PID 1: %v", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	loopbackSeen := false
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			loopbackSeen = true
			continue
		}
		// Already loaded GRE modules create these unconnected fallback
		// devices in each new netns. No other non-loopback NIC is allowed.
		if (iface.Name != "gre0" && iface.Name != "gretap0" && iface.Name != "erspan0") || iface.Flags&net.FlagUp != 0 {
			t.Fatalf("unexpected or UP non-loopback interface: %s", iface.Name)
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) != 0 {
			t.Fatalf("kernel fallback %s must have no addresses: %v, %v", iface.Name, addrs, err)
		}
	}
	if !loopbackSeen {
		t.Fatal("disposable namespace must contain loopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runIP := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "/usr/bin/ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture ip %v: %v: %s", args, err, out)
		}
		return out
	}
	var routes []json.RawMessage
	if err := json.Unmarshal(runIP("-4", "-json", "route", "show", "table", "main"), &routes); err != nil || len(routes) != 0 {
		t.Fatalf("requires an empty main IPv4 route table: %v, %v", routes, err)
	}
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	link := domain.Link{ID: id, Backend: domain.BackendSpoof, Addresses: domain.LinkAddresses{
		Local: netip.MustParsePrefix("10.245.219.1/32"),
		Peer:  netip.MustParsePrefix("10.245.219.2/32"),
	}}
	name, err := carrier.TunnelName(id)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close namespace-local nonpersistent TUN: %v", err)
		}
	})
	request, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatal(err)
	}
	request.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		t.Fatal(err)
	}
	runIP("link", "set", "dev", name, "alias", "stl:spoof:"+string(id))
	runIP("addr", "add", link.Addresses.Local.String(), "dev", name)
	runIP("link", "set", "dev", name, "up")
	if _, err := os.Lstat("/sys/class/net/" + name); err != nil {
		t.Fatalf("fixture needs a fresh sysfs mount in its private mount/network namespaces: %v", err)
	}

	// Reproduce the real setup window: the owned TUN is configured, but
	// OpenPrivateTUN has not yet issued its final peer-route add command.
	host := &Host{}
	exists, owned, addressReady, peerRoute, err := host.inspectTUN(ctx, link)
	if err != nil || !exists || !owned || !addressReady || peerRoute {
		t.Errorf("TUN awaiting peer route must remain pending: exists=%t owned=%t address=%t route=%t err=%v",
			exists, owned, addressReady, peerRoute, err)
	}
	runIP("route", "add", link.Addresses.Peer.String(), "dev", name, "scope", "link", "src", link.Addresses.Local.Addr().String())
	exists, owned, addressReady, peerRoute, err = host.inspectTUN(ctx, link)
	if err != nil || !exists || !owned || !addressReady || !peerRoute {
		t.Fatalf("TUN must become ready after its peer route appears: exists=%t owned=%t address=%t route=%t err=%v",
			exists, owned, addressReady, peerRoute, err)
	}
	t.Log("owned TUN and exact private peer route became ready")

	// A cancelled inspection is an actual execution failure, not route absence.
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, _, _, _, err := host.inspectTUN(cancelled, link); err == nil {
		t.Fatal("cancelled route inspection must remain an error")
	}
}

func TestSpoofPeerRouteReadinessPreservesFailures(t *testing.T) {
	exitFailure := func(code int) error {
		t.Helper()
		err := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", code)).Run()
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != code {
			t.Fatalf("prepare command exit status %d: %v", code, err)
		}
		return fmt.Errorf("route command failed: %w", err)
	}
	exitTwo, exitOne := exitFailure(2), exitFailure(1)
	const unreachable = "RTNETLINK answers: Network is unreachable\n"
	for _, tc := range []struct {
		name    string
		output  string
		cause   error
		wantErr bool
	}{
		{"pending route", unreachable, exitTwo, false},
		{"permission denied", "RTNETLINK answers: Operation not permitted\n", exitTwo, true},
		{"unrelated route error", "Error: inet prefix is expected\n", exitTwo, true},
		{"different exit status", unreachable, exitOne, true},
		{"missing executable", unreachable, &os.PathError{Op: "fork/exec", Path: "/usr/bin/ip", Err: os.ErrNotExist}, true},
		{"nonexecutable command", unreachable, &os.PathError{Op: "fork/exec", Path: "/usr/bin/ip", Err: os.ErrPermission}, true},
		{"cancelled command", unreachable, context.Canceled, true},
		{"malformed JSON", "{", nil, true},
		{"empty successful JSON", "[]", nil, true},
		{"ambiguous successful JSON", "[{},{}]", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := privatePeerRouteReady([]byte(tc.output), tc.cause, "stlsfixture", netip.MustParseAddr("10.245.219.1"))
			if ready || (err != nil) != tc.wantErr {
				t.Fatalf("ready=%t err=%v; want not-ready and error=%t", ready, err, tc.wantErr)
			}
			if tc.wantErr && tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("original command failure lost: got %v, want %v", err, tc.cause)
			}
		})
	}
}
