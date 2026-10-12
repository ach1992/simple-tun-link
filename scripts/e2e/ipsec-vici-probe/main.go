// The isolated IPsec proof tool runs only in the disposable E2E container.
// It never performs host service/package/network admission or production writes.
package main

import (
	"context"
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/strongswan/govici/vici"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "IPSEC_LAB_ERROR:", err)
		os.Exit(1)
	}
}
func run() error {
	// This helper can issue effectful VICI commands. It is intentionally
	// unusable against a real daemon or the host's VICI socket.
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" {
		return fmt.Errorf("isolated disposable lab authorization required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return fmt.Errorf("a disposable container is required")
	}
	if len(os.Args) != 6 {
		return fmt.Errorf("usage: vici-probe operation socket side esp|nat-t a|b")
	}
	op, socket, side, enc, suffix := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	if side != "a" && side != "b" {
		return fmt.Errorf("invalid side")
	}
	expectedSocket := "/run/stl-ipsec-proof/" + side + ".vici"
	if filepath.Clean(socket) != expectedSocket {
		return fmt.Errorf("VICI endpoint is outside the disposable lab")
	}
	if enc != "esp" && enc != "nat-t" {
		return fmt.Errorf("invalid encapsulation")
	}
	if suffix != "a" && suffix != "b" {
		return fmt.Errorf("only named disposable lab links permitted")
	}
	a := side == "a"
	ua, ub := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	la, lb := netip.MustParsePrefix("10.251.88.0/31"), netip.MustParsePrefix("10.251.88.1/31")
	if suffix == "b" {
		la, lb = netip.MustParsePrefix("10.251.88.2/31"), netip.MustParsePrefix("10.251.88.3/31")
	}
	if !a {
		ua, ub = ub, ua
		la, lb = lb, la
	}
	p, err := ipsec.NewProfile(domain.Link{ID: domain.LinkID("lnk_" + strings.Repeat(suffix, 32)), Underlay: domain.Underlay{Local: ua, Peer: ub}, Addresses: domain.LinkAddresses{Local: la, Peer: lb}, Backend: domain.BackendIPsec, Encapsulation: domain.Encapsulation(enc)})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	stat, err := os.Lstat(socket)
	if err != nil || stat.Mode()&os.ModeSocket == 0 || stat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("the expected lab VICI socket is unavailable")
	}
	sess, err := vici.NewSession(vici.WithAddr("unix", socket))
	if err != nil {
		return fmt.Errorf("VICI unavailable")
	}
	defer sess.Close()
	call := func(command string, message *vici.Message) error {
		reply, e := sess.Call(ctx, command, message)
		if e != nil || reply == nil {
			return fmt.Errorf("%s command unavailable", command)
		}
		if v, ok := reply.Get("success").(string); !ok || v != "yes" {
			return fmt.Errorf("%s returned failure", command)
		}
		return nil
	}
	switch op {
	case "load":
		// load-shared and load-conn replace objects by exact name. Inspect
		// before issuing either call even in the exclusive lab daemon.
		// There is no equivalent safe production guarantee without an
		// owner-held, lifetime-exclusive writer boundary.
		reader, readErr := ipsec.NewReader(socket)
		if readErr != nil {
			return fmt.Errorf("private VICI reader unavailable")
		}
		snapshot, readErr := reader.Inspect(ctx, p)
		if readErr != nil {
			return fmt.Errorf("complete VICI vacancy cannot be proven")
		}
		if snapshot.ConnectionNamePresent || snapshot.SecretNamePresent {
			return fmt.Errorf("matching VICI object already present; refusing replacement")
		}
		secretFile := "/run/stl-ipsec-proof/" + suffix + ".secret"
		if side == "b" && os.Getenv("STL_IPSEC_MISMATCH_LINK") == suffix {
			secretFile = "/run/stl-ipsec-proof/" + suffix + "-mismatch.secret"
		}
		secret, err := os.ReadFile(secretFile)
		if err != nil {
			return fmt.Errorf("protected test PSK unavailable")
		}
		defer clear(secret)
		if len(secret) != 32 {
			return fmt.Errorf("test PSK wrong length")
		}
		shared, e := vici.MarshalMessage(map[string]any{"id": p.SecretName, "type": "IKE", "data": string(secret), "owners": []string{p.LocalIKEID, p.PeerIKEID}})
		if e != nil {
			return fmt.Errorf("invalid shared request")
		}
		if err = call("load-shared", shared); err != nil {
			return err
		}
		conn, e := p.ConnectionRequest()
		if e != nil {
			return e
		}
		if err = call("load-conn", conn); err != nil {
			return err
		}
	case "initiate":
		q, e := vici.MarshalMessage(map[string]any{"child": p.ChildName, "ike": p.ConnectionName, "timeout": "20000", "loglevel": "0"})
		if e != nil {
			return e
		}
		if err = call("initiate", q); err != nil {
			return err
		}
	case "terminate":
		q, e := vici.MarshalMessage(map[string]any{"ike": p.ConnectionName, "timeout": "20000", "loglevel": "0"})
		if e != nil {
			return e
		}
		if err = call("terminate", q); err != nil {
			return err
		}
	case "unload-conn":
		q, _ := vici.MarshalMessage(map[string]any{"name": p.ConnectionName})
		if err = call("unload-conn", q); err != nil {
			return err
		}
	case "unload-shared":
		q, _ := vici.MarshalMessage(map[string]any{"id": p.SecretName})
		if err = call("unload-shared", q); err != nil {
			return err
		}
	case "unload":
		q, _ := vici.MarshalMessage(map[string]any{"name": p.ConnectionName})
		if err = call("unload-conn", q); err != nil {
			return err
		}
		q, _ = vici.MarshalMessage(map[string]any{"id": p.SecretName})
		if err = call("unload-shared", q); err != nil {
			return err
		}
	case "check", "assert-absent", "reapply":
		for _, method := range []string{"get-conns", "get-shared"} {
			reply, e := sess.Call(ctx, method, vici.NewMessage())
			if e != nil || reply == nil {
				return fmt.Errorf("%s unavailable", method)
			}
			var listKey string
			if method == "get-conns" {
				listKey = "conns"
			} else {
				listKey = "keys"
			}
			names, ok := reply.Get(listKey).([]string)
			if !ok {
				return fmt.Errorf("invalid %s reply", method)
			}
			target := p.ConnectionName
			if method == "get-shared" {
				target = p.SecretName
			}
			found := false
			for _, n := range names {
				if strings.EqualFold(n, target) {
					found = true
				}
			}
			if op == "assert-absent" && found {
				return fmt.Errorf("%s remains after owned unlink", method)
			}
			if (op == "check" || op == "reapply") && !found {
				return fmt.Errorf("%s not found for owned Link", method)
			}
			fmt.Printf("VICI_%s_PRESENT=%v\n", method, found)
		}
	default:
		return fmt.Errorf("unsupported operation")
	}
	fmt.Printf("VICI_%s_OK peer=%s encap=%s\n", strings.ToUpper(op), side, enc)
	return nil
}
