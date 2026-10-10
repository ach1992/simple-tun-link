package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/version"
	"golang.org/x/sys/unix"
)

const menuInputLimit = 128

var errMenuInputTooLong = errors.New("menu input exceeds limit")

func terminalIsInteractive(file *os.File) bool {
	if file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}

// No external lookups or host mutations: the menu only presents a snapshot
// of local state. Its text is for humans, never a machine API.
func printMenuHeader(out io.Writer, options *runtimeOptions) {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	var u unix.Utsname
	kernel := "unknown"
	if unix.Uname(&u) == nil {
		kernel = unix.ByteSliceToString(u.Release[:])
	}
	fmt.Fprintf(out, "simple-tun-link | stl %s | github.com/ach1992/simple-tun-link\n", safeMenuText(version.Version))
	fmt.Fprintf(out, "Host: %s | OS: %s/%s | Kernel: %s\n", safeMenuText(host), runtime.GOOS, runtime.GOARCH, safeMenuText(kernel))
	fmt.Fprintf(out, "Local address candidate: %s (verify route toward the peer)\n", safeMenuText(localAddressCandidate()))

	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	if root == "" {
		fmt.Fprintln(out, "Configured Links: unavailable")
		return
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		fmt.Fprintln(out, "Configured Links: unavailable (state cannot be read)")
	} else {
		fmt.Fprintf(out, "Configured Links: %d (saved state, not verified connectivity)\n", len(snapshot.Links))
	}
}

// Kernel/host/interface labels must not inject terminal control or
// Unicode format/bidirectional ordering characters.
func safeMenuText(value string) string {
	var result strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = '_'
		}
		if result.Len()+utf8.RuneLen(r) > 96 {
			break
		}
		result.WriteRune(r)
	}
	if result.Len() == 0 {
		return "unknown"
	}
	return result.String()
}

func localAddressCandidate() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unavailable"
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.To4() != nil && ipnet.IP.IsGlobalUnicast() {
				return iface.Name + " / " + ipnet.IP.String()
			}
		}
	}
	return "not detected; choose explicitly"
}

func readMenuAnswer(in *bufio.Reader) (string, error) {
	answer := make([]byte, 0, 32)
	for len(answer) <= menuInputLimit {
		next, err := in.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(answer) != 0 {
				return strings.TrimSpace(string(answer)), nil
			}
			return "", err
		}
		if next == '\n' {
			return strings.TrimSpace(string(answer)), nil
		}
		answer = append(answer, next)
	}
	return "", errMenuInputTooLong
}

// The menu calls the existing command surfaces; it does not reimplement
// domain validation, backend ownership, diagnostics, pairing or mutation.
func menuCommand(input io.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	if input == nil {
		fmt.Fprintln(errOut, "menu requires an input stream")
		return 2
	}
	reader := bufio.NewReader(input)
	printMenuHeader(out, options)
	for {
		fmt.Fprintln(out, "\nTasks:")
		fmt.Fprintln(out, "  1  Create Tunnel (guided GRE Native)")
		fmt.Fprintln(out, "  2  Import Setup Link (confirmed GRE/IPIP only)")
		fmt.Fprintln(out, "  3  Manage Links")
		fmt.Fprintln(out, "  4  Tests & Diagnostics")
		fmt.Fprintln(out, "  5  Settings (read-only)")
		fmt.Fprintln(out, "  6  Update (guided)")
		fmt.Fprintln(out, "  7  Uninstall (guided)")
		fmt.Fprintln(out, "  8  Exit")
		fmt.Fprint(out, "Choose a task: ")
		choice, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			fmt.Fprintln(errOut, "menu selection is invalid or too long")
			return 2
		}
		switch choice {
		case "1":
			if code := menuCreate(input, reader, out, errOut, options); code != 0 {
				return code
			}
		case "2":
			if code := menuImport(input, reader, out, errOut, options); code != 0 {
				return code
			}
		case "3":
			if code := menuManage(input, reader, out, errOut, options); code != 0 {
				return code
			}
		case "4":
			if code := linkReadCommand([]string{"list"}, out, errOut, options); code != 0 {
				return code
			}
			fmt.Fprintln(out, "Diagnostics send bounded probes to a selected peer Link Address; no host configuration is changed.")
			fmt.Fprint(out, "Diagnose Link ID (Enter returns to menu): ")
			id, err := readMenuAnswer(reader)
			if err != nil && !errors.Is(err, io.EOF) {
				fmt.Fprintln(errOut, "invalid Link ID; no probes sent")
				return 2
			}
			if id != "" {
				if domain.LinkID(id).Validate() != nil {
					fmt.Fprintln(errOut, "invalid Link ID; no probes sent")
					return 2
				}
				if code := linkDiagnoseCommand([]string{"diagnose", id}, out, errOut, options); code != 0 {
					return code
				}
			}
		case "5":
			if code := menuSettings(out, errOut, options); code != 0 {
				return code
			}
		case "6":
			if code := menuUpdate(reader, out, errOut); code != 0 {
				return code
			}
		case "7":
			if code := menuUninstall(out, errOut, options); code != 0 {
				return code
			}
		case "8":
			return 0
		default:
			fmt.Fprintln(out, "Select a number from 1 to 8.")
		}
	}
}
