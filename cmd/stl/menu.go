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
	fmt.Fprintf(out, "simple-tun-link (STL)  |  Version: %s\n", safeMenuText(version.Version))
	fmt.Fprintln(out, "Repository: https://github.com/ach1992/simple-tun-link")
	fmt.Fprintf(out, "Host: %s | OS: %s/%s | Kernel: %s\n", safeMenuText(host), runtime.GOOS, runtime.GOARCH, safeMenuText(kernel))
	fmt.Fprintf(out, "Local address candidate: %s (route verified during setup)\n", safeMenuText(localAddressCandidate()))

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
		fmt.Fprintf(out, "Configured Links: %d (saved; use Test connectivity for live status)\n", len(snapshot.Links))
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
	overflow := false
	for count := 0; count < 64*1024; count++ {
		next, err := in.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && (len(answer) > 0 || overflow) {
				if overflow {
					return "", errMenuInputTooLong
				}
				return strings.TrimSpace(string(answer)), nil
			}
			return "", err
		}
		if next == '\n' {
			if overflow {
				return "", errMenuInputTooLong
			}
			return strings.TrimSpace(string(answer)), nil
		}
		if len(answer) < menuInputLimit {
			answer = append(answer, next)
		} else {
			overflow = true
		}
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
	for {
		fmt.Fprintln(out, "\n------------------------------------------------------------")
		printMenuHeader(out, options)
		fmt.Fprintln(out, "\nMAIN MENU")
		fmt.Fprintln(out, "  1  Create tunnel       (choose GRE / IPIP / WireGuard / IPsec)")
		fmt.Fprintln(out, "  2  Import setup link   (join an existing tunnel)")
		fmt.Fprintln(out, "  3  My tunnels          (status / share / test / remove)")
		fmt.Fprintln(out, "  4  Test connectivity   (read-only)")
		fmt.Fprintln(out, "  5  Settings           (read-only)")
		fmt.Fprintln(out, "  6  Update             (guided)")
		fmt.Fprintln(out, "  7  Uninstall          (guided)")
		fmt.Fprintln(out, "  8  Exit")
		fmt.Fprint(out, "Choose a task: ")
		choice, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			fmt.Fprintln(out, "Please enter a short number from 1 to 8. You are still in the menu.")
			continue
		}
		var result int
		switch choice {
		case "1":
			result = menuCreate(input, reader, out, errOut, options)
		case "2":
			result = menuImport(input, reader, out, errOut, options)
		case "3":
			result = menuManage(input, reader, out, errOut, options)
		case "4":
			result = menuDiagnose(input, reader, out, errOut, options)
		case "5":
			result = menuSettings(out, errOut, options)
		case "6":
			result = menuUpdate(reader, out, errOut)
		case "7":
			result = menuUninstall(out, errOut, options)
		case "8", "0", "q":
			fmt.Fprintln(out, "Goodbye.")
			return 0
		default:
			fmt.Fprintln(out, "Choose a number from 1 to 8.")
		}
		if result != 0 {
			fmt.Fprintln(out, "\nThat action did not complete. Read the message above, then choose your next action.")
			fmt.Fprintln(out, "No automatic retry or cleanup has been started.")
		}
	}
}
