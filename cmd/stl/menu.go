package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	count := "unavailable"
	if root != "" {
		if snapshot, err := state.NewFileStore(root).Load(context.Background()); err == nil {
			count = fmt.Sprintf("%d saved", len(snapshot.Links))
		}
	}
	fmt.Fprintf(out, "%s  %s\n", menuPaint(out, menuBlue, "SIMPLE TUN LINK"), menuPaint(out, menuCyan, version.Version))
	fmt.Fprintln(out, menuPaint(out, menuDim, strings.Repeat("-", menuRuleWidth(out))))
	menuField(out, "Host", safeMenuText(host))
	menuField(out, "IPv4 candidate", safeMenuText(localAddressCandidate()))
	menuField(out, "Tunnels", count)
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
// Each interactive frame replaces the previous frame after acknowledgment.
func menuCommand(input io.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	if input == nil {
		fmt.Fprintln(errOut, "menu requires an input stream")
		return 2
	}
	reader := bufio.NewReader(input)
	for {
		menuScreen(out, "")
		printMenuHeader(out, options)
		menuSection(out, "Main menu")
		menuOption(out, "1", "Create tunnel", "Set up a new connection")
		menuOption(out, "2", "Import setup link", "Join the other server")
		menuOption(out, "3", "My tunnels", "View, share, test, remove")
		menuOption(out, "4", "Test connectivity", "Check one or all saved tunnels")
		menuOption(out, "5", "Settings", "Host and STL information")
		menuActionOption(out, "6", "Update", "Choose a published release", "UPDATE")
		menuActionOption(out, "7", "Uninstall", "Verify and remove installed STL", "UNINSTALL")
		menuOption(out, "8", "Exit", "")
		fmt.Fprint(out, "\nChoose a task: ")
		choice, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			menuNotice(out, "WARNING", "Enter a short number from 1 to 8.")
			menuAcknowledge(input, reader, out)
			continue
		}
		if choice == "8" || choice == "0" || strings.EqualFold(choice, "q") {
			fmt.Fprintln(out, "Goodbye.")
			return 0
		}
		menuScreen(out, "")
		var result int
		needsAcknowledgement := true
		switch choice {
		case "1":
			result = menuCreate(input, reader, out, errOut, options)
		case "2":
			result = menuImport(input, reader, out, errOut, options)
		case "3":
			result = menuManage(input, reader, out, errOut, options)
			needsAcknowledgement = false
		case "4":
			result = menuDiagnose(input, reader, out, errOut, options)
		case "5":
			result = menuSettings(out, errOut, options)
		case "6":
			result = menuUpdate(input, reader, out, errOut, options)
		case "7":
			result = menuUninstall(input, reader, out, errOut, options)
		default:
			menuNotice(out, "WARNING", "Choose a number from 1 to 8.")
		}
		// Outcome messages live in each action; a generic FAILED banner
		// would wrongly classify unavailable capabilities and repeat errors.
		if result == menuUpdatedExecutable {
			// An installer was attempted. Even an uncertain failure can leave
			// a different on-disk binary; never resume the old menu/Engine.
			return 0
		}
		if needsAcknowledgement {
			menuAcknowledge(input, reader, out)
		}
	}
}
