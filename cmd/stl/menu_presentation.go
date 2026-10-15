package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Human-only terminal rendering. Machine CLI/JSON and redirected output never
// contain ANSI escapes, and color is never the sole indicator of a result.
const (
	menuCyan   = "36"
	menuBlue   = "1;34"
	menuGreen  = "1;32"
	menuYellow = "1;33"
	menuRed    = "1;31"
	menuDim    = "2"
)

func menuTerminal(out io.Writer) (*os.File, bool) {
	file, ok := out.(*os.File)
	if !ok || !terminalIsInteractive(file) {
		return nil, false
	}
	return file, true
}

func menuEscapeCapable(out io.Writer) bool {
	_, tty := menuTerminal(out)
	term := strings.ToLower(os.Getenv("TERM"))
	return tty && term != "" && term != "dumb"
}

func menuColorEnabled(out io.Writer) bool {
	_, disabled := os.LookupEnv("NO_COLOR")
	return menuEscapeCapable(out) && !disabled && os.Getenv("CLICOLOR") != "0"
}

func menuPaint(out io.Writer, role, value string) string {
	if !menuColorEnabled(out) || value == "" {
		return value
	}
	return "\x1b[" + role + "m" + value + "\x1b[0m"
}

func menuScreen(out io.Writer, title string) {
	if menuEscapeCapable(out) && os.Getenv("STL_NO_CLEAR") != "1" {
		// 2J clears only the visible screen, leaving terminal scrollback intact.
		// Never erase scrollback: it can contain useful diagnostic evidence.
		fmt.Fprint(out, "\x1b[2J\x1b[H")
	}
	if title != "" {
		menuSection(out, title)
	}
}

func menuSection(out io.Writer, title string) {
	width := 55
	if file, ok := menuTerminal(out); ok {
		if ws, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
			width = min(width, int(ws.Col)-4)
			if width < 8 {
				width = 8
			}
		}
	}
	fmt.Fprintln(out, "\n"+menuPaint(out, menuBlue, strings.ToUpper(title)))
	fmt.Fprintln(out, menuPaint(out, menuDim, strings.Repeat("-", width)))
}

func menuOption(out io.Writer, number, title, description string) {
	entry := menuPaint(out, menuCyan, fmt.Sprintf("%2s", number))
	if file, ok := menuTerminal(out); ok {
		if ws, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 && ws.Col < 64 {
			fmt.Fprintf(out, "  %s  %s\n      %s\n", entry, title, menuPaint(out, menuDim, description))
			return
		}
	}
	fmt.Fprintf(out, "  %s  %-22s %s\n", entry, title, menuPaint(out, menuDim, description))
}

func menuField(out io.Writer, label, value string) {
	fmt.Fprintf(out, "  %-17s %s\n", label, menuPaint(out, menuCyan, value))
}

// The controlling stdout session AND the destination stderr must both
// support terminal control before rendering a human failure page. A TTY
// stderr alone never makes a redirected/automation stdout interactive.
func menuSessionErrorTTY(stdout, stderr io.Writer) bool {
	return menuEscapeCapable(stdout) && menuEscapeCapable(stderr)
}

// Preserve the stderr channel for failures, while never emitting ANSI
// from an independently interactive stderr when stdout is redirected.
func menuSessionErrorNotice(stdout, stderr io.Writer, message string) {
	if !menuSessionErrorTTY(stdout, stderr) {
		fmt.Fprintf(stderr, "\n[FAILED] %s\n", message)
		return
	}
	menuNotice(stderr, "FAILED", message)
}

func menuNotice(out io.Writer, kind, message string) {
	role := menuBlue
	switch kind {
	case "OK":
		role = menuGreen
	case "WARNING":
		role = menuYellow
	case "FAILED":
		role = menuRed
	}
	fmt.Fprintf(out, "\n%s %s\n", menuPaint(out, role, "["+kind+"]"), message)
}

// A result stays visible until explicitly acknowledged in a real terminal.
// Do not consume an extra line in redirected/automation tests and scripts.
func menuAcknowledge(input io.Reader, reader *bufio.Reader, out io.Writer) {
	in, inOK := input.(*os.File)
	if _, outOK := menuTerminal(out); !inOK || !outOK || !terminalIsInteractive(in) {
		return
	}
	fmt.Fprint(out, "\n"+menuPaint(out, menuDim, "Press Enter to continue...")+" ")
	_, _ = readMenuAnswer(reader)
}
