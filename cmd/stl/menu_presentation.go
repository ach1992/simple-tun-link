package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
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
	if !menuColorEnabled(out) || value == "" || role == "" {
		return value
	}
	return "\x1b[" + role + "m" + value + "\x1b[0m"
}

// Action colors are a single menu-wide vocabulary. They never change
// machine output or the meaning of a confirmation.
func menuActionRole(action string) string {
	switch action {
	case "REMOVE", "DELETE", "UNINSTALL":
		return menuRed
	case "PREPARE", "INSTALL", "UPDATE":
		return menuYellow
	case "YES":
		return menuGreen
	case "SHOW":
		return menuBlue
	default:
		return menuCyan
	}
}

func menuActionToken(out io.Writer, action string) string {
	return menuPaint(out, menuActionRole(action), action)
}

// Prompts may style semantic action words, while preserving their exact
// plain content under NO_COLOR/TERM=dumb and on redirected streams.
var menuPromptActions = regexp.MustCompile("\\b(?:REMOVE|DELETE|UNINSTALL|PREPARE|INSTALL|UPDATE|SHOW|YES)\\b")

func menuPrompt(out io.Writer, prompt string) string {
	if !menuColorEnabled(out) || menuCopyable(prompt) {
		return prompt
	}
	matches := menuPromptActions.FindAllStringIndex(prompt, -1)
	var result strings.Builder
	from := 0
	for _, span := range matches {
		result.WriteString(menuPaint(out, menuCyan, prompt[from:span[0]]))
		result.WriteString(menuActionToken(out, prompt[span[0]:span[1]]))
		from = span[1]
	}
	result.WriteString(menuPaint(out, menuCyan, prompt[from:]))
	return result.String()
}

func menuOptionRole(title string) string {
	title = strings.ToUpper(title)
	for _, word := range strings.FieldsFunc(title, func(r rune) bool { return r < 'A' || r > 'Z' }) {
		switch word {
		case "REMOVE", "DELETE", "UNINSTALL":
			return menuRed
		}
	}
	for _, word := range strings.FieldsFunc(title, func(r rune) bool { return r < 'A' || r > 'Z' }) {
		switch word {
		case "INSTALL", "PREPARE", "UPDATE":
			return menuYellow
		case "SHOW":
			return menuBlue
		}
	}
	return ""
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
	role := menuOptionRole(title)
	if role == "" {
		role = menuBlue
	}
	fmt.Fprintln(out, "\n"+menuPaint(out, role, strings.ToUpper(title)))
	fmt.Fprintln(out, menuPaint(out, menuDim, strings.Repeat("-", width)))
}

func menuOption(out io.Writer, number, title, description string) {
	if !menuCopyable(description) {
		description = menuPaint(out, menuDim, description)
	}
	entry := menuPaint(out, menuCyan, fmt.Sprintf("%2s", number))
	role := menuOptionRole(title)
	if file, ok := menuTerminal(out); ok {
		if ws, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 && ws.Col < 64 {
			fmt.Fprintf(out, "  %s  %s\n      %s\n", entry, menuPaint(out, role, title), description)
			return
		}
	}
	// Pad the raw title before decoration. ANSI bytes must not move columns.
	fmt.Fprintf(out, "  %s  %s %s\n", entry, menuPaint(out, role, fmt.Sprintf("%-22s", title)),
		description)
}

// Human-only width; redirected/automation output is never reformatted.
func menuColumns(out io.Writer) int {
	if file, ok := menuTerminal(out); ok {
		if ws, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
			return int(ws.Col)
		}
	}
	return 0
}

// URLs, opaque IDs and shell commands must remain exact copyable tokens.
func menuCopyable(value string) bool {
	return strings.Contains(value, "://") || strings.Contains(value, "stl://") ||
		strings.HasPrefix(value, "sudo ") || strings.HasPrefix(value, "bash ") ||
		strings.HasPrefix(value, "stl ") || strings.HasPrefix(value, "curl ")
}

// Group long *prose* on narrow real terminals, but never alter machine,
// redirected, credential or copyable command values.
func menuField(out io.Writer, label, value string) {
	cols := menuColumns(out)
	if cols >= 24 && !menuCopyable(value) &&
		2+max(17, len(label))+1+len(value) > cols {
		fmt.Fprintf(out, "  %s\n", label)
		width := max(16, cols-6)
		wrapped := "      " + strings.ReplaceAll(wrapTerminalGuidance(value, width), "\n", "\n      ")
		fmt.Fprintln(out, menuFieldValue(out, label, wrapped))
		return
	}
	fmt.Fprintf(out, "  %-17s %s\n", label, menuFieldValue(out, label, value))
}

// Exact copyable commands, private setup links and URLs are never decorated.
func menuFieldValue(out io.Writer, label, value string) string {
	if menuCopyable(value) {
		return value
	}
	if strings.EqualFold(strings.TrimSpace(label), "Status") || strings.EqualFold(strings.TrimSpace(label), "State") {
		v := strings.ToUpper(strings.TrimSpace(value))
		switch {
		case strings.HasPrefix(v, "OK"), strings.HasPrefix(v, "READY"),
			strings.HasPrefix(v, "VERIFIED"), strings.HasPrefix(v, "CONNECTED"):
			return menuPaint(out, menuGreen, value)
		case strings.HasPrefix(v, "FAILED"), strings.HasPrefix(v, "ERROR"),
			strings.HasPrefix(v, "BLOCKED"), strings.HasPrefix(v, "CONFLICT"):
			return menuPaint(out, menuRed, value)
		case strings.HasPrefix(v, "UNKNOWN"):
			return menuPaint(out, menuDim, value)
		case strings.HasPrefix(v, "UNAVAILABLE"):
			return menuPaint(out, menuCyan, value)
		case strings.HasPrefix(v, "WARNING"), strings.HasPrefix(v, "NEEDS"),
			strings.HasPrefix(v, "UNVERIFIED"):
			return menuPaint(out, menuYellow, value)
		}
	}
	return menuPaint(out, menuCyan, value)
}

// Human explanations are paragraphs, never machine output. Indent and
// wrap long prose only in a real terminal; never split opaque Setup Links,
// exact shell commands or remote URLs that operators must copy byte-for-byte.
func menuProse(out io.Writer, message string) {
	cols := menuColumns(out)
	if cols >= 24 && len(message) > cols-4 && !menuCopyable(message) {
		fmt.Fprintln(out, "  "+strings.ReplaceAll(wrapTerminalGuidance(message, max(16, cols-4)), "\n", "\n  "))
		return
	}
	fmt.Fprintln(out, message)
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
	case "FAILED", "ERROR", "CONFLICT":
		role = menuRed
	case "UNKNOWN":
		role = menuDim
	case "UNAVAILABLE":
		role = menuCyan
	}
	cols := menuColumns(out)
	if cols >= 24 && len(kind)+len(message)+5 > cols && !menuCopyable(message) {
		fmt.Fprintf(out, "\n%s\n", menuPaint(out, role, "["+kind+"]"))
		fmt.Fprintln(out, "  "+strings.ReplaceAll(wrapTerminalGuidance(message, max(16, cols-4)), "\n", "\n  "))
		return
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
