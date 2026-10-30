// Package systemdunit provides pure, version-scoped parsing of systemd unit
// observations. It performs no host operation and grants no resource authority.
package systemdunit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ParseVersion reads exactly one systemctl manager Version property. Its
// strict format keeps missing newer properties from masquerading as legacy
// capability absence. A parsed version alone does not authenticate a manager.
func ParseVersion(raw []byte) (int, bool) {
	if len(raw) < len("Version=247\n") || len(raw) > 120 ||
		!strings.HasPrefix(string(raw), "Version=") || raw[len(raw)-1] != '\n' ||
		strings.Count(string(raw), "\n") != 1 {
		return 0, false
	}
	s := strings.TrimSuffix(strings.TrimPrefix(string(raw), "Version="), "\n")
	if len(s) < 3 {
		return 0, false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return 0, false
		}
	}
	if s[0] < '1' || s[0] > '9' || s[1] < '0' || s[1] > '9' || s[2] < '0' || s[2] > '9' {
		return 0, false
	}
	if len(s) > 3 && !strings.ContainsAny(s[3:4], ".-+~") {
		return 0, false
	}
	return int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0'), true
}

// LegacyUnitSnapshot contains only selected identity fields and relevant
// dependency evidence from a legacy manager dump. Missing map keys remain
// distinct from present empty values: Fragment Path and StopWhenUnneeded are
// conditional in systemd 249/250. Consumers apply their own identity policy.
//
// Present=false is merely a parsed observation. The caller must separately
// establish full successful command completion and unchanged manager identity.
// The dump has no authenticated EOF marker; a syntactically complete prefix
// cannot by itself prove that the original source was completely delivered.
type LegacyUnitSnapshot struct {
	Present         bool
	Fields          map[string]string
	IncomingUpholds bool
	OutgoingUpholds bool
}

// ParseLegacyManagerDump streams the attested v249/v250 Manager.Dump format.
// Those managers support Upholds= but do not export the UpheldBy D-Bus
// property. Inspect both global forward edges and the selected reverse edges;
// unrelated units must not hide references to a selected unit or its aliases.
//
// No total-output or unit-count quota is imposed. Individual lines are bounded
// to 1 MiB, and the caller owns execution time and command-completion checks.
// No dump content or field value is included in errors.
func ParseLegacyManagerDump(r io.Reader, version int, selected string, aliases ...string) (LegacyUnitSnapshot, error) {
	var zero LegacyUnitSnapshot
	if r == nil || (version != 249 && version != 250) || !validUnitToken(selected) {
		return zero, errors.New("unsupported systemd manager snapshot request")
	}
	targets := map[string]bool{selected: true}
	for _, alias := range aliases {
		if !validUnitToken(alias) {
			return zero, errors.New("invalid selected systemd unit alias")
		}
		targets[alias] = true
	}
	result := LegacyUnitSnapshot{Fields: make(map[string]string)}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	// bufio.ScanLines silently strips CR and accepts an unfinished last line.
	// Manager output always has line terminators; preserve bytes for checking.
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) != 0 {
			return 0, nil, errors.New("incomplete systemd snapshot line")
		}
		return 0, nil, nil
	})
	header, features := false, false
	currentUnit := ""
	units := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.ContainsAny(line, "\x00\r") {
			return zero, errors.New("invalid bytes in systemd manager snapshot")
		}
		if !header {
			prefix := fmt.Sprintf("Manager: systemd %d (", version)
			if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, ")") || len(line) <= len(prefix)+1 {
				return zero, errors.New("systemd manager dump version or identity unverified")
			}
			header = true
			continue
		}
		if strings.HasPrefix(line, "Manager:") {
			return zero, errors.New("duplicated systemd manager snapshot header")
		}
		if strings.HasPrefix(line, "Features:") {
			if features || currentUnit != "" || !strings.HasPrefix(line, "Features: ") || len(line) == len("Features: ") {
				return zero, errors.New("invalid systemd manager feature header")
			}
			features = true
			continue
		}
		if strings.HasPrefix(line, "-> Unit ") {
			if !features || !strings.HasSuffix(line, ":") {
				return zero, errors.New("malformed systemd unit snapshot header")
			}
			name := strings.TrimSuffix(strings.TrimPrefix(line, "-> Unit "), ":")
			if !validUnitToken(name) || units[name] {
				return zero, errors.New("invalid or duplicated systemd unit snapshot")
			}
			units[name] = true
			currentUnit = name
			if name == selected {
				result.Present = true
			}
			continue
		}
		if strings.HasPrefix(line, "-> Job ") {
			if !features || !strings.HasSuffix(line, ":") {
				return zero, errors.New("malformed systemd job snapshot header")
			}
			job := strings.TrimSuffix(strings.TrimPrefix(line, "-> Job "), ":")
			if job == "" || strings.Trim(job, "0123456789") != "" {
				return zero, errors.New("invalid systemd job snapshot identity")
			}
			currentUnit = ""
			continue
		}
		if strings.HasPrefix(line, "->") {
			return zero, errors.New("unrecognized systemd snapshot section")
		}
		for _, relation := range []string{"Upholds", "UpheldBy"} {
			trimmed := strings.TrimLeft(line, " \t")
			if !strings.HasPrefix(trimmed, relation+":") {
				continue
			}
			prefix := "\t" + relation + ": "
			if currentUnit == "" || !strings.HasPrefix(line, prefix) {
				return zero, errors.New("malformed systemd dependency observation")
			}
			value := strings.TrimPrefix(line, prefix)
			name, origin, found := strings.Cut(value, " (")
			if !found || !validUnitToken(name) || len(origin) < 2 || !strings.HasSuffix(origin, ")") ||
				strings.ContainsAny(strings.TrimSuffix(origin, ")"), "()\t") {
				return zero, errors.New("invalid systemd dependency edge")
			}
			if relation == "Upholds" {
				result.IncomingUpholds = result.IncomingUpholds || targets[name]
				result.OutgoingUpholds = result.OutgoingUpholds || targets[currentUnit]
			} else {
				result.IncomingUpholds = result.IncomingUpholds || targets[currentUnit]
				result.OutgoingUpholds = result.OutgoingUpholds || targets[name]
			}
		}
		if currentUnit != selected {
			continue
		}
		for _, field := range []string{"Unit Load State", "Unit Active State", "Need Daemon Reload", "Fragment Path", "StopWhenUnneeded", "Transient"} {
			if !strings.HasPrefix(line, "\t"+field+":") {
				continue
			}
			prefix := "\t" + field + ": "
			if _, repeated := result.Fields[field]; repeated || !strings.HasPrefix(line, prefix) {
				return zero, errors.New("invalid or duplicated selected systemd unit field")
			}
			result.Fields[field] = strings.TrimPrefix(line, prefix)
			break
		}
	}
	if scanner.Err() != nil {
		return zero, errors.New("systemd manager snapshot truncated or unreadable")
	}
	if !header || !features || len(units) == 0 {
		return zero, errors.New("systemd manager snapshot is incomplete")
	}
	if result.Present {
		for _, field := range []string{"Unit Load State", "Unit Active State", "Need Daemon Reload"} {
			if _, exists := result.Fields[field]; !exists {
				return zero, errors.New("selected systemd unit identity is incomplete")
			}
		}
	}
	return result, nil
}

func validUnitToken(name string) bool {
	if name == "" || !strings.ContainsRune(name, '.') {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_:.@-\\", c)) {
			return false
		}
	}
	return true
}
