package ipsec

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

const nativeManagerEnvMaxEntries = 256

// decodeNativeManagerStringArray accepts only the bounded, one-line "as N
// \"value\" ..." busctl encoding. Never fall back to strings.Fields: values
// can contain spaces and escapes. The untrusted variables must not be logged.
func decodeNativeManagerStringArray(raw string) ([]string, error) {
	if len(raw) > 8192 || !strings.HasPrefix(raw, "as ") {
		return nil, errors.New("native manager environment frame invalid")
	}
	raw = strings.TrimPrefix(raw, "as ")
	end := 0
	for end < len(raw) && raw[end] >= '0' && raw[end] <= '9' {
		end++
	}
	if end == 0 || (end > 1 && raw[0] == '0') {
		return nil, errors.New("native manager environment count invalid")
	}
	n, err := strconv.Atoi(raw[:end])
	if err != nil || n < 0 || n > nativeManagerEnvMaxEntries {
		return nil, errors.New("native manager environment count out of range")
	}
	values := make([]string, 0, n)
	pos := end
	for i := 0; i < n; i++ {
		if pos >= len(raw) || raw[pos] != ' ' || pos+1 >= len(raw) || raw[pos+1] != '"' {
			return nil, errors.New("native manager environment string framing invalid")
		}
		start := pos + 1
		pos = start + 1
		closed := false
		for pos < len(raw) {
			if raw[pos] == '\\' {
				pos += 2
				continue
			}
			if raw[pos] == '"' {
				closed = true
				break
			}
			pos++
		}
		if !closed || pos >= len(raw) {
			return nil, errors.New("native manager environment string unterminated")
		}
		value, err := strconv.Unquote(raw[start : pos+1])
		if err != nil || len(value) > 4096 || strings.ContainsAny(value, "\x00\n\r") {
			return nil, errors.New("native manager environment string invalid")
		}
		values = append(values, value)
		pos++
	}
	if pos != len(raw) {
		return nil, errors.New("native manager environment trailing data")
	}
	return values, nil
}

// attestManagerEnvironment checks the EFFECTIVE manager spawn environment,
// which includes DefaultEnvironment, systemd.setenv, and runtime
// SetEnvironment sources. Service.Environment alone cannot prove this bound.
// In particular, LD_PRELOAD could run arbitrary initialization code before
// our existing post-start /proc/<pid>/environ admission.
// The systemd manager is inspected read-only, never reconfigured.
func (a NativeRuntimeAdmission) attestManagerEnvironment(ctx context.Context) error {
	raw, err := a.readBus(ctx, "get-property", "org.freedesktop.systemd1",
		"/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Environment")
	if err != nil {
		return errors.New("native pre-start manager environment unavailable")
	}
	values, err := decodeNativeManagerStringArray(raw)
	if err != nil {
		return errors.New("native pre-start manager environment unverified")
	}
	seen := make(map[string]struct{}, len(values))
	for _, entry := range values {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || len(name) == 0 || len(name) > 255 ||
			(name[0] >= '0' && name[0] <= '9') {
			return errors.New("native pre-start manager environment malformed")
		}
		for i := 0; i < len(name); i++ {
			c := name[i]
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				c == '_' || (i > 0 && c >= '0' && c <= '9')) {
				return errors.New("native pre-start manager environment malformed")
			}
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("native pre-start manager environment ambiguous")
		}
		seen[name] = struct{}{}
		if strings.HasPrefix(name, "LD_") ||
			(strings.HasPrefix(name, "STRONGSWAN_") &&
				(name != "STRONGSWAN_CONF" || value != NativeExclusiveConfigPath)) {
			return errors.New("native pre-start manager environment contains unsafe override")
		}
	}
	return nil
}
