package masque

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// capsuleProtocolTrue validates RFC 9297's Capsule-Protocol Item as one
// Structured Field Boolean true. Unknown parameters are allowed and ignored
// (RFC 9297 section 3.4), but a list, malformed item or false value is never
// true. Duplicate header fields are rejected separately by authorizeRequest.
//
// This narrow parser only needs a Boolean Item plus parameter bare values;
// it does not introduce a dependency or a second generic HTTP parser.
func capsuleProtocolTrue(value string) bool {
	value = strings.Trim(value, " \t")
	if !strings.HasPrefix(value, "?1") {
		return false
	}
	value = value[2:]
	for {
		if value == "" {
			return true
		}
		if value[0] != ';' {
			// RFC 9651 section 4.2.3: whitespace before a parameter
			// separator is not allowed within a Structured Field Item.
			return false
		}
		// Parameter grammar discards SP only after the semicolon; HTAB
		// in that position is invalid even though outer OWS is allowed.
		value = strings.TrimLeft(value[1:], " ")
		if value == "" || !sfKeyStart(value[0]) {
			return false
		}
		i := 1
		for i < len(value) && sfKeyChar(value[i]) {
			i++
		}
		value = value[i:]
		if strings.HasPrefix(value, "=") {
			n, ok := sfBareItemLength(value[1:])
			if !ok {
				return false
			}
			value = value[1+n:]
		}
	}
}

func sfKeyStart(c byte) bool { return c >= 'a' && c <= 'z' || c == '*' }

func sfKeyChar(c byte) bool {
	return sfKeyStart(c) || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '.'
}

func sfTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~:/", rune(c))
}

// Parse only the byte span of one RFC 9651 bare Item, without interpreting
// unknown parameter values. A comma, second Item, or invalid value cannot
// be used to disguise a second Capsule-Protocol field.
func sfBareItemLength(s string) (int, bool) {
	if len(s) == 0 {
		return 0, false
	}
	switch s[0] {
	case '?':
		if len(s) > 1 && (s[1] == '0' || s[1] == '1') {
			return 2, true
		}
		return 0, false
	case '"':
		return sfStringLength(s)
	case ':':
		end := strings.IndexByte(s[1:], ':')
		if end < 0 {
			return 0, false
		}
		raw := s[1 : end+1]
		// RFC 9651 section 4.2.7 requires the base64 alphabet and
		// recommends accepting valid unpadded encodings. Go's default
		// decoder accepts LF, so check every encoded byte before parsing.
		for i := 0; i < len(raw); i++ {
			c := raw[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
				c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
				return 0, false
			}
		}
		// RFC 9651 advises accepting missing padding, even when only
		// some expected '=' suffix bytes are present. StdEncoding checks
		// alphabet placement after absent suffix padding is synthesized.
		pad := (4 - len(raw)%4) % 4
		_, err := base64.StdEncoding.DecodeString(raw + strings.Repeat("=", pad))
		return end + 2, err == nil
	case '%':
		// A Display String needs at least the opening %" and closing ".
		// An unauthenticated peer may supply only %" here; never give
		// make() the negative capacity that len(s)-3 would produce.
		if len(s) < 3 || s[1] != '"' {
			return 0, false
		}
		// A Display String's %-escapes use lowercase hex and the final
		// decoded octets must form valid UTF-8 (RFC 9651 section 4.2.10).
		decoded := make([]byte, 0, len(s)-3)
		for i := 2; i < len(s); i++ {
			c := s[i]
			switch {
			case c == '"':
				return i + 1, utf8.Valid(decoded)
			case c == '%' && i+2 < len(s) &&
				isLowerHex(s[i+1]) && isLowerHex(s[i+2]):
				decoded = append(decoded, hexNibble(s[i+1])<<4|hexNibble(s[i+2]))
				i += 2
			case c >= 0x20 && c <= 0x7e && c != '%':
				decoded = append(decoded, c)
			default:
				return 0, false
			}
		}
		return 0, false
	case '@':
		n, ok := sfNumberLength(s[1:], false)
		return n + 1, ok
	default:
		if s[0] == '-' || s[0] >= '0' && s[0] <= '9' {
			return sfNumberLength(s, true)
		}
		if !sfTokenChar(s[0]) || !(s[0] == '*' ||
			s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
			return 0, false
		}
		i := 1
		for i < len(s) && sfTokenChar(s[i]) {
			i++
		}
		return i, true
	}
}

func sfStringLength(s string) (int, bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return i + 1, true
		case '\\':
			i++
			if i >= len(s) || (s[i] != '"' && s[i] != '\\') {
				return 0, false
			}
		default:
			if s[i] < 0x20 || s[i] > 0x7e {
				return 0, false
			}
		}
	}
	return 0, false
}

func sfNumberLength(s string, decimalAllowed bool) (int, bool) {
	i := 0
	if strings.HasPrefix(s, "-") {
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	digits := i - start
	if digits < 1 || digits > 15 {
		return 0, false
	}
	if decimalAllowed && i < len(s) && s[i] == '.' {
		if digits > 12 {
			return 0, false
		}
		i++
		start = i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i-start < 1 || i-start > 3 {
			return 0, false
		}
	}
	return i, true
}

func isLowerHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

func hexNibble(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	return c - 'a' + 10
}
