package stlerr

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestErrorDoesNotExposeCause(t *testing.T) {
	cause := errors.New("private_key=SUPER-SECRET")
	err := Wrap(CodeApply, "ensure", "lnk_abc", "wireguard", "backend apply failed", cause)

	if got := err.Error(); strings.Contains(got, "SUPER-SECRET") {
		t.Fatalf("Error() leaked cause: %q", got)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause is not available to errors.Is")
	}

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), "SUPER-SECRET") {
		t.Fatalf("JSON leaked cause: %s", encoded)
	}
	// Newly supported optional reason/action fields must not change the
	// ordinary v1 error object unless a caller explicitly supplies them.
	if strings.Contains(string(encoded), "reason_code") ||
		strings.Contains(string(encoded), "next_step") {
		t.Fatalf("empty optional recovery fields changed generic JSON: %s", encoded)
	}
}
