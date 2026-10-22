package hostidentity

import "testing"

func TestValidBootIDStrictCanonicalAndActualKernel(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"12345678-abcd-4abc-8abc-0123456789ab", true},
		{"88eabd6c-22ab-4c9b-9d23-fb076330638c", true},
		{"", false}, {"not-a-uuid", false},
		{"00000000-0000-0000-0000-000000000000", false},
		{"12345678-ABCD-4abc-8abc-0123456789ab", false},
		{"12345678-abcd-4abc-8abc-0123456789ab ", false},
		{"12345678abcd4abc8abc0123456789ab", false},
	} {
		if got := ValidBootID(tc.value); got != tc.valid {
			t.Fatalf("boot ID %q accepted=%t wanted=%t", tc.value, got, tc.valid)
		}
	}
	got, err := CurrentKernelBootID()
	if err != nil || !ValidBootID(got) {
		t.Fatalf("fixed-proc kernel identity not readable/valid: %v", err)
	}
}
