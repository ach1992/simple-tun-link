package quic

import "fmt"

// ImportCredentialBundle validates a protected pairing payload for exactly one
// Link and role. It makes independent copies; the caller retains ownership of
// the input and must clear it after use. No file is written, no identity is
// generated and no running helper is adopted by importing a bundle.
func ImportCredentialBundle(plan Plan, files map[string][]byte) (CredentialBundle, error) {
	if err := validMaterialScope(plan); err != nil {
		return CredentialBundle{}, err
	}
	// Validate before copying to bound memory and reject foreign filenames.
	if _, err := validateRoleMaterial(plan, files); err != nil {
		return CredentialBundle{}, err
	}
	bundle := CredentialBundle{files: make(map[string][]byte, len(files))}
	for name, raw := range files {
		bundle.files[name] = append([]byte(nil), raw...)
	}
	if _, err := validateRoleMaterial(plan, bundle.files); err != nil {
		bundle.Clear()
		return CredentialBundle{}, fmt.Errorf("QUIC imported credential copy did not verify")
	}
	return bundle, nil
}
