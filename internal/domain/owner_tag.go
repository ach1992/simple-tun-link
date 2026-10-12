package domain

// OwnerTag is a stable, public Link identity used in Linux alias fields.
// It does not alone confer authority to delete or replace a kernel device.
func OwnerTag(id LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "stl:" + string(id), nil
}
