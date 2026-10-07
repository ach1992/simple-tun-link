package linux

import (
	"fmt"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const ownerTagPrefix = "stl:"

// OwnerTag is a stable, non-secret marker suitable for Linux resources that
// support an alias/comment field. It identifies the owning Link, not merely a
// resource with a colliding name.
func OwnerTag(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return ownerTagPrefix + string(id), nil
}

func ParseOwnerTag(tag string) (domain.LinkID, bool) {
	if !strings.HasPrefix(tag, ownerTagPrefix) {
		return "", false
	}
	id := domain.LinkID(strings.TrimPrefix(tag, ownerTagPrefix))
	if err := id.Validate(); err != nil {
		return "", false
	}
	return id, true
}

// RequireOwned proves exact persisted ownership before a destructive operation.
// A merely overlapping or colliding resource is intentionally insufficient.
func RequireOwned(id domain.LinkID, claim domain.ResourceClaim, owned []domain.ResourceClaim) error {
	if err := id.Validate(); err != nil {
		return err
	}
	if err := claim.Validate(); err != nil {
		return err
	}
	for _, recorded := range owned {
		if recorded.Canonical() == claim.Canonical() {
			return nil
		}
	}
	return fmt.Errorf("resource %s is not recorded as owned by Link %s", claim.Kind, id)
}
