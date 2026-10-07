package backend

import (
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type Registry struct {
	byKind map[domain.Backend]Backend
}

func NewRegistry(backends ...Backend) (*Registry, error) {
	r := &Registry{byKind: make(map[domain.Backend]Backend, len(backends))}
	for _, b := range backends {
		if b == nil {
			return nil, fmt.Errorf("nil backend")
		}
		kind := b.Kind()
		if kind == "" {
			return nil, fmt.Errorf("backend kind is required")
		}
		if _, exists := r.byKind[kind]; exists {
			return nil, fmt.Errorf("duplicate backend %q", kind)
		}
		r.byKind[kind] = b
	}
	return r, nil
}

func (r *Registry) Get(kind domain.Backend) (Backend, bool) {
	if r == nil {
		return nil, false
	}
	b, ok := r.byKind[kind]
	return b, ok
}
