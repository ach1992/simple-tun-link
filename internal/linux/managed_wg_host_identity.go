//go:build !stl_e2e_lab

package linux

import "github.com/ach1992/simple-tun-link/internal/hostidentity"

func managedSiblingKernelBootID() (string, error) { return hostidentity.CurrentKernelBootID() }
