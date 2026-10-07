package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type LockManager struct {
	root string
}

func NewLockManager(root string) *LockManager {
	return &LockManager{root: filepath.Join(root, "locks")}
}

func (m *LockManager) Acquire(ctx context.Context, claims []domain.ResourceClaim) (func() error, error) {
	claims = normalizeClaims(claims)
	if len(claims) == 0 {
		return func() error { return nil }, nil
	}
	if err := ensurePrivateDir(m.root); err != nil {
		return nil, err
	}

	locked := make([]*fileLock, 0, len(claims))
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			releaseAll(locked)
			return nil, err
		}
		hash := sha256.Sum256([]byte(claim.Canonical()))
		name := hex.EncodeToString(hash[:]) + ".lock"
		lock, err := acquireFileLock(ctx, filepath.Join(m.root, name))
		if err != nil {
			releaseAll(locked)
			return nil, fmt.Errorf("lock resource %q: %w", claim.Kind, err)
		}
		locked = append(locked, lock)
	}

	return func() error {
		var first error
		for i := len(locked) - 1; i >= 0; i-- {
			if err := locked[i].release(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}, nil
}

type fileLock struct {
	file *os.File
}

func acquireFileLock(ctx context.Context, path string) (*fileLock, error) {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &fileLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (l *fileLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func releaseAll(locks []*fileLock) {
	for i := len(locks) - 1; i >= 0; i-- {
		_ = locks[i].release()
	}
}
