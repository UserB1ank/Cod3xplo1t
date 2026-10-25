package plugin

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// OpenWorkerID stores an opaque node identity without hostname, account name or
// filesystem path. A fully written temporary file is linked atomically so two
// startups never observe an empty worker identity.
func OpenWorkerID(directory string) (string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", ErrInvalid
	}
	path := filepath.Join(directory, "worker-id")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		file, err := os.CreateTemp(directory, ".worker-id-")
		if err != nil {
			return "", ErrInvalid
		}
		name := file.Name()
		defer os.Remove(name)
		if _, err = file.WriteString("worker-" + rand.Text()); err != nil {
			file.Close()
			return "", ErrInvalid
		}
		if err = file.Close(); err != nil {
			return "", ErrInvalid
		}
		if err = os.Link(name, path); err != nil && !errors.Is(err, os.ErrExist) {
			return "", ErrInvalid
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 100 {
		return "", ErrInvalid
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", ErrInvalid
	}
	id := string(raw)
	if !strings.HasPrefix(id, "worker-") || len(id) < 20 {
		return "", ErrInvalid
	}
	for _, c := range strings.TrimPrefix(id, "worker-") {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return "", ErrInvalid
		}
	}
	return id, nil
}
