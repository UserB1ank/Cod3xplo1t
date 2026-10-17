package artifact

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const MaxBytes int64 = 512 << 20

type Local struct {
	root  string
	index Index
}

func NewLocal(root string, index Index) (*Local, error) {
	if root == "" || index == nil {
		return nil, ErrInvalid
	}
	for _, dir := range []string{"objects", "staging"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			return nil, err
		}
	}
	return &Local{root: root, index: index}, nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

func (s *Local) Put(ctx context.Context, ref Ref, src io.Reader, budget int64) (Ref, error) {
	if err := ref.Validate(); err != nil {
		return Ref{}, err
	}
	if src == nil || budget <= 0 || budget > MaxBytes {
		return Ref{}, ErrInvalid
	}
	if ref.Bytes > budget {
		return Ref{}, ErrBudget
	}
	f, err := os.CreateTemp(filepath.Join(s.root, "staging"), "put-*")
	if err != nil {
		return Ref{}, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx, src}, ref.Bytes+1))
	if err != nil {
		return Ref{}, err
	}
	if err := ctx.Err(); err != nil {
		return Ref{}, err
	}
	if n != ref.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != ref.SHA256 {
		return Ref{}, ErrIntegrity
	}
	if err := f.Sync(); err != nil {
		return Ref{}, err
	}
	if err := f.Close(); err != nil {
		return Ref{}, err
	}
	target := filepath.Join(s.root, "objects", ref.SHA256)
	if err := os.Link(f.Name(), target); err != nil && !errors.Is(err, os.ErrExist) {
		return Ref{}, err
	}
	// A duplicate object must still be healthy before a new reference is visible.
	verified, err := s.openVerified(ctx, ref, budget)
	if err != nil {
		return Ref{}, err
	}
	verified.Close()
	if err := s.index.PublishArtifact(ctx, ref); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

func (s *Local) openVerified(ctx context.Context, ref Ref, budget int64) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if budget <= 0 || budget > MaxBytes {
		return nil, ErrInvalid
	}
	if ref.Bytes > budget {
		return nil, ErrBudget
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Join(s.root, "objects"))
	if err != nil {
		return nil, ErrNotFound
	}
	defer root.Close()
	f, err := root.Open(ref.SHA256)
	if err != nil {
		return nil, ErrNotFound
	}
	fail := func(e error) (*os.File, error) { f.Close(); return nil, e }
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != ref.Bytes {
		return fail(ErrIntegrity)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(contextReader{ctx, f}, ref.Bytes+1))
	if err != nil {
		return fail(err)
	}
	if n != ref.Bytes || fmt.Sprintf("%x", h.Sum(nil)) != ref.SHA256 {
		return fail(ErrIntegrity)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return f, nil
}

type readCloser struct {
	contextReader
	io.Closer
}

func (s *Local) Open(ctx context.Context, scope Scope, id string, budget int64) (io.ReadCloser, Ref, error) {
	ref, err := s.index.LookupArtifact(ctx, scope, id)
	if err != nil {
		return nil, Ref{}, err
	}
	f, err := s.openVerified(ctx, ref, budget)
	if err != nil {
		return nil, Ref{}, err
	}
	return readCloser{contextReader{ctx, f}, f}, ref, nil
}

func (s *Local) Stat(ctx context.Context, scope Scope, id string, budget int64) (Ref, error) {
	r, ref, err := s.Open(ctx, scope, id, budget)
	if err != nil {
		return Ref{}, err
	}
	return ref, r.Close()
}

func (s *Local) List(ctx context.Context, scope Scope, cursor string, limit int) ([]Ref, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	return s.index.ListArtifacts(ctx, scope, cursor, limit)
}
