package artifact

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"io/fs"
	"os"
)

const SourceDirectorySchema = "codexploit/source-directory/v1"
const SourceWarningBytes int64 = 500 << 20

// Source inputs are directories, not in-memory artifacts. This bound is separate
// from output-object limits and can be exceeded only by explicit operator consent.
const MaxSourceBytes int64 = 8 << 30

type DirectoryStore interface {
	SourceDirectoryRef(context.Context, Scope) (Ref, error)
	SourceDirectory(context.Context, Scope, string) (string, error)
}

func sourceDirectoryID(scope Scope) string { return "source-" + scope.SnapshotID }

func (s *Local) SourceDirectory(ctx context.Context, scope Scope, id string) (string, error) {
	if s.ResolveSourceDirectory == nil || id != sourceDirectoryID(scope) {
		return "", ErrNotFound
	}
	return s.ResolveSourceDirectory(ctx, scope)
}

// SourceDirectoryRef is a logical project binding, never a content hash. SHA256
// exists only for old reference schemas; it identifies the binding and is not
// used to verify source files. No archive or per-file digest list is produced.
func (s *Local) SourceDirectoryRef(ctx context.Context, scope Scope) (Ref, error) {
	dir, err := s.SourceDirectory(ctx, scope, sourceDirectoryID(scope))
	if err != nil {
		return Ref{}, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Ref{}, ErrNotFound
	}
	defer root.Close()
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrInvalid
		}
		if info.Size() > MaxSourceBytes-total {
			return ErrBudget
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return Ref{}, err
	}
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(scope.ProjectID+":"+scope.SourceID+":"+scope.SnapshotID)))
	return Ref{ID: sourceDirectoryID(scope), Kind: "source.snapshot", Scope: scope, SHA256: identity, Bytes: total, MediaType: "inode/directory", SchemaID: SourceDirectorySchema, Producer: Producer{PluginID: "builtin.project-source", PluginVersion: "1.0.0", InvocationID: "source-" + scope.SnapshotID, ConfigDigest: identity}}, nil
}

// BindSourceDirectories enables project source resolution on the same scoped
// store used by the compiler, plugin host and authenticated API.
func (s *Local) BindSourceDirectories(manager *repository.Manager) {
	s.ResolveSourceDirectory = func(ctx context.Context, scope Scope) (string, error) {
		actual, err := s.index.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
		if err != nil || actual != scope {
			return "", ErrNotFound
		}
		source, err := manager.Load(scope.SnapshotID)
		if err != nil {
			return "", ErrNotFound
		}
		if err := source.Freeze(); err != nil {
			return "", err
		}
		return source.TreeDir(), nil
	}
}
