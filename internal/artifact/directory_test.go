package artifact_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestProjectSourceDirectoryNeedsNoArchiveOrContentVerification(t *testing.T) {
	index := storage.NewMemory()
	objects, err := artifact.NewLocal(t.TempDir(), index)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "source.go"), []byte("package main"), 0400); err != nil {
		t.Fatal(err)
	}
	scope := artifact.Scope{ProjectID: "project", SourceID: "source", SnapshotID: "snap-11111111111111111111111111111111"}
	objects.ResolveSourceDirectory = func(_ context.Context, got artifact.Scope) (string, error) {
		if got != scope {
			return "", artifact.ErrNotFound
		}
		return dir, nil
	}
	ref, err := objects.SourceDirectoryRef(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Bytes != 12 || ref.SchemaID != artifact.SourceDirectorySchema {
		t.Fatalf("ref = %+v", ref)
	}
	if _, err := objects.Stat(t.Context(), scope, ref.ID, 500<<20); err != nil {
		t.Fatal(err)
	}
	if _, _, err := objects.Open(t.Context(), scope, ref.ID, 500<<20); err == nil {
		t.Fatal("directory must not be read as an artifact")
	}
	if err := os.Chmod(filepath.Join(dir, "source.go"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "source.go"), []byte("package test"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Stat(t.Context(), scope, ref.ID, 500<<20); err != nil {
		t.Fatal(err)
	}
}
