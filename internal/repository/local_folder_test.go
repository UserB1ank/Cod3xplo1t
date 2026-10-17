package repository

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalFolderSnapshotIncludesCurrentWorkingFiles(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\nconst version = 1\n")
	repo.commit("fixture")
	repo.write("main.go", "package main\nconst version = 2\n")
	repo.write("new.go", "package main\nconst added = true\n")
	m := newTestManager(t)
	snapshot, err := m.Create(context.Background(), Source{Raw: repo.dir, Kind: KindDir})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, m, snapshot.SnapshotID)
	current, err := os.ReadFile(filepath.Join(snapshot.TreeDir(), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	added, err := os.ReadFile(filepath.Join(snapshot.TreeDir(), "new.go"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.VCS != "none" || string(current) != "package main\nconst version = 2\n" || string(added) != "package main\nconst added = true\n" {
		t.Fatalf("folder mode did not capture current files: vcs=%s current=%q added=%q", snapshot.VCS, current, added)
	}
}

// This fixture changes the external filesystem at the read boundary. It does
// not reach into the manager's planning or publication implementation.
type changingDirectoryFS struct {
	fs.FS
	dir   string
	reads int
}

func (f *changingDirectoryFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err == nil && name == "main.go" {
		f.reads++
		if f.reads == 2 {
			if writeErr := os.WriteFile(filepath.Join(f.dir, "added.go"), []byte("package main\n"), 0o644); writeErr != nil {
				file.Close()
				return nil, writeErr
			}
		}
	}
	return file, err
}

func TestLocalFolderChangesDuringCaptureDoNotPublishSnapshot(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := &changingDirectoryFS{FS: os.DirFS(directory), dir: directory}
	manager := newTestManager(t)
	snapshot, err := manager.Create(context.Background(), Source{Kind: KindDir, Raw: "/repos/service", NameOverride: "fixture/service", Files: files})
	if snapshot != nil {
		cleanup(t, manager, snapshot.SnapshotID)
	}
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("changed directory was published: %v", err)
	}
	list, err := manager.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("failed capture remained usable: %v %v", list, err)
	}
}

func TestLocalFolderModeRejectsGitRevision(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeFile(t, directory, "main.go", "package main\n")
	manager := newTestManager(t)
	snapshot, err := manager.Create(context.Background(), Source{Raw: directory, Kind: KindDir, Ref: "main"})
	if snapshot != nil {
		cleanup(t, manager, snapshot.SnapshotID)
	}
	if err == nil {
		t.Fatal("a Git revision was silently ignored by folder mode")
	}
}
