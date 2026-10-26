package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectSourceIsOneReadOnlyDirectoryWithoutContentVersions(t *testing.T) {
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	src := Source{Raw: dir, Kind: KindDir, NameOverride: "projects/example/source"}
	first, err := m.ImportSource(t.Context(), src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Remove(first.SnapshotID) })
	if first.Commit != "project-source" || !first.Frozen {
		t.Fatalf("source = %+v", first)
	}
	if err := os.WriteFile(file, []byte("package changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := m.ImportSource(t.Context(), src)
	if err != nil {
		t.Fatal(err)
	}
	if again.SnapshotID != first.SnapshotID {
		t.Fatal("source was versioned by content")
	}
	data, err := os.ReadFile(filepath.Join(again.TreeDir(), "main.go"))
	if err != nil || string(data) != "package main\n" {
		t.Fatalf("source changed: %q %v", data, err)
	}
	info, err := os.Stat(filepath.Join(first.TreeDir(), "main.go"))
	if err != nil || info.Mode().Perm()&0222 != 0 {
		t.Fatal("source is writable")
	}
}
