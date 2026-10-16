package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// cleanupWorkspace removes every snapshot through the manager. Frozen trees are
// read-only, so this is the only supported way to delete them, and t.TempDir's
// cleanup would otherwise fail.
func cleanupWorkspace(t *testing.T, workspace string) {
	t.Helper()
	t.Cleanup(func() {
		mgr, err := repository.NewManager(workspace)
		if err != nil {
			t.Errorf("NewManager for cleanup: %v", err)
			return
		}
		ids, err := mgr.List()
		if err != nil {
			t.Errorf("list for cleanup: %v", err)
		}
		for _, id := range ids {
			if err := mgr.Remove(id); err != nil {
				t.Errorf("cleanup remove %s: %v", id, err)
			}
		}
	})
}

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range map[string]string{
		"go.mod":  "module example.invalid/cli\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
		"main.go": "package main\n\nimport \"github.com/gin-gonic/gin\"\n\nfunc main() { gin.Default().Run() }\n",
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// captureStdout runs fn with stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), runErr
}

func TestRunManifestWritesManifestNextToSnapshot(t *testing.T) {
	// Not parallel: this test redirects the process-wide stdout.
	source := writeFixture(t)
	workspace := filepath.Join(t.TempDir(), "work")
	cleanupWorkspace(t, workspace)

	out, err := captureStdout(t, func() error {
		return runManifest(context.Background(), []string{"--source", source, "--workspace", workspace, "--json"})
	})
	if err != nil {
		t.Fatalf("runManifest: %v", err)
	}
	var manifest analysis.Manifest
	if err := json.Unmarshal([]byte(out), &manifest); err != nil {
		t.Fatalf("stdout is not a manifest: %v\n%s", err, out)
	}
	if manifest.SnapshotID == "" || manifest.AnalysisID == "" {
		t.Fatalf("manifest ids are empty: %+v", manifest)
	}
	if manifest.PrimaryLanguage != "Go" {
		t.Errorf("primary language = %q, want Go", manifest.PrimaryLanguage)
	}
	stored, err := os.ReadFile(filepath.Join(workspace, "snapshots", manifest.SnapshotID, repository.ManifestFileName))
	if err != nil {
		t.Fatalf("manifest file not written: %v", err)
	}
	if !strings.Contains(string(stored), manifest.AnalysisID) {
		t.Error("stored manifest does not match the printed one")
	}
	// The frozen tree must reject writes.
	if err := os.WriteFile(filepath.Join(workspace, "snapshots", manifest.SnapshotID, "repo", "main.go"), []byte("x"), 0o644); err == nil {
		t.Error("snapshot tree is writable")
	}
}

func TestRunSnapshotSummaryAndIdempotence(t *testing.T) {
	source := writeFixture(t)
	workspace := filepath.Join(t.TempDir(), "work")
	cleanupWorkspace(t, workspace)

	first, err := captureStdout(t, func() error {
		return runSnapshot(context.Background(), []string{"--source", source, "--workspace", workspace, "--json"})
	})
	if err != nil {
		t.Fatalf("runSnapshot: %v", err)
	}
	var snap repository.Snapshot
	if err := json.Unmarshal([]byte(first), &snap); err != nil {
		t.Fatalf("stdout is not a snapshot: %v\n%s", err, first)
	}
	second, err := captureStdout(t, func() error {
		return runSnapshot(context.Background(), []string{"--source", source, "--workspace", workspace, "--json"})
	})
	if err != nil {
		t.Fatalf("second runSnapshot: %v", err)
	}
	var again repository.Snapshot
	if err := json.Unmarshal([]byte(second), &again); err != nil {
		t.Fatalf("second stdout is not a snapshot: %v", err)
	}
	if snap.SnapshotID != again.SnapshotID || snap.CreatedAt != again.CreatedAt {
		t.Errorf("snapshot was rebuilt: %s/%s vs %s/%s", snap.SnapshotID, snap.CreatedAt, again.SnapshotID, again.CreatedAt)
	}
	if snap.WorktreeDirty || snap.VCS != "none" {
		t.Errorf("unexpected snapshot flags: vcs=%q dirty=%v", snap.VCS, snap.WorktreeDirty)
	}
}

func TestRunSnapshotsListAndRemove(t *testing.T) {
	source := writeFixture(t)
	workspace := filepath.Join(t.TempDir(), "work")

	var snap repository.Snapshot
	out, err := captureStdout(t, func() error {
		return runSnapshot(context.Background(), []string{"--source", source, "--workspace", workspace, "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &snap); err != nil {
		t.Fatal(err)
	}

	listed, err := captureStdout(t, func() error {
		return runSnapshots(context.Background(), []string{"list", "--workspace", workspace})
	})
	if err != nil {
		t.Fatalf("snapshots list: %v", err)
	}
	if !strings.Contains(listed, snap.SnapshotID) {
		t.Errorf("list output does not contain the snapshot:\n%s", listed)
	}

	if _, err := captureStdout(t, func() error {
		return runSnapshots(context.Background(), []string{"remove", "--workspace", workspace, "--id", snap.SnapshotID})
	}); err != nil {
		t.Fatalf("snapshots remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "snapshots", snap.SnapshotID)); err == nil {
		t.Error("snapshot directory survived removal")
	}
}

func TestCommandValidation(t *testing.T) {
	t.Parallel()
	source := writeFixture(t)
	cases := map[string][]string{
		"missing source":     {},
		"unexpected operand": {"--source", source, "extra"},
		"unknown flag":       {"--source", source, "--nope"},
	}
	for name, args := range cases {
		if _, err := parseCommon("snapshot", args); err == nil {
			t.Errorf("%s: parseCommon accepted %v", name, args)
		}
	}
	if _, err := parseCommon("snapshot", []string{"--source", source, "--ref", "main"}); err != nil {
		t.Errorf("valid flags were rejected: %v", err)
	}
	if err := runSnapshots(context.Background(), nil); err == nil {
		t.Error("runSnapshots accepted an empty subcommand")
	}
	if err := runSnapshots(context.Background(), []string{"remove"}); err == nil {
		t.Error("runSnapshots remove accepted a missing --id")
	}
	if err := runSnapshots(context.Background(), []string{"nope"}); err == nil {
		t.Error("runSnapshots accepted an unknown subcommand")
	}
}
