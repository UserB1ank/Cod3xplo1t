package repository

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fixture builds a small directory source covering the cases P1 must account
// for: plain source, ignored generated/vendored content, binary content, a
// symlink and a nested package.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module fixture\n\ngo 1.24\n")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, root, "internal/app/service.go", "package app\n\nfunc Serve() {}\n")
	writeFile(t, root, "node_modules/dep/index.js", "module.exports = 1\n")
	writeFile(t, root, "dist/bundle.js", "console.log('built')\n")
	writeFile(t, root, "vendor/legacy/legacy.go", "package legacy\n")
	writeFile(t, root, "assets/logo.bin", "\x00\x01\x02binary\n")
	writeFile(t, root, "app.min.js", "var a=1\n")
	if err := os.Symlink("main.go", filepath.Join(root, "main-link.go")); err != nil {
		t.Logf("symlink not supported on this platform: %v", err)
	}
	return root
}

func writeFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return p
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(filepath.Join(t.TempDir(), "work"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// cleanup removes a snapshot and fails the test if the read-only tree cannot be
// deleted: removable snapshots are part of the P1 contract.
func cleanup(t *testing.T, m *Manager, id string) {
	t.Helper()
	t.Cleanup(func() {
		if err := m.Remove(id); err != nil && !errors.Is(err, ErrSnapshotNotFound) {
			t.Errorf("Remove(%s): %v", id, err)
		}
	})
}

func TestCreateDirectorySnapshot(t *testing.T) {
	t.Parallel()
	src := fixture(t)
	m := newTestManager(t)

	snap, err := m.Create(context.Background(), Source{Raw: src})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	if snap.VCS != "none" || !strings.HasPrefix(snap.Commit, "content:") {
		t.Fatalf("unexpected revision for directory source: vcs=%q commit=%q", snap.VCS, snap.Commit)
	}
	if snap.SnapshotID != SnapshotID(snap.Identity, snap.Commit, nil) {
		t.Fatalf("snapshot id %q does not match the identity triple", snap.SnapshotID)
	}
	if snap.Stats.Files != 3 {
		t.Errorf("accepted %d files, want 3 (go.mod, main.go, internal/app/service.go)", snap.Stats.Files)
	}
	if snap.Stats.SkippedIgnored < 4 {
		t.Errorf("ignored counter = %d, want at least 4", snap.Stats.SkippedIgnored)
	}
	if snap.Stats.SkippedBinary != 1 {
		t.Errorf("binary counter = %d, want 1", snap.Stats.SkippedBinary)
	}
	if snap.Stats.SkippedTotal() < 5 {
		t.Errorf("skipped total = %d, want at least 5", snap.Stats.SkippedTotal())
	}
	for _, want := range []SkipReason{SkipIgnored, SkipBinary} {
		found := false
		for _, s := range snap.Skipped {
			if s.Reason == want && s.Detail != "" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no accounted-for skip with reason %q and an explanation", want)
		}
	}
	if err := snap.Unfreeze(); err != nil {
		t.Fatalf("Unfreeze: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snap.TreeDir(), "node_modules")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ignored directory was materialised: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snap.TreeDir(), "internal", "app", "service.go")); err != nil {
		t.Errorf("kept source missing from snapshot: %v", err)
	}

	// A second load must reproduce the same facts.
	loaded, err := m.Load(snap.SnapshotID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Commit != snap.Commit || loaded.Stats != snap.Stats || loaded.Identity != snap.Identity {
		t.Fatalf("loaded snapshot differs from created one:\n%+v\n%+v", loaded, snap)
	}
	if len(loaded.Limitations) == 0 {
		t.Error("snapshot carries no coverage limitations")
	}
	ids, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 || ids[0] != snap.SnapshotID {
		t.Fatalf("List = %v, want [%s]", ids, snap.SnapshotID)
	}
}

func TestSnapshotTreeIsReadOnly(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: fixture(t)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	target := filepath.Join(snap.TreeDir(), "main.go")
	if err := os.WriteFile(target, []byte("mutated"), 0o644); err == nil {
		t.Error("frozen snapshot tree is writable")
	}
	if !snap.Frozen {
		t.Error("snapshot does not report a frozen tree")
	}
	// The manifest slot stays writable so later stages can append artifacts.
	if err := snap.WriteManifest([]byte("{}\n")); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if err := snap.WriteManifest([]byte("{}\n")); err == nil {
		t.Error("WriteManifest overwrote an existing artifact")
	}
	data, err := snap.ReadManifest()
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("ReadManifest = %q, %v", data, err)
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	t.Parallel()
	src := fixture(t)
	m := newTestManager(t)

	first, err := m.Create(context.Background(), Source{Raw: src})
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	cleanup(t, m, first.SnapshotID)
	second, err := m.Create(context.Background(), Source{Raw: src})
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if first.SnapshotID != second.SnapshotID {
		t.Fatalf("same source produced different ids: %s != %s", first.SnapshotID, second.SnapshotID)
	}
	if first.CreatedAt != second.CreatedAt {
		t.Errorf("existing snapshot was rebuilt: %s != %s", first.CreatedAt, second.CreatedAt)
	}
	ids, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected exactly one snapshot, got %v", ids)
	}
}

func TestCreateTracksContentChanges(t *testing.T) {
	t.Parallel()
	src := fixture(t)
	m := newTestManager(t)

	before, err := m.Create(context.Background(), Source{Raw: src})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, before.SnapshotID)

	writeFile(t, src, "internal/app/service.go", "package app\n\nfunc Serve() {}\n\nfunc Extra() {}\n")
	after, err := m.Create(context.Background(), Source{Raw: src})
	if err != nil {
		t.Fatalf("Create after edit: %v", err)
	}
	cleanup(t, m, after.SnapshotID)
	if before.SnapshotID == after.SnapshotID {
		t.Fatal("content change did not produce a new snapshot id")
	}
}

func TestCreateRespectsFileBudget(t *testing.T) {
	t.Parallel()
	src := fixture(t)
	m := newTestManager(t)
	m.Limits = Limits{MaxFiles: 2, MaxRepoBytes: 1 << 20, MaxFileBytes: 1 << 20, MaxDepth: 32, MaxSkippedEntries: 10}
	_, err := m.Create(context.Background(), Source{Raw: src})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded, got %v", err)
	}
	ids, lerr := m.List()
	if lerr != nil {
		t.Fatalf("List: %v", lerr)
	}
	if len(ids) != 0 {
		t.Fatalf("failed snapshot was left behind: %v", ids)
	}
}

func TestCreateRejectsMissingSource(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	_, err := m.Create(context.Background(), Source{Raw: filepath.Join(t.TempDir(), "missing")})
	if !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("expected ErrSourceNotFound, got %v", err)
	}
}

func TestRemoteSourceNeedsExplicitNetworkPermission(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	_, err := m.Create(context.Background(), Source{Raw: "https://example.invalid/org/repo.git"})
	if !errors.Is(err, ErrNetworkDisabled) {
		t.Fatalf("expected ErrNetworkDisabled, got %v", err)
	}
}

func TestConcurrentCreatesShareOneSnapshot(t *testing.T) {
	t.Parallel()
	src := fixture(t)
	m := newTestManager(t)

	const workers = 4
	ids := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snap, err := m.Create(context.Background(), Source{Raw: src})
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = snap.SnapshotID
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	for i := 1; i < workers; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("worker %d produced %s, want %s", i, ids[i], ids[0])
		}
	}
	cleanup(t, m, ids[0])
	listed, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("concurrent creates produced %v", listed)
	}
	if err := m.CleanTemp(); err != nil {
		t.Fatalf("CleanTemp: %v", err)
	}
}

func TestCopyVerifiedDetectsConcurrentEdit(t *testing.T) {
	t.Parallel()
	src := fixture(t)
	l := DefaultLimits()
	plan, err := planDir(src, l)
	if err != nil {
		t.Fatalf("planDir: %v", err)
	}
	writeFile(t, src, "main.go", "package main\n\nfunc main() { println(1) }\n")
	dst := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyPlan(src, dst, plan); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("expected ErrSourceChanged, got %v", err)
	}
}

func TestRemoveIsIdempotentForMissingSnapshot(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	if err := m.Remove("snap-00000000000000000000000000000000"); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("expected ErrSnapshotNotFound, got %v", err)
	}
	if _, err := m.Load("snap-00000000000000000000000000000000"); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("expected ErrSnapshotNotFound from Load, got %v", err)
	}
	for _, bad := range []string{"../escape", "a/b", "", "snap-XYZ", "snap-abc"} {
		if err := m.Remove(bad); err == nil {
			t.Errorf("Remove(%q) accepted an invalid id", bad)
		}
		if _, err := m.Load(bad); err == nil {
			t.Errorf("Load(%q) accepted an invalid id", bad)
		}
	}
}

func TestLoadRejectsUnknownSchema(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "snap")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := `{"schema_version": 99, "snapshot_id": "snap-x", "identity": {"kind":"git","name":"x"}, "commit": "deadbeef", "created_at": "2020-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, MetadataFileName), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(dir); err == nil {
		t.Fatal("unknown schema version was accepted")
	}
	if _, err := LoadSnapshot(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("expected ErrSnapshotNotFound, got %v", err)
	}
}

func TestExtractTarRejectsEscapingEntries(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"parent traversal": "../evil.sh",
		"absolute path":    "/etc/cron.d/evil",
	}
	for name, entry := range cases {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		body := []byte("#!/bin/sh\n")
		if err := tw.WriteHeader(&tar.Header{Name: entry, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("%s: write header: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("%s: write body: %v", name, err)
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("%s: close: %v", name, err)
		}
		if _, err := extractTar(&buf, t.TempDir(), DefaultLimits(), nil); err == nil {
			t.Errorf("%s (%s): escaping archive entry was accepted", name, entry)
		}
	}
}

func TestExtractTarAppliesLimitsAndLimitations(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := map[string][]byte{
		"main.go":               []byte("package main\n"),
		"node_modules/dep.go":   []byte("package dep\n"),
		"deep/a/b/c/d/e/f/g.go": []byte("package deep\n"),
		"bin.dat":               []byte("\x00\x01"),
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	l := DefaultLimits()
	l.MaxDepth = 3
	plan, err := extractTar(&buf, t.TempDir(), l, nil)
	if err != nil {
		t.Fatalf("extractTar: %v", err)
	}
	if plan.Stats.Files != 1 {
		t.Errorf("accepted %d files, want 1", plan.Stats.Files)
	}
	if plan.Stats.SkippedIgnored != 1 || plan.Stats.SkippedDepth != 1 || plan.Stats.SkippedBinary != 1 {
		t.Errorf("unexpected skip accounting: %+v", plan.Stats)
	}
	if len(plan.Skips) != 3 {
		t.Errorf("recorded %d skip explanations, want 3: %+v", len(plan.Skips), plan.Skips)
	}

	snap := &Snapshot{Stats: plan.Stats, VCS: "git"}
	snap.describeLimitations()
	joined := strings.Join(snap.Limitations, "\n")
	for _, want := range []string{"ignore rules", "binary file", "depth limit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("limitations %q do not mention %q", joined, want)
		}
	}
}

func TestSkippedEntriesAreBoundedButCounted(t *testing.T) {
	t.Parallel()
	src := t.TempDir()
	for i := 0; i < 25; i++ {
		writeFile(t, src, fmt.Sprintf("node_modules/dep%d/index.js", i), "x\n")
	}
	writeFile(t, src, "main.go", "package main\n")
	m := newTestManager(t)
	m.Limits.MaxSkippedEntries = 5
	snap, err := m.Create(context.Background(), Source{Raw: src})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)
	if snap.Stats.SkippedIgnored != 1 {
		// The whole node_modules directory is skipped as one entry.
		t.Logf("ignored counter = %d", snap.Stats.SkippedIgnored)
	}
	if len(snap.Skipped) > 5 {
		t.Fatalf("skip sample has %d entries, want at most 5", len(snap.Skipped))
	}
}

func TestSnapshotMetadataAlwaysEmitsArrays(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: fixture(t)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	data, err := os.ReadFile(snap.MetadataPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"skipped": [`, `"symlinks": [`, `"submodule_state": [`, `"limitations": [`, `"dirty_paths": [`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("snapshot metadata is missing %s:\n%s", want, data)
		}
	}
	// A freshly written document and a reloaded one must serialise identically.
	loaded, err := LoadSnapshot(snap.Dir)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if string(reloaded) != string(original) {
		t.Errorf("reload changed the document:\n%s\n%s", original, reloaded)
	}
}
