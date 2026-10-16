package repository

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo is a throwaway repository with a pinned committer identity so that
// commit SHAs are reproducible on every machine.
type gitRepo struct {
	t   *testing.T
	dir string
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	r := &gitRepo{t: t, dir: dir}
	r.git("-c", "init.defaultBranch=main", "init", "-q")
	r.git("symbolic-ref", "HEAD", "refs/heads/main")
	return r
}

func (r *gitRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=example",
		"GIT_AUTHOR_EMAIL=example",
		"GIT_COMMITTER_NAME=example",
		"GIT_COMMITTER_EMAIL=example",
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2024-01-01T00:00:00Z",
		"LC_ALL=C",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *gitRepo) write(rel, content string) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *gitRepo) commit(msg string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func TestCreateGitSnapshotPinsCommit(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n\nfunc main() {}\n")
	repo.write("internal/app/service.go", "package app\n")
	head := repo.commit("initial")

	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	if snap.VCS != "git" {
		t.Errorf("vcs = %q, want git", snap.VCS)
	}
	if snap.Commit != head {
		t.Errorf("commit = %q, want %q", snap.Commit, head)
	}
	if !isHexSHA(snap.Commit) {
		t.Errorf("commit %q is not a full SHA", snap.Commit)
	}
	if snap.SnapshotID != SnapshotID(snap.Identity, head, nil) {
		t.Errorf("snapshot id does not match hash(%s, %s)", snap.Identity.Name, head)
	}
	if snap.WorktreeDirty {
		t.Error("clean tree reported as dirty")
	}
	if _, err := os.Stat(filepath.Join(snap.TreeDir(), ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("VCS metadata leaked into the snapshot tree: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(snap.TreeDir(), "main.go"))
	if err != nil {
		t.Fatalf("read snapshotted file: %v", err)
	}
	if !bytes.Contains(body, []byte("func main")) {
		t.Errorf("unexpected snapshotted content: %q", body)
	}

	// Re-running on the same commit must be idempotent.
	again, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if again.SnapshotID != snap.SnapshotID || again.CreatedAt != snap.CreatedAt {
		t.Errorf("same commit produced a different snapshot: %s vs %s", again.SnapshotID, snap.SnapshotID)
	}
}

func TestGitSnapshotRecordsDirtyWorktreeWithoutIncludingIt(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n\nvar v = 1\n")
	repo.commit("initial")

	repo.write("main.go", "package main\n\nvar v = 2\n")
	repo.write("untracked.go", "package main\n")
	repo.git("add", "untracked.go")

	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	if !snap.WorktreeDirty {
		t.Fatal("dirty worktree was not recorded")
	}
	if snap.DirtyPathCount < 2 {
		t.Errorf("dirty path count = %d, want at least 2", snap.DirtyPathCount)
	}
	if !contains(snap.DirtyPaths, "main.go") {
		t.Errorf("dirty paths %v do not include main.go", snap.DirtyPaths)
	}
	body, err := os.ReadFile(filepath.Join(snap.TreeDir(), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("v = 2")) {
		t.Error("uncommitted change leaked into the snapshot tree")
	}
	if !mentions(snap.Limitations, "uncommitted change") {
		t.Errorf("limitations do not state that the snapshot reflects the commit only: %v", snap.Limitations)
	}
}

func TestGitSnapshotPinsExplicitOlderCommit(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n\nconst version = \"v1\"\n")
	first := repo.commit("v1")
	repo.write("main.go", "package main\n\nconst version = \"v2\"\n")
	repo.commit("v2")

	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir, Ref: first})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	if snap.Commit != first {
		t.Fatalf("commit = %q, want %q", snap.Commit, first)
	}
	if snap.RequestedRef != first {
		t.Errorf("requested ref = %q, want %q", snap.RequestedRef, first)
	}
	body, err := os.ReadFile(filepath.Join(snap.TreeDir(), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"v1"`)) {
		t.Errorf("snapshot does not contain the pinned revision: %q", body)
	}
}

func TestGitSnapshotRejectsUnknownRevision(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n")
	repo.commit("initial")
	m := newTestManager(t)

	if _, err := m.Create(context.Background(), Source{Raw: repo.dir, Ref: "no-such-ref"}); err == nil {
		t.Error("unknown revision was accepted")
	}
	if _, err := m.Create(context.Background(), Source{Raw: repo.dir, Ref: "--upload-pack=evil"}); err == nil {
		t.Error("option-like revision was accepted")
	}
}

func TestGitSubmoduleGitlinkIsRecordedNotExpanded(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n")
	base := repo.commit("initial")
	// A gitlink entry is what a submodule looks like in the parent tree. It must
	// be staged after `git add -A`, otherwise git would treat the missing
	// directory as a deletion.
	repo.git("update-index", "--add", "--cacheinfo", "160000,"+base+",deps/lib")
	repo.git("commit", "-q", "-m", "add submodule gitlink")
	dirty := repo.git("rev-parse", "HEAD")

	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	if len(snap.SubmoduleState) != 1 {
		t.Fatalf("submodule state = %+v, want one gitlink", snap.SubmoduleState)
	}
	got := snap.SubmoduleState[0]
	if got.Path != "deps/lib" || got.Commit != base || got.Status != "pinned" {
		t.Errorf("unexpected gitlink record: %+v", got)
	}
	if !mentions(snap.Limitations, "submodule gitlink") {
		t.Errorf("limitations do not state that submodule content is missing: %v", snap.Limitations)
	}
	if snap.SnapshotID != SnapshotID(snap.Identity, dirty, snap.SubmoduleState) {
		t.Error("submodule state was not part of the snapshot id")
	}
	if _, err := os.Stat(filepath.Join(snap.TreeDir(), "deps", "lib")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unexpanded submodule content appeared in the tree: %v", err)
	}

	// The strict policy must refuse rather than return a parent-only tree.
	strict := newTestManager(t)
	strict.Limits.Submodules = SubmoduleRequire
	if _, err := strict.Create(context.Background(), Source{Raw: repo.dir}); err == nil {
		t.Error("submodule policy \"require\" did not reject a repository with submodules")
	}
}

func TestGitSnapshotRecordsSymlinks(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n")
	if err := os.Symlink("main.go", filepath.Join(repo.dir, "link.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	repo.commit("initial")

	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)

	if len(snap.Symlinks) != 1 {
		t.Fatalf("symlinks = %+v, want one record", snap.Symlinks)
	}
	if snap.Symlinks[0].Path != "link.go" || snap.Symlinks[0].Target != "main.go" {
		t.Errorf("unexpected symlink record: %+v", snap.Symlinks[0])
	}
	if snap.Stats.SkippedSymlink != 1 {
		t.Errorf("skipped symlink counter = %d, want 1", snap.Stats.SkippedSymlink)
	}
}

func TestGitLFSPolicy(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n")
	repo.write(".gitattributes", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
	repo.commit("initial")

	m := newTestManager(t)
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)
	if !snap.LFS.Detected || !snap.LFS.PointerOnly {
		t.Errorf("LFS detection = %+v, want detected pointer-only state", snap.LFS)
	}
	if !mentions(snap.Limitations, "Git LFS") {
		t.Errorf("limitations do not mention LFS: %v", snap.Limitations)
	}

	strict := newTestManager(t)
	strict.Limits.LFS = LFSRequire
	if _, err := strict.Create(context.Background(), Source{Raw: repo.dir}); err == nil {
		t.Error("LFS policy \"require\" did not reject an LFS repository")
	}
}

func TestIncludeIgnoredDirsOverride(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	repo.write("main.go", "package main\n")
	repo.write("vendor/lib.go", "package vendorlib\n")
	repo.commit("initial")

	m := newTestManager(t)
	m.Limits.IncludeIgnoredDirs = []string{"vendor"}
	snap, err := m.Create(context.Background(), Source{Raw: repo.dir})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanup(t, m, snap.SnapshotID)
	if _, err := os.Stat(filepath.Join(snap.TreeDir(), "vendor", "lib.go")); err != nil {
		t.Fatalf("explicitly included directory is missing: %v", err)
	}
	if snap.Stats.SkippedIgnored != 0 {
		t.Errorf("ignored counter = %d, want 0 once vendor is included", snap.Stats.SkippedIgnored)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func mentions(hay []string, needle string) bool {
	return strings.Contains(strings.Join(hay, "\n"), needle)
}
