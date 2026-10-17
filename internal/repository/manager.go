package repository

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Manager owns a snapshot workspace. It never writes inside the user's original
// repository: everything it produces lives under Root.
type Manager struct {
	// Root is the workspace root; snapshots live in Root/snapshots and clone
	// caches in Root/cache/git.
	Root string
	// Limits are the default limits applied to every snapshot. Zero values fall
	// back to DefaultLimits.
	Limits Limits
	// Engine identifies this component in snapshot metadata.
	Engine EngineInfo
	// AllowNetwork permits cloning remote git URLs. It is false by default so
	// that a misconfigured caller cannot reach the network accidentally.
	AllowNetwork bool
	// GitBin overrides the git executable (default "git").
	GitBin string
	// Freeze makes the snapshotted tree read-only once it is complete.
	Freeze bool

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

// DefaultEngine is the engine identity written into new snapshots.
var DefaultEngine = EngineInfo{Name: "codexploit/repository", Version: "0.1.0"}

// Option customises a Manager at construction time.
type Option func(*Manager)

// WithLimits sets the default limits.
func WithLimits(l Limits) Option { return func(m *Manager) { m.Limits = l } }

// WithEngine overrides the engine identity recorded in metadata.
func WithEngine(e EngineInfo) Option { return func(m *Manager) { m.Engine = e } }

// WithAllowNetwork enables cloning of remote git URLs.
func WithAllowNetwork(allow bool) Option { return func(m *Manager) { m.AllowNetwork = allow } }

// WithGitBin overrides the git executable.
func WithGitBin(bin string) Option { return func(m *Manager) { m.GitBin = bin } }

// WithFreeze controls whether the snapshot tree is made read-only.
func WithFreeze(freeze bool) Option { return func(m *Manager) { m.Freeze = freeze } }

// NewManager creates a workspace at root, creating the snapshots directory.
func NewManager(root string, opts ...Option) (*Manager, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("repository: empty workspace root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		Root:   abs,
		Engine: DefaultEngine,
		Freeze: true,
		locks:  make(map[string]*sync.Mutex),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.Limits = m.Limits.WithDefaults()
	if err := m.Limits.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.snapshotsDir(), 0o755); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) snapshotsDir() string {
	return filepath.Join(m.Root, filepath.FromSlash(SnapshotsDirName))
}

// validSnapshotID accepts exactly the ids this package generates, so that an id
// coming from an API call can never be used to address another directory.
func validSnapshotID(id string) bool {
	if !strings.HasPrefix(id, snapshotIDPrefix) {
		return false
	}
	hex := strings.TrimPrefix(id, snapshotIDPrefix)
	if len(hex) != snapshotIDBytes*2 {
		return false
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// snapshotDir is the final location of a snapshot.
func (m *Manager) snapshotDir(id string) string {
	return filepath.Join(m.snapshotsDir(), id)
}

// lock serialises work on the same repository identity so two concurrent
// snapshots of one repository cannot interleave their temp directories.
func (m *Manager) lock(key string) func() {
	m.locksMu.Lock()
	l, ok := m.locks[key]
	if !ok {
		l = &sync.Mutex{}
		m.locks[key] = l
	}
	m.locksMu.Unlock()
	l.Lock()
	return l.Unlock
}

// Create pins the source to an immutable revision and materialises a snapshot.
// It is idempotent: an existing snapshot with the same identity triple is
// returned unchanged instead of being rebuilt.
func (m *Manager) Create(ctx context.Context, src Source) (*Snapshot, error) {
	l := m.Limits.WithDefaults()
	if err := l.Validate(); err != nil {
		return nil, err
	}
	res, err := m.Resolve(ctx, src)
	if err != nil {
		return nil, err
	}
	unlock := m.lock(res.Identity.Kind + ":" + res.Identity.Name)
	defer unlock()

	snap := &Snapshot{
		SchemaVersion: SchemaVersion,
		Identity:      res.Identity,
		Limits:        l,
		Engine:        m.Engine,
		CreatedAt:     ageOf(timeNow().UTC()),
	}

	var plan *dirPlan
	var directory fs.FS
	switch res.Kind {
	case KindDir:
		directory = res.Source.Files
		if directory == nil {
			root, openErr := os.OpenRoot(res.Path)
			if openErr != nil {
				return nil, openErr
			}
			defer root.Close()
			directory = root.FS()
		}
		snap.VCS = "none"
		snap.RequestedRef = ""
		plan, err = planDirectory(directory, l)
		if err != nil {
			return nil, err
		}
		snap.Commit = contentRevision(plan.Digest)
	case KindLocalGit, KindRemoteGit:
		snap.VCS = "git"
		ref := res.Source.Ref
		if ref == "" {
			ref = "HEAD"
		}
		snap.RequestedRef = ref
		commit, cerr := m.resolveCommit(ctx, res.Path, res.Source.Ref)
		if cerr != nil {
			return nil, cerr
		}
		snap.Commit = commit
		subs, serr := m.submoduleStates(ctx, res.Path, commit)
		if serr != nil {
			return nil, serr
		}
		snap.SubmoduleState = subs
		if len(subs) > 0 && l.Submodules == SubmoduleRequire {
			return nil, fmt.Errorf("repository: %s has %d submodule(s) and submodule policy is %q, which cannot be satisfied", res.Identity.Name, len(subs), l.Submodules)
		}
		if res.Kind == KindLocalGit {
			dirty, paths, count, derr := m.worktreeStatus(ctx, res.Path)
			if derr != nil {
				return nil, derr
			}
			snap.WorktreeDirty, snap.DirtyPaths, snap.DirtyPathCount = dirty, paths, count
		}
	default:
		return nil, fmt.Errorf("repository: unsupported source kind %q", res.Kind)
	}

	snap.SnapshotID = SnapshotID(snap.Identity, snap.Commit, snap.SubmoduleState)
	final := m.snapshotDir(snap.SnapshotID)
	if existing, lerr := LoadSnapshot(final); lerr == nil {
		if existing.Commit != snap.Commit || existing.Identity != snap.Identity {
			return nil, fmt.Errorf("repository: %s already exists but describes %s@%s instead of %s@%s",
				final, existing.Identity.Name, existing.Commit, snap.Identity.Name, snap.Commit)
		}
		return existing, nil
	}

	tmp, err := os.MkdirTemp(m.snapshotsDir(), ".tmp-"+snap.SnapshotID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	tree := filepath.Join(tmp, TreeDirName)
	if err := os.MkdirAll(tree, 0o755); err != nil {
		return nil, err
	}

	switch res.Kind {
	case KindDir:
		if err := copyDirectory(directory, tree, plan); err != nil {
			return nil, err
		}
		latest, err := planDirectory(directory, l)
		if err != nil {
			return nil, fmt.Errorf("%w: directory cannot be revalidated", ErrSourceChanged)
		}
		if latest.Digest != plan.Digest {
			return nil, ErrSourceChanged
		}
	default:
		plan, err = m.extractCommitTree(ctx, res.Path, snap.Commit, tree, l, snap.SubmoduleState)
		if err != nil {
			return nil, err
		}
	}

	snap.Stats = plan.Stats
	snap.Skipped = plan.Skips
	snap.Symlinks = plan.Symlinks
	snap.LFS = scanLFSAttributes(tree)
	if snap.LFS.Detected && l.LFS == LFSRequire {
		return nil, fmt.Errorf("repository: %s tracks files with Git LFS and LFS policy is %q, but Codexploit never fetches LFS content", res.Identity.Name, l.LFS)
	}
	snap.describeLimitations()

	snap.Dir = tmp
	if err := snap.Save(); err != nil {
		return nil, err
	}
	if m.Freeze {
		if err := snap.Freeze(); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		// A concurrent creator won the race: reuse its snapshot.
		if existing, lerr := LoadSnapshot(final); lerr == nil {
			return existing, nil
		}
		return nil, err
	}
	snap.Dir = final
	return snap, nil
}

// describeLimitations records every capability boundary that applies to this
// snapshot, so downstream consumers never read an incomplete tree as a complete
// one.
func (s *Snapshot) describeLimitations() {
	st := s.Stats
	if st.SkippedIgnored > 0 {
		s.addLimitation("%d path(s) excluded by ignore rules (generated, vendored or cached content); use limits.include_ignored_dirs to override", st.SkippedIgnored)
	}
	if st.SkippedBinary > 0 {
		s.addLimitation("%d binary file(s) excluded; set limits.allow_binary to keep them", st.SkippedBinary)
	}
	if st.SkippedLarge > 0 {
		s.addLimitation("%d file(s) exceeded the per-file size limit", st.SkippedLarge)
	}
	if st.SkippedDepth > 0 {
		s.addLimitation("%d path(s) exceeded the depth limit", st.SkippedDepth)
	}
	if st.SkippedUnreadable > 0 {
		s.addLimitation("%d path(s) could not be read", st.SkippedUnreadable)
	}
	if st.SkippedOther > 0 {
		s.addLimitation("%d special file(s) (socket, device, fifo or hardlink) excluded", st.SkippedOther)
	}
	if st.SkippedLimit > 0 {
		s.addLimitation("%d file(s) dropped because the file or byte budget was reached", st.SkippedLimit)
	}
	if len(s.SubmoduleState) > 0 {
		s.addLimitation("%d submodule gitlink(s) pinned but contents not expanded; analysis covers the parent tree only", len(s.SubmoduleState))
	}
	if len(s.Symlinks) > 0 {
		s.addLimitation("%d symlink(s) recorded but not materialised; targets are not followed", len(s.Symlinks))
	}
	if s.LFS.Detected {
		s.addLimitation("Git LFS tracked files are stored as pointer files; LFS content was not fetched")
	}
	if s.WorktreeDirty {
		s.addLimitation("source working tree had %d uncommitted change(s) at snapshot time; this snapshot reflects commit %s only", s.DirtyPathCount, shortSHA(s.Commit))
	}
	if s.VCS == "none" {
		s.addLimitation("directory source without VCS metadata: the revision is a content digest of the accepted file set, not a commit")
	}
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// Load reads a snapshot from the workspace by id.
func (m *Manager) Load(id string) (*Snapshot, error) {
	if !validSnapshotID(id) {
		return nil, fmt.Errorf("repository: invalid snapshot id %q", id)
	}
	return LoadSnapshot(m.snapshotDir(id))
}

// List returns the snapshot ids present in the workspace, sorted.
func (m *Manager) List() ([]string, error) {
	entries, err := os.ReadDir(m.snapshotsDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if _, err := os.Stat(filepath.Join(m.snapshotsDir(), e.Name(), MetadataFileName)); err != nil {
			continue
		}
		ids = append(ids, e.Name())
	}
	sort.Strings(ids)
	return ids, nil
}

// Remove deletes a snapshot, restoring write permission first so that read-only
// trees can be removed on every platform.
func (m *Manager) Remove(id string) error {
	if !validSnapshotID(id) {
		return fmt.Errorf("repository: invalid snapshot id %q", id)
	}
	dir := m.snapshotDir(id)
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrSnapshotNotFound, id)
		}
		return err
	}
	if err := unfreezeTree(dir); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// CleanTemp removes leftover build directories from interrupted snapshots.
func (m *Manager) CleanTemp() error {
	entries, err := os.ReadDir(m.snapshotsDir())
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		p := filepath.Join(m.snapshotsDir(), e.Name())
		if err := unfreezeTree(p); err != nil {
			errs = append(errs, err)
		}
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
