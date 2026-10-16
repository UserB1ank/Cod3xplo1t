package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// On-disk snapshot layout:
//
//	<root>/snapshots/<snapshot_id>/snapshot.json              metadata (this file)
//	<root>/snapshots/<snapshot_id>/repository_manifest.json   analysis output (P1 analyzer)
//	<root>/snapshots/<snapshot_id>/repo/...                   frozen source tree
//
// Only the tree is frozen read-only; the snapshot root stays writable so later
// analysis stages can append their own immutable artifacts.
const (
	// MetadataFileName holds the snapshot metadata document.
	MetadataFileName = "snapshot.json"
	// TreeDirName holds the frozen source tree inside a snapshot directory.
	TreeDirName = "repo"
	// ManifestFileName is the analyzer output written next to the tree.
	ManifestFileName = "repository_manifest.json"
	// SnapshotsDirName is the sub-directory of the workspace root holding snapshots.
	SnapshotsDirName = "snapshots"
)

// SchemaVersion is the version of the snapshot metadata document. Bump it when
// a field changes meaning; readers must reject unknown versions.
const SchemaVersion = 1

// EngineInfo identifies the component that produced a document, so consumers
// never have to guess which version wrote the facts they are reading.
type EngineInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SkipReason explains why a file was left out of the snapshot tree.
type SkipReason string

const (
	SkipIgnored    SkipReason = "ignored"        // matched an ignore rule
	SkipBinary     SkipReason = "binary"         // binary content, policy denies storage
	SkipLarge      SkipReason = "file_too_large" // above MaxFileBytes
	SkipDepth      SkipReason = "max_depth"      // below MaxDepth
	SkipSymlink    SkipReason = "symlink"        // symlinks are recorded, not followed
	SkipUnreadable SkipReason = "unreadable"     // could not be read
	SkipOther      SkipReason = "special_file"   // socket, device, fifo, hardlink
	SkipSubmodule  SkipReason = "submodule"      // content not present in parent tree
	SkipLimit      SkipReason = "limit"          // files/bytes budget reached
)

// SkippedEntry is one accounted-for omission.
type SkippedEntry struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
	Detail string     `json:"detail,omitempty"`
}

// Stats counts what happened while materialising the snapshot. Counters are
// exact; the Skipped entry list is a bounded sample.
type Stats struct {
	Files             int   `json:"files"`
	Bytes             int64 `json:"bytes"`
	Dirs              int   `json:"dirs"`
	SkippedIgnored    int   `json:"skipped_ignored"`
	SkippedBinary     int   `json:"skipped_binary"`
	SkippedLarge      int   `json:"skipped_large"`
	SkippedDepth      int   `json:"skipped_depth"`
	SkippedSymlink    int   `json:"skipped_symlink"`
	SkippedUnreadable int   `json:"skipped_unreadable"`
	SkippedOther      int   `json:"skipped_other"`
	SkippedSubmodule  int   `json:"skipped_submodule"`
	SkippedLimit      int   `json:"skipped_limit"`
}

// SkippedTotal is the sum of every skip counter.
func (s Stats) SkippedTotal() int {
	return s.SkippedIgnored + s.SkippedBinary + s.SkippedLarge + s.SkippedDepth +
		s.SkippedSymlink + s.SkippedUnreadable + s.SkippedOther + s.SkippedSubmodule +
		s.SkippedLimit
}

// SubmoduleState is the pinned state of one git submodule. Status is one of
// "initialized", "uninitialized", "modified" or "conflict".
type SubmoduleState struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
	Status string `json:"status"`
}

// SymlinkEntry records a symlink found in the source without materialising it.
type SymlinkEntry struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// LFSState records Git LFS detection. Codexploit never fetches LFS content
// automatically, so tracked files stay as pointer files.
type LFSState struct {
	Detected    bool     `json:"detected"`
	PointerOnly bool     `json:"pointer_only"`
	Attributes  []string `json:"attributes,omitempty"` // attributes files naming filter=lfs
}

// Snapshot is the immutable record of one pinned repository revision.
type Snapshot struct {
	SchemaVersion  int              `json:"schema_version"`
	SnapshotID     string           `json:"snapshot_id"`
	Identity       Identity         `json:"identity"`
	VCS            string           `json:"vcs"` // "git" or "none"
	RequestedRef   string           `json:"requested_ref,omitempty"`
	Commit         string           `json:"commit"`
	SubmoduleState []SubmoduleState `json:"submodule_state"`
	WorktreeDirty  bool             `json:"worktree_dirty"`
	DirtyPaths     []string         `json:"dirty_paths"`
	DirtyPathCount int              `json:"dirty_path_count"`
	Symlinks       []SymlinkEntry   `json:"symlinks"`
	LFS            LFSState         `json:"lfs"`
	Skipped        []SkippedEntry   `json:"skipped"`
	Stats          Stats            `json:"stats"`
	Limits         Limits           `json:"limits"`
	Engine         EngineInfo       `json:"engine"`
	// Limitations lists analysis-capability boundaries that apply to this
	// snapshot, in the same spirit as the graph limits in the design doc: an
	// empty finding is never presented without its coverage statement.
	Limitations []string `json:"limitations"`
	CreatedAt   string   `json:"created_at"`

	// Dir is the snapshot directory on disk. It is derived on load and never
	// part of the persisted document or of SnapshotID.
	Dir string `json:"-"`
	// Frozen reports whether the source tree is currently read-only.
	Frozen bool `json:"-"`
}

// TreeDir is the directory holding the frozen source tree.
func (s *Snapshot) TreeDir() string { return filepath.Join(s.Dir, TreeDirName) }

// MetadataPath is the path of the metadata document.
func (s *Snapshot) MetadataPath() string { return filepath.Join(s.Dir, MetadataFileName) }

// ManifestPath is the path of the analyzer manifest for this snapshot.
func (s *Snapshot) ManifestPath() string { return filepath.Join(s.Dir, ManifestFileName) }

// normalizeLists replaces nil slices with empty ones so a reloaded document has
// the same shape as a freshly created one.
func (s *Snapshot) normalizeLists() {
	if s.Skipped == nil {
		s.Skipped = []SkippedEntry{}
	}
	if s.Symlinks == nil {
		s.Symlinks = []SymlinkEntry{}
	}
	if s.SubmoduleState == nil {
		s.SubmoduleState = []SubmoduleState{}
	}
	if s.DirtyPaths == nil {
		s.DirtyPaths = []string{}
	}
	if s.Limitations == nil {
		s.Limitations = []string{}
	}
}

// sortSkipped orders skip records for stable output.
func (s *Snapshot) sortSkipped() {
	sort.SliceStable(s.Skipped, func(i, j int) bool {
		if s.Skipped[i].Path != s.Skipped[j].Path {
			return s.Skipped[i].Path < s.Skipped[j].Path
		}
		return s.Skipped[i].Reason < s.Skipped[j].Reason
	})
}

// addLimitation appends a unique limitation note.
func (s *Snapshot) addLimitation(format string, args ...any) {
	note := fmt.Sprintf(format, args...)
	for _, existing := range s.Limitations {
		if existing == note {
			return
		}
	}
	s.Limitations = append(s.Limitations, note)
}

// Save writes the metadata document. The document is written atomically so a
// crash cannot leave a half-written snapshot.json behind.
func (s *Snapshot) Save() error {
	if s.Dir == "" {
		return errors.New("repository: snapshot has no directory")
	}
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	s.normalizeLists()
	s.sortSkipped()
	sort.Strings(s.Limitations)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("repository: marshal snapshot metadata: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.Dir, ".snapshot-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.MetadataPath())
}

// LoadSnapshot reads a snapshot directory. Unknown schema versions are refused
// instead of being interpreted optimistically.
func LoadSnapshot(dir string) (*Snapshot, error) {
	data, err := os.ReadFile(filepath.Join(dir, MetadataFileName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrSnapshotNotFound, dir)
		}
		return nil, err
	}
	var s Snapshot
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("repository: parse %s: %w", filepath.Join(dir, MetadataFileName), err)
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("repository: unsupported snapshot schema_version %d in %s", s.SchemaVersion, dir)
	}
	s.Dir = dir
	s.Frozen = isFrozen(filepath.Join(dir, TreeDirName))
	s.normalizeLists()
	return &s, nil
}

// WriteManifest stores an analysis artifact (for example the repository
// manifest) next to the frozen tree. Artifacts are immutable: an existing file
// is never overwritten in place, because downstream evidence points at it.
func (s *Snapshot) WriteManifest(data []byte) error {
	if s.Dir == "" {
		return errors.New("repository: snapshot has no directory")
	}
	// The manager owns directory creation. A late analysis must not recreate a
	// snapshot directory that a concurrent deletion already removed.
	f, err := os.OpenFile(s.ManifestPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("repository: refusing to overwrite %s: %w", s.ManifestPath(), err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WriteArtifact stores a derived analysis artifact next to the snapshot, for
// example the SCG document. Artifacts are content-addressed by their name
// (scg-<graph-version>.json), so a rebuild never overwrites evidence: it adds a
// new file.
func (s *Snapshot) WriteArtifact(name string, data []byte) error {
	if s.Dir == "" {
		return errors.New("repository: snapshot has no directory")
	}
	if !validArtifactName(name) {
		return fmt.Errorf("repository: invalid artifact name %q", name)
	}
	target := s.ArtifactPath(name)
	tmp, err := os.CreateTemp(s.Dir, ".artifact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if _, err := os.Stat(target); err == nil {
		// Identical content was already stored: keep the existing file.
		existing, rerr := os.ReadFile(target)
		if rerr == nil && string(existing) == string(data) {
			return nil
		}
		return fmt.Errorf("repository: artifact %s already exists with different content", name)
	}
	return os.Rename(tmpName, target)
}

// ArtifactPath is the on-disk path of a derived artifact.
func (s *Snapshot) ArtifactPath(name string) string {
	return filepath.Join(s.Dir, name)
}

// validArtifactName allows a flat, deterministic file name only.
func validArtifactName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return !strings.Contains(name, "..")
}

// ReadManifest returns the stored analysis artifact.
func (s *Snapshot) ReadManifest() ([]byte, error) {
	return os.ReadFile(s.ManifestPath())
}

// Freeze makes the source tree read-only, files first and directories
// afterwards, so a concurrent reader can never see a half-frozen tree.
func (s *Snapshot) Freeze() error {
	if err := freezeTree(s.TreeDir()); err != nil {
		return err
	}
	s.Frozen = true
	return nil
}

// Unfreeze restores write permission on the tree. It must be called (or Remove
// used) before deleting a snapshot: read-only directories cannot be removed on
// any supported platform.
func (s *Snapshot) Unfreeze() error {
	if err := unfreezeTree(s.Dir); err != nil {
		return err
	}
	s.Frozen = false
	return nil
}

func freezeTree(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
			return nil
		}
		if err := os.Chmod(p, 0o444); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o555); err != nil {
			return err
		}
	}
	return nil
}

func unfreezeTree(root string) error {
	var errs []error
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A partially deleted snapshot must still be removable.
			errs = append(errs, err)
			return nil
		}
		mode := os.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		}
		if cerr := os.Chmod(p, mode); cerr != nil {
			errs = append(errs, cerr)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func isFrozen(tree string) bool {
	info, err := os.Stat(tree)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o200 == 0
}

// scanLFSAttributes finds .gitattributes files that mark content as LFS-tracked.
func scanLFSAttributes(root string) LFSState {
	var state LFSState
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != ".gitattributes" && d.Name() != ".lfsconfig" {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(data), "filter=lfs") {
			rel, _ := filepath.Rel(root, p)
			state.Detected = true
			state.PointerOnly = true
			state.Attributes = append(state.Attributes, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(state.Attributes)
	return state
}
