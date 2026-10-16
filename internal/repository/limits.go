package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Policies for repository features that cannot be handled silently. Every
// policy degrades to an explicit record (or a hard error) so that a snapshot
// never claims coverage it does not have.

// SymlinkPolicy controls how symlinks found in a directory source are treated.
type SymlinkPolicy string

const (
	// SymlinkRecord records the link and its target but does not materialise it
	// in the snapshot and never follows it. This is the default: following
	// links can escape the repository root.
	SymlinkRecord SymlinkPolicy = "record"
	// SymlinkSkip drops links without recording them.
	SymlinkSkip SymlinkPolicy = "skip"
)

// SubmodulePolicy controls how git submodules are treated.
type SubmodulePolicy string

const (
	// SubmoduleRecord records each pinned submodule commit and states that
	// submodule contents are not part of the snapshot tree (the MVP does not
	// expand submodules).
	SubmoduleRecord SubmodulePolicy = "record"
	// SubmoduleRequire fails the snapshot when the repository has submodules,
	// instead of returning a parent-only tree.
	SubmoduleRequire SubmodulePolicy = "require"
)

// LFSPolicy controls how Git LFS pointers are treated.
type LFSPolicy string

const (
	// LFSRecord keeps LFS pointer files as-is and records the limitation. LFS
	// content is never fetched automatically.
	LFSRecord LFSPolicy = "record"
	// LFSRequire fails the snapshot when LFS-tracked files are detected.
	LFSRequire LFSPolicy = "require"
)

// Limits bound the work and the size of a snapshot. Zero values are replaced by
// the defaults returned from DefaultLimits.
type Limits struct {
	// MaxRepoBytes caps the total size of accepted file content.
	MaxRepoBytes int64 `json:"max_repo_bytes"`
	// MaxFiles caps the number of accepted files.
	MaxFiles int `json:"max_files"`
	// MaxFileBytes caps the size of a single file; larger files are skipped.
	MaxFileBytes int64 `json:"max_file_bytes"`
	// MaxDepth caps the number of path segments below the repository root.
	MaxDepth int `json:"max_depth"`
	// MaxSkippedEntries caps how many skipped entries are kept for evidence;
	// counters always stay exact.
	MaxSkippedEntries int `json:"max_skipped_entries"`
	// AllowBinary keeps binary files instead of skipping them. Binary file
	// content is required for byte-level analysis but is usually noise.
	AllowBinary bool `json:"allow_binary"`
	// ExtraIgnoreDirs adds ignore entries on top of DefaultIgnoreDirs. Entries
	// with a trailing slash match directories only; other entries match any
	// path segment.
	ExtraIgnoreDirs []string `json:"extra_ignore_dirs,omitempty"`
	// IncludeIgnoredDirs explicitly overrides DefaultIgnoreDirs entries, e.g.
	// "vendor" or "dist". This is the documented escape hatch for repositories
	// where a normally generated directory holds audited source.
	IncludeIgnoredDirs []string `json:"include_ignored_dirs,omitempty"`
	// Symlinks, Submodules and LFS select the handling policy for each feature.
	Symlinks   SymlinkPolicy   `json:"symlinks"`
	Submodules SubmodulePolicy `json:"submodules"`
	LFS        LFSPolicy       `json:"lfs"`
}

// DefaultLimits returns the MVP limits from the implementation guide: generated
// directories, vendors and caches are excluded, with a conservative size budget.
func DefaultLimits() Limits {
	return Limits{
		MaxRepoBytes:      512 << 20, // 512 MiB of accepted content
		MaxFiles:          50000,
		MaxFileBytes:      4 << 20, // 4 MiB per file
		MaxDepth:          32,
		MaxSkippedEntries: 200,
		AllowBinary:       false,
		Symlinks:          SymlinkRecord,
		Submodules:        SubmoduleRecord,
		LFS:               LFSRecord,
	}
}

// DefaultIgnoreDirs lists directory names that are generated, vendored or
// cached. The list is deliberately conservative: everything here is either
// reproducible from other inputs or not source code.
var DefaultIgnoreDirs = []string{
	".git", ".hg", ".svn", ".bzr",
	"node_modules", "bower_components", "vendor", "third_party", "thirdparty",
	"dist", "build", "out", "target", "obj", "bin",
	".venv", "venv", "virtualenv", "__pycache__", ".mypy_cache", ".pytest_cache",
	".tox", ".eggs", ".gradle", ".m2", ".terraform", ".cache", ".parcel-cache",
	".next", ".nuxt", ".svelte-kit", ".angular", ".dart_tool", ".stack-work",
	"coverage", "htmlcov", ".nyc_output", "logs", "tmp",
	".idea", ".vscode", ".vs", ".DS_Store",
}

// DefaultIgnoreGlobs lists file patterns that are generated or minified.
var DefaultIgnoreGlobs = []string{
	"*.min.js", "*.min.css", "*.map", "*.bundle.js",
}

// Validate rejects incoherent limits before any filesystem work happens.
func (l Limits) Validate() error {
	var errs []error
	if l.MaxRepoBytes < 0 {
		errs = append(errs, fmt.Errorf("MaxRepoBytes must not be negative, got %d", l.MaxRepoBytes))
	}
	if l.MaxFiles < 0 {
		errs = append(errs, fmt.Errorf("MaxFiles must not be negative, got %d", l.MaxFiles))
	}
	if l.MaxFileBytes < 0 {
		errs = append(errs, fmt.Errorf("MaxFileBytes must not be negative, got %d", l.MaxFileBytes))
	}
	if l.MaxDepth < 0 {
		errs = append(errs, fmt.Errorf("MaxDepth must not be negative, got %d", l.MaxDepth))
	}
	switch l.Symlinks {
	case "", SymlinkRecord, SymlinkSkip:
	default:
		errs = append(errs, fmt.Errorf("unknown symlink policy %q", l.Symlinks))
	}
	switch l.Submodules {
	case "", SubmoduleRecord, SubmoduleRequire:
	default:
		errs = append(errs, fmt.Errorf("unknown submodule policy %q", l.Submodules))
	}
	switch l.LFS {
	case "", LFSRecord, LFSRequire:
	default:
		errs = append(errs, fmt.Errorf("unknown LFS policy %q", l.LFS))
	}
	return errors.Join(errs...)
}

// WithDefaults fills every zero field from DefaultLimits and normalises
// policies, so the rest of the package can assume a fully populated value.
func (l Limits) WithDefaults() Limits {
	d := DefaultLimits()
	if l.MaxRepoBytes == 0 {
		l.MaxRepoBytes = d.MaxRepoBytes
	}
	if l.MaxFiles == 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxSkippedEntries == 0 {
		l.MaxSkippedEntries = d.MaxSkippedEntries
	}
	if l.Symlinks == "" {
		l.Symlinks = d.Symlinks
	}
	if l.Submodules == "" {
		l.Submodules = d.Submodules
	}
	if l.LFS == "" {
		l.LFS = d.LFS
	}
	return l
}

// ignoreMatcher decides whether a repository-relative path is excluded from the
// snapshot. It reports the ignore rule that matched, so every dropped file can
// be explained in the snapshot metadata.
type ignoreMatcher struct {
	dirs    map[string]string // segment -> rule as written
	globs   map[string]string // glob -> rule as written
	include map[string]bool   // explicitly re-included segments
}

func newIgnoreMatcher(l Limits) *ignoreMatcher {
	m := &ignoreMatcher{
		dirs:    make(map[string]string, len(DefaultIgnoreDirs)),
		globs:   make(map[string]string, len(DefaultIgnoreGlobs)),
		include: make(map[string]bool, len(l.IncludeIgnoredDirs)),
	}
	for _, d := range DefaultIgnoreDirs {
		m.dirs[d] = "default:" + d
	}
	for _, g := range DefaultIgnoreGlobs {
		m.globs[g] = "default:" + g
	}
	for _, d := range l.ExtraIgnoreDirs {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasSuffix(d, "/") {
			m.dirs[strings.TrimSuffix(d, "/")] = "extra:" + d
			continue
		}
		if strings.ContainsAny(d, "*?[") {
			m.globs[d] = "extra:" + d
			continue
		}
		m.dirs[d] = "extra:" + d
	}
	for _, d := range l.IncludeIgnoredDirs {
		d = strings.Trim(strings.TrimSpace(d), "/")
		if d == "" {
			continue
		}
		m.include[d] = true
	}
	return m
}

// Match reports whether rel (a slash-separated repository-relative path) is
// ignored, together with the rule responsible.
func (m *ignoreMatcher) Match(rel string, isDir bool) (bool, string) {
	if rel == "" || rel == "." {
		return false, ""
	}
	segments := strings.Split(rel, "/")
	for _, seg := range segments {
		if m.include[seg] {
			// An explicit include wins for this segment and everything below
			// it, but not for other ignored segments elsewhere in the path.
			continue
		}
		if rule, ok := m.dirs[seg]; ok {
			return true, rule
		}
	}
	if !isDir {
		base := path.Base(rel)
		for glob, rule := range m.globs {
			if ok, err := path.Match(glob, base); err == nil && ok {
				return true, rule
			}
		}
	}
	return false, ""
}

// IsBinary applies a cheap, deterministic heuristic: a NUL byte inside the
// sniffed prefix means binary. Failures to read are reported as text so the
// caller decides what to do with unreadable content.
func IsBinary(prefix []byte) bool {
	return bytes.IndexByte(prefix, 0) >= 0
}

// binarySniffSize is the prefix length inspected by IsBinary.
const binarySniffSize = 8000

// readPrefix returns up to binarySniffSize bytes from r.
func readPrefix(r io.Reader) ([]byte, error) {
	buf := make([]byte, binarySniffSize)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return buf[:n], nil
}
