package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Source is a user-supplied repository location plus the revision to pin.
type Source struct {
	// Raw is exactly what the user passed: a git URL, a local git repository or
	// a plain directory.
	Raw string
	// Ref is the revision to pin. Empty means HEAD for git sources. A full
	// commit SHA is accepted as well.
	Ref string
	// NameOverride replaces the derived repository identity. Use it when two
	// mirrors of the same repository must share snapshot IDs.
	NameOverride string
}

// Kind classifies how a source should be read.
type Kind string

const (
	// KindDir reads a plain local directory (no VCS metadata).
	KindDir Kind = "dir"
	// KindLocalGit reads a local git repository through its object database.
	KindLocalGit Kind = "local_git"
	// KindRemoteGit reads a git repository over the network.
	KindRemoteGit Kind = "remote_git"
)

// Errors returned by source resolution and snapshot creation.
var (
	// ErrNetworkDisabled is returned when a remote source is used but the
	// manager was not allowed to touch the network.
	ErrNetworkDisabled = errors.New("repository: network access is disabled for this manager")
	// ErrSourceChanged is returned when a directory source mutates between the
	// moment it was hashed and the moment it was copied.
	ErrSourceChanged = errors.New("repository: source changed while it was being snapshotted")
	// ErrSourceNotFound is returned for a source path that does not exist.
	ErrSourceNotFound = errors.New("repository: source path does not exist")
	// ErrSnapshotNotFound is returned when a snapshot id is not on disk.
	ErrSnapshotNotFound = errors.New("repository: snapshot not found")
	// ErrLimitExceeded is returned when a hard limit (files, bytes) is hit.
	ErrLimitExceeded = errors.New("repository: limit exceeded")
)

// Resolved is the outcome of resolving a Source before any hashing happens.
type Resolved struct {
	Source Source
	Kind   Kind
	// Path is the local path used for reading: the directory itself for KindDir
	// and KindLocalGit, or the clone cache location for KindRemoteGit.
	Path string
	// Identity is the canonical repository identity used in the snapshot hash.
	Identity Identity
}

// IsLocalPath reports whether raw looks like a local filesystem path rather
// than a URL. Windows drive letters ("C:\src") are handled explicitly.
func IsLocalPath(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.Contains(raw, "://") {
		return false
	}
	if strings.HasPrefix(raw, "git@") || strings.HasPrefix(raw, "ssh:") {
		return false
	}
	// scp-like syntax: host:path where the host part has no path separator.
	if i := strings.Index(raw, ":"); i > 0 {
		if !strings.ContainsAny(raw[:i], `/\`) && !filepath.IsAbs(raw) {
			if i < len(raw)-1 && (raw[i+1] == '/' || isLikelyHostSegment(raw[:i])) {
				return false
			}
		}
	}
	return true
}

func isLikelyHostSegment(s string) bool {
	if s == "" {
		return false
	}
	// A single-letter segment before ':' is a Windows drive, not a host.
	if len(s) == 1 {
		return false
	}
	return strings.Contains(s, ".") || strings.Contains(s, "@")
}

// Resolve classifies the source and prepares a local read path. For remote
// git sources this requires network access and a clone; callers that must stay
// offline should reject KindRemoteGit up front.
func (m *Manager) Resolve(ctx context.Context, src Source) (*Resolved, error) {
	src.Raw = strings.TrimSpace(src.Raw)
	if src.Raw == "" {
		return nil, errors.New("repository: empty source")
	}
	if IsLocalPath(src.Raw) {
		abs, err := filepath.Abs(src.Raw)
		if err != nil {
			return nil, fmt.Errorf("repository: resolve %q: %w", src.Raw, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%w: %s", ErrSourceNotFound, abs)
			}
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("repository: source %s is not a directory", abs)
		}
		name := src.NameOverride
		if name == "" {
			name = NormalizeRepoName(filepath.ToSlash(abs))
		}
		if m.isGitRepo(ctx, abs) {
			return &Resolved{Source: src, Kind: KindLocalGit, Path: abs, Identity: Identity{Kind: "git", Name: name}}, nil
		}
		return &Resolved{Source: src, Kind: KindDir, Path: abs, Identity: Identity{Kind: "dir", Name: name}}, nil
	}

	name := src.NameOverride
	if name == "" {
		name = NormalizeRepoName(src.Raw)
	}
	if !m.AllowNetwork {
		return nil, fmt.Errorf("%w: %s", ErrNetworkDisabled, src.Raw)
	}
	clonePath, err := m.ensureCloneCache(ctx, src.Raw)
	if err != nil {
		return nil, err
	}
	return &Resolved{Source: src, Kind: KindRemoteGit, Path: clonePath, Identity: Identity{Kind: "git", Name: name}}, nil
}

// digestPrefix is the domain separator for directory content hashes.
const digestPrefix = "codexploit/dirtree/v1"

// planEntry is one accepted file of a directory source, frozen at hash time.
type planEntry struct {
	Rel    string // slash-separated path below the root
	Size   int64
	Mode   fs.FileMode
	Digest string // sha256 of the content
}

// dirPlan is the deterministic description of a directory source.
type dirPlan struct {
	Entries  []planEntry
	Symlinks []SymlinkEntry
	Digest   string
	Stats    Stats
	Skips    []SkippedEntry
}

// planDir walks a plain directory and produces the accepted-file list, its
// content digest and the skip accounting. It never follows symlinks.
func planDir(root string, l Limits) (*dirPlan, error) {
	matcher := newIgnoreMatcher(l)
	plan := &dirPlan{}
	plan.ensureSkipCapacity(l)
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		segments := len(strings.Split(rel, "/"))
		if segments > l.MaxDepth {
			plan.Stats.SkippedDepth++
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipDepth, Detail: fmt.Sprintf("depth %d > max_depth %d", segments, l.MaxDepth)})
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ignored, rule := matcher.Match(rel, d.IsDir()); ignored {
			plan.Stats.SkippedIgnored++
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipIgnored, Detail: rule})
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			if l.Symlinks == SymlinkSkip {
				plan.Stats.SkippedSymlink++
				plan.addSkip(SkippedEntry{Path: rel, Reason: SkipSymlink, Detail: "symlink skipped by policy"})
				return nil
			}
			target, lerr := os.Readlink(p)
			if lerr != nil {
				plan.Stats.SkippedUnreadable++
				plan.addSkip(SkippedEntry{Path: rel, Reason: SkipUnreadable, Detail: lerr.Error()})
				return nil
			}
			plan.Stats.SkippedSymlink++
			plan.Symlinks = append(plan.Symlinks, SymlinkEntry{Path: rel, Target: target})
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipSymlink, Detail: "-> " + target})
			return nil
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			plan.Stats.SkippedOther++
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipOther, Detail: d.Type().String()})
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			plan.Stats.SkippedUnreadable++
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipUnreadable, Detail: ierr.Error()})
			return nil
		}
		if info.Size() > l.MaxFileBytes {
			plan.Stats.SkippedLarge++
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipLarge, Detail: fmt.Sprintf("%d bytes > max_file_bytes %d", info.Size(), l.MaxFileBytes)})
			return nil
		}

		digest, binary, derr := hashFile(p, rel, l, plan)
		if derr != nil {
			return derr
		}
		if binary && !l.AllowBinary {
			plan.Stats.SkippedBinary++
			plan.addSkip(SkippedEntry{Path: rel, Reason: SkipBinary, Detail: "NUL byte in first 8000 bytes"})
			return nil
		}
		if len(plan.Entries) >= l.MaxFiles {
			return fmt.Errorf("%w: more than max_files=%d accepted files under %s", ErrLimitExceeded, l.MaxFiles, root)
		}
		total += info.Size()
		if total > l.MaxRepoBytes {
			return fmt.Errorf("%w: more than max_repo_bytes=%d under %s", ErrLimitExceeded, l.MaxRepoBytes, root)
		}
		plan.Entries = append(plan.Entries, planEntry{Rel: rel, Size: info.Size(), Mode: info.Mode().Perm(), Digest: digest})
		plan.Stats.Files++
		plan.Stats.Bytes += info.Size()
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(plan.Entries, func(i, j int) bool { return plan.Entries[i].Rel < plan.Entries[j].Rel })
	plan.Digest = digestEntries(plan.Entries)
	return plan, nil
}

// hashFile hashes one file and applies the binary policy. The file handle is
// opened once: the sniff prefix is folded into the same digest stream.
func hashFile(p, rel string, l Limits, plan *dirPlan) (string, bool, error) {
	f, err := os.Open(p)
	if err != nil {
		plan.Stats.SkippedUnreadable++
		plan.addSkip(SkippedEntry{Path: rel, Reason: SkipUnreadable, Detail: err.Error()})
		return "", false, nil
	}
	defer f.Close()
	prefix, err := readPrefix(f)
	if err != nil {
		plan.Stats.SkippedUnreadable++
		plan.addSkip(SkippedEntry{Path: rel, Reason: SkipUnreadable, Detail: err.Error()})
		return "", false, nil
	}
	h := sha256.New()
	h.Write(prefix)
	if _, err := io.Copy(h, f); err != nil {
		plan.Stats.SkippedUnreadable++
		plan.addSkip(SkippedEntry{Path: rel, Reason: SkipUnreadable, Detail: err.Error()})
		return "", false, nil
	}
	return hex.EncodeToString(h.Sum(nil)), IsBinary(prefix), nil
}

// digestEntries hashes the accepted file list so that a plain directory can be
// pinned to a content revision. The encoding is length-prefixed and sorted, so
// the digest is stable across filesystems and walk orders.
func digestEntries(entries []planEntry) string {
	h := sha256.New()
	writeField(h, digestPrefix)
	writeInt(h, len(entries))
	for _, e := range entries {
		writeField(h, e.Rel)
		writeField(h, fmt.Sprintf("%d", e.Size))
		writeField(h, fmt.Sprintf("%#o", e.Mode))
		writeField(h, e.Digest)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// copyPlan materialises a directory plan into dst, verifying that every file is
// still byte-identical to the hashed version. A concurrent edit aborts the
// snapshot instead of producing a tree that does not match its ID.
func copyPlan(root, dst string, plan *dirPlan) error {
	for _, e := range plan.Entries {
		src := filepath.Join(root, filepath.FromSlash(e.Rel))
		target := filepath.Join(dst, filepath.FromSlash(e.Rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := copyVerified(src, target, e); err != nil {
			return err
		}
	}
	return nil
}

func copyVerified(src, target string, e planEntry) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(out, h), in)
	closeErr := out.Close()
	if cerr != nil {
		return cerr
	}
	if closeErr != nil {
		return closeErr
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != e.Digest {
		return fmt.Errorf("%w: %s", ErrSourceChanged, e.Rel)
	}
	if e.Mode&0o111 != 0 {
		if err := os.Chmod(target, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// addSkip records a skipped entry, keeping the list bounded while the counters
// stay exact.
func (p *dirPlan) addSkip(s SkippedEntry) {
	if len(p.Skips) < cap(p.Skips) {
		p.Skips = append(p.Skips, s)
	}
}

// ensureSkipCapacity sizes the bounded skip list from the configured limit.
func (p *dirPlan) ensureSkipCapacity(l Limits) {
	p.Skips = make([]SkippedEntry, 0, l.MaxSkippedEntries)
}

// contentRevision is the pseudo-commit used for plain directory sources.
func contentRevision(digest string) string {
	return "content:" + digest
}

// timeNow is indirect so tests can pin timestamps.
var timeNow = time.Now

func ageOf(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
