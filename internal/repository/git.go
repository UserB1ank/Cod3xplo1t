package repository

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// gitCacheDirName is the sub-directory of the workspace root holding bare clone
// caches for remote sources.
const gitCacheDirName = "cache/git"

// dirtyPathSample is how many dirty paths are kept as evidence. The count is
// always exact; the list is a bounded sample.
const dirtyPathSample = 50

// gitEnv returns a hardened environment: no prompts, no credential helpers, no
// system or global git configuration, no hooks, no index refresh side effects
// and no automatic LFS download.
func (m *Manager) gitEnv(ctx context.Context) []string {
	transport, explicit := ctx.Value(gitEnvironmentKey{}).([]string)
	var env []string
	for _, value := range os.Environ() {
		if explicit && (strings.HasPrefix(value, "GIT_") || strings.HasPrefix(value, "SSH_") || strings.HasPrefix(value, "GCM_")) {
			continue
		}
		env = append(env, value)
	}
	env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GCM_INTERACTIVE=never",
		"LC_ALL=C",
	)
	if m.GitCAFile != "" {
		env = append(env, "GIT_SSL_CAINFO="+m.GitCAFile)
	}
	if explicit {
		env = append(env, transport...)
	}
	return env
}

// gitArgs prepends the safety flags shared by every git invocation.
func gitArgs(args ...string) []string {
	base := []string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "credential.helper=",
		"-c", "advice.detachedHead=false",
		"-c", "protocol.version=2",
		"-c", "http.followRedirects=false",
		"-c", "http.sslVerify=true",
		"-c", "core.fsmonitor=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
	}
	return append(base, args...)
}

// git runs git in dir and returns trimmed stdout. stderr is folded into the
// error so failures are diagnosable without leaking prompts.
func (m *Manager) git(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := m.gitRaw(ctx, dir, args...)
	return strings.TrimRight(out, "\n"), err
}

func (m *Manager) gitRaw(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, m.gitBin(), gitArgs(args...)...)
	cmd.Dir = dir
	cmd.Env = m.gitEnv(ctx)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.String(), nil
}

func (m *Manager) gitBin() string {
	if m.GitBin != "" {
		return m.GitBin
	}
	return "git"
}

// isGitRepo reports whether path is a git repository (working tree or bare).
func (m *Manager) isGitRepo(ctx context.Context, path string) bool {
	if _, err := exec.LookPath(m.gitBin()); err != nil {
		return false
	}
	_, err := m.git(ctx, path, "rev-parse", "--git-dir")
	return err == nil
}

// validRef rejects revisions that could be mistaken for command line options.
func validRef(ref string) error {
	if ref == "" {
		return nil
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("repository: invalid revision %q", ref)
	}
	if strings.ContainsAny(ref, " \t\n") {
		return fmt.Errorf("repository: revision %q must not contain whitespace", ref)
	}
	return nil
}

// resolveCommit pins a revision to a full commit SHA using the repository's own
// object database. No worktree state is ever consulted.
func (m *Manager) resolveCommit(ctx context.Context, repoPath, ref string) (string, error) {
	if err := validRef(ref); err != nil {
		return "", err
	}
	if ref == "" {
		ref = "HEAD"
	}
	out, err := m.git(ctx, repoPath, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("repository: cannot resolve revision %q in %s: %w", ref, repoPath, err)
	}
	sha := strings.TrimSpace(out)
	if !isHexSHA(sha) {
		return "", fmt.Errorf("repository: revision %q resolved to %q, which is not a commit SHA", ref, sha)
	}
	return strings.ToLower(sha), nil
}

func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// submoduleStates reads the submodule gitlinks pinned by a commit. It uses the
// object database only (git ls-tree), so it behaves identically for bare caches
// and for the user's working copy, and it never depends on whether the
// submodule checkouts happen to exist on this machine.
//
// Submodule content is not part of the parent tree and is not expanded in the
// MVP: every gitlink is recorded and the omission is stated as a limitation.
func (m *Manager) submoduleStates(ctx context.Context, repoPath, commit string) ([]SubmoduleState, error) {
	out, err := m.git(ctx, repoPath, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	var states []SubmoduleState
	for _, rec := range strings.Split(out, "\x00") {
		if rec == "" {
			continue
		}
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok || path == "" {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 {
			continue
		}
		mode, kind, sha := fields[0], fields[1], fields[2]
		if mode != "160000" || !strings.EqualFold(kind, "commit") {
			continue
		}
		if !isHexSHA(sha) {
			continue
		}
		states = append(states, SubmoduleState{Path: path, Commit: strings.ToLower(sha), Status: "pinned"})
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Path < states[j].Path })
	return states, nil
}

// worktreeStatus reports whether the user's working copy has uncommitted
// changes. The snapshot still uses the committed tree; dirtiness is recorded so
// nobody mistakes the snapshot for "what the user is looking at".
func (m *Manager) worktreeStatus(ctx context.Context, repoPath string) (bool, []string, int, error) {
	out, err := m.git(ctx, repoPath, "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil {
		return false, nil, 0, err
	}
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 4 {
			continue
		}
		p := strings.TrimSpace(line[3:])
		// Renames are reported as "old -> new"; keep the new path.
		if _, after, ok := strings.Cut(p, " -> "); ok {
			p = after
		}
		paths = append(paths, strings.Trim(p, `"`))
	}
	sort.Strings(paths)
	total := len(paths)
	if len(paths) > dirtyPathSample {
		paths = paths[:dirtyPathSample]
	}
	return total > 0, paths, total, nil
}

// ensureCloneCache materialises (or refreshes) a bare clone for a remote URL.
// The cache is shared per repository identity, so repeated snapshots of the same
// repository do not re-download everything.
func (m *Manager) ensureCloneCache(ctx context.Context, url string) (string, error) {
	_, explicit := ctx.Value(gitEnvironmentKey{}).([]string)
	cacheIdentity := NormalizeRepoName(url)
	if explicit {
		cacheIdentity = url
	}
	sum := sha256.Sum256([]byte(cacheIdentity))
	dir := filepath.Join(m.Root, filepath.FromSlash(gitCacheDirName), hex.EncodeToString(sum[:8]))
	unlock := m.lock("git-cache:" + dir)
	defer unlock()
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil {
		remote := "origin"
		if explicit {
			remote = url
		}
		args := []string{"fetch", "--prune", "--no-tags", "--", remote, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}
		if explicit {
			args = append(args, "+HEAD:refs/codexploit/remote-head")
		}
		if _, err := m.git(ctx, dir, args...); err != nil {
			return "", err
		}
		if explicit {
			if _, err := m.git(ctx, dir, "symbolic-ref", "HEAD", "refs/codexploit/remote-head"); err != nil {
				return "", err
			}
		}
		return dir, nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", err
	}
	tmp := dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return "", err
	}
	// A blob-less partial clone keeps the initial download small; not every
	// server supports it, so a plain bare clone is the fallback.
	if _, err := m.git(ctx, "", "clone", "--bare", "--tags", "--filter=blob:none", "--", url, tmp); err != nil {
		if removeErr := os.RemoveAll(tmp); removeErr != nil {
			return "", removeErr
		}
		if _, err2 := m.git(ctx, "", "clone", "--bare", "--tags", "--", url, tmp); err2 != nil {
			os.RemoveAll(tmp)
			return "", errors.Join(err, err2)
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		if _, statErr := os.Stat(filepath.Join(dir, "HEAD")); statErr == nil {
			os.RemoveAll(tmp)
			return dir, nil
		}
		os.RemoveAll(tmp)
		return "", err
	}
	return dir, nil
}

// extractCommitTree streams a commit tree into dst, applying limits, ignore
// rules and the binary policy, and returns the resulting plan. Submodule
// gitlinks are excluded from the tree: an empty directory in their place would
// misrepresent content that Codexploit never fetched.
func (m *Manager) extractCommitTree(ctx context.Context, repoPath, commit, dst string, l Limits, submodules []SubmoduleState) (*dirPlan, error) {
	commit = strings.ToLower(strings.TrimSpace(commit))
	if !isHexSHA(commit) {
		return nil, fmt.Errorf("repository: refusing to archive non-SHA revision %q", commit)
	}
	cmd := exec.CommandContext(ctx, m.gitBin(), gitArgs("archive", "--format=tar", commit)...)
	cmd.Dir = repoPath
	cmd.Env = m.gitEnv(ctx)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	plan, extractErr := extractTar(stdout, dst, l, submodules)
	waitErr := cmd.Wait()
	if extractErr != nil {
		return nil, extractErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("git archive %s: %w: %s", commit, waitErr, strings.TrimSpace(stderr.String()))
	}
	return plan, nil
}

// extractTar writes a tar stream to dst under the same policies as planDir.
// Every skipped entry is counted and explained.
func extractTar(r io.Reader, dst string, l Limits, submodules []SubmoduleState) (*dirPlan, error) {
	matcher := newIgnoreMatcher(l)
	plan := &dirPlan{}
	plan.ensureSkipCapacity(l)
	gitlinks := make(map[string]bool, len(submodules))
	for _, sm := range submodules {
		gitlinks[strings.TrimSuffix(sm.Path, "/")] = true
	}
	tr := tar.NewReader(r)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("repository: read archive: %w", err)
		}
		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "./")
		name = strings.TrimSuffix(name, "/")
		if name == "" || name == "." {
			continue
		}
		if !safeRelPath(name) {
			return nil, fmt.Errorf("repository: archive entry %q escapes the snapshot root", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		}
		if isGitlinkPath(name, gitlinks) {
			plan.Stats.SkippedSubmodule++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipSubmodule, Detail: "submodule gitlink recorded in submodule_state; content not expanded"})
			continue
		}
		depth := len(strings.Split(name, "/"))
		if depth > l.MaxDepth {
			plan.Stats.SkippedDepth++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipDepth, Detail: fmt.Sprintf("depth %d > max_depth %d", depth, l.MaxDepth)})
			continue
		}
		isDir := hdr.Typeflag == tar.TypeDir
		if ignored, rule := matcher.Match(name, isDir); ignored {
			plan.Stats.SkippedIgnored++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipIgnored, Detail: rule})
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, err
			}
			plan.Stats.Dirs++
			continue
		case tar.TypeSymlink:
			if l.Symlinks == SymlinkSkip {
				plan.Stats.SkippedSymlink++
				plan.addSkip(SkippedEntry{Path: name, Reason: SkipSymlink, Detail: "symlink skipped by policy"})
				continue
			}
			plan.Stats.SkippedSymlink++
			plan.Symlinks = append(plan.Symlinks, SymlinkEntry{Path: name, Target: hdr.Linkname})
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipSymlink, Detail: "-> " + hdr.Linkname})
			continue
		case tar.TypeReg:
		default:
			plan.Stats.SkippedOther++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipOther, Detail: fmt.Sprintf("tar type %q", hdr.Typeflag)})
			continue
		}
		if hdr.Size > l.MaxFileBytes {
			plan.Stats.SkippedLarge++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipLarge, Detail: fmt.Sprintf("%d bytes > max_file_bytes %d", hdr.Size, l.MaxFileBytes)})
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, l.MaxFileBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > l.MaxFileBytes {
			plan.Stats.SkippedLarge++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipLarge, Detail: fmt.Sprintf("content exceeded max_file_bytes %d", l.MaxFileBytes)})
			continue
		}
		prefix := data
		if len(prefix) > binarySniffSize {
			prefix = prefix[:binarySniffSize]
		}
		if IsBinary(prefix) && !l.AllowBinary {
			plan.Stats.SkippedBinary++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipBinary, Detail: "NUL byte in first 8000 bytes"})
			continue
		}
		if len(plan.Entries) >= l.MaxFiles || total+int64(len(data)) > l.MaxRepoBytes {
			plan.Stats.SkippedLimit++
			plan.addSkip(SkippedEntry{Path: name, Reason: SkipLimit, Detail: "file or byte budget reached"})
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, err
		}
		mode := os.FileMode(0o644)
		if hdr.Mode&0o111 != 0 {
			mode = 0o755
		}
		if err := os.WriteFile(target, data, mode); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		plan.Entries = append(plan.Entries, planEntry{Rel: name, Size: int64(len(data)), Mode: mode.Perm(), Digest: hex.EncodeToString(sum[:])})
		plan.Stats.Files++
		plan.Stats.Bytes += int64(len(data))
		total += int64(len(data))
	}
	sort.Slice(plan.Entries, func(i, j int) bool { return plan.Entries[i].Rel < plan.Entries[j].Rel })
	plan.Digest = digestEntries(plan.Entries)
	return plan, nil
}

// isGitlinkPath reports whether an archive entry belongs to a submodule that is
// pinned but not expanded.
func isGitlinkPath(name string, gitlinks map[string]bool) bool {
	if len(gitlinks) == 0 {
		return false
	}
	if gitlinks[name] {
		return true
	}
	for prefix := range gitlinks {
		if strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

// safeRelPath rejects archive entries that would escape the destination root.
func safeRelPath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") {
		return false
	}
	if strings.Contains(name, ":") && len(name) > 1 && name[1] == ':' {
		return false // Windows drive letter
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return false
		}
	}
	return fs.ValidPath(name)
}
