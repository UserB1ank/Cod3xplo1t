// Package repository implements the P1 snapshot chain of Codexploit: import a
// repository, pin it to an immutable revision, freeze a read-only snapshot and
// record exactly which facts about that snapshot are known and which are not.
//
// Design constraints taken from docs/codexploit_implementation_guide.md §5:
//
//   - the user's original working copy is never modified or used as the
//     analysis workspace; a separate snapshot directory is materialised;
//   - hooks, install scripts and build commands from the repository are never
//     executed;
//   - repository size, file count, file size, depth and file type limits are
//     enforced and every dropped file is accounted for;
//   - submodules, symlinks, Git LFS and worktree dirtiness are recorded
//     explicitly instead of being silently ignored;
//   - the same (repo_identity, commit, submodule_state) triple always yields
//     the same snapshot_id.
package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Snapshot ID layout: platform prefix + hex digest of the identity triple.
const (
	snapshotIDPrefix = "snap-"
	snapshotIDBytes  = 16 // 32 hex characters, enough for a content key
)

// Identity is the canonical, host-stable description of what is being snapshotted.
// It is the first input of the snapshot hash, so any change of meaning here
// changes every snapshot_id derived from it.
type Identity struct {
	// Kind is "git" for VCS sources and "dir" for plain directories.
	Kind string `json:"kind"`
	// Name is the repository identity: the normalised remote URL for git
	// sources, or the cleaned local path for directory sources.
	Name string `json:"name"`
}

// SnapshotID derives the deterministic snapshot identifier from the identity
// triple defined in docs/codexploit_implementation_guide.md §4.1:
//
//	snapshot_id = hash(repo_identity, commit_sha, submodule_state)
//
// The digest input is length-prefixed so that field boundaries cannot be
// forged by moving content between fields (e.g. commit "ab" + submodule "c"
// must not collide with commit "a" + submodule "bc").
func SnapshotID(identity Identity, commitSHA string, submoduleState []SubmoduleState) string {
	h := sha256.New()
	writeField(h, "codexploit/snapshot/v1")
	writeField(h, identity.Kind)
	writeField(h, identity.Name)
	writeField(h, commitSHA)
	writeInt(h, len(submoduleState))
	for _, sm := range submoduleState {
		writeField(h, sm.Path)
		writeField(h, sm.Commit)
		writeField(h, sm.Status)
	}
	sum := h.Sum(nil)
	return snapshotIDPrefix + hex.EncodeToString(sum[:snapshotIDBytes])
}

// AnalysisID derives the analysis identifier from the snapshot and the exact
// engine, rule set and configuration that produced a manifest, per §4.1:
//
//	analysis_id = hash(snapshot_id, engine, engine_version, ruleset_hash, config_hash)
//
// It is the cache key component that keeps results from different analyzers or
// rule sets from being compared to each other.
func AnalysisID(snapshotID, engine, engineVersion, rulesetHash, configHash string) string {
	h := sha256.New()
	writeField(h, "codexploit/analysis/v1")
	writeField(h, snapshotID)
	writeField(h, engine)
	writeField(h, engineVersion)
	writeField(h, rulesetHash)
	writeField(h, configHash)
	sum := h.Sum(nil)
	return "analysis-" + hex.EncodeToString(sum[:snapshotIDBytes])
}

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	fmt.Fprintf(h, "%d:", len(s))
	h.Write([]byte(s))
}

func writeInt(h interface{ Write([]byte) (int, error) }, v int) {
	h.Write([]byte(fmt.Sprintf("%d:", v)))
}

// NormalizeRepoName canonicalises a repository identity so that cosmetic
// differences (trailing slash, ".git" suffix, case of the scp-like git URL)
// do not produce different snapshot IDs for the same repository.
func NormalizeRepoName(name string) string {
	n := strings.TrimSpace(name)
	n = strings.TrimSuffix(n, "/")
	n = strings.TrimSuffix(n, ".git")
	if strings.HasPrefix(n, "git@") {
		// git@host:org/repo -> ssh://git@host/org/repo
		if host, path, ok := strings.Cut(strings.TrimPrefix(n, "git@"), ":"); ok {
			n = "ssh://git@" + strings.ToLower(host) + "/" + path
		}
	}
	return n
}
