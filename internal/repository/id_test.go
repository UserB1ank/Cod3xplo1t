package repository

import "testing"

func TestSnapshotIDIsDeterministic(t *testing.T) {
	t.Parallel()
	id := Identity{Kind: "git", Name: "https://example.invalid/org/repo"}
	subs := []SubmoduleState{
		{Path: "deps/a", Commit: "1111111111111111111111111111111111111111", Status: "pinned"},
		{Path: "deps/b", Commit: "2222222222222222222222222222222222222222", Status: "pinned"},
	}
	first := SnapshotID(id, "abc123", subs)
	second := SnapshotID(id, "abc123", subs)
	if first != second {
		t.Fatalf("same identity triple produced different ids: %s != %s", first, second)
	}
	if len(first) != len(snapshotIDPrefix)+snapshotIDBytes*2 {
		t.Fatalf("unexpected snapshot id length: %q", first)
	}
	changed := []struct {
		name string
		id   Identity
		sha  string
		subs []SubmoduleState
	}{
		{"identity", Identity{Kind: "git", Name: "https://example.invalid/org/other"}, "abc123", subs},
		{"kind", Identity{Kind: "dir", Name: "https://example.invalid/org/repo"}, "abc123", subs},
		{"commit", id, "abc124", subs},
		{"submodule commit", id, "abc123", []SubmoduleState{{Path: "deps/a", Commit: "9999999999999999999999999999999999999999", Status: "pinned"}, subs[1]}},
		{"submodule path", id, "abc123", []SubmoduleState{{Path: "deps/z", Commit: subs[0].Commit, Status: "pinned"}, subs[1]}},
		{"submodule status", id, "abc123", []SubmoduleState{{Path: subs[0].Path, Commit: subs[0].Commit, Status: "uninitialized"}, subs[1]}},
		{"submodule dropped", id, "abc123", subs[:1]},
		{"submodule reordered", id, "abc123", []SubmoduleState{subs[1], subs[0]}},
	}
	seen := map[string]string{first: "baseline"}
	for _, tc := range changed {
		got := SnapshotID(tc.id, tc.sha, tc.subs)
		if prev, dup := seen[got]; dup {
			t.Errorf("%s: id collides with %s", tc.name, prev)
		}
		seen[got] = tc.name
	}
}

// TestSnapshotIDFieldBoundaries guards the length-prefixed encoding: moving
// content across field boundaries must not produce the same id.
func TestSnapshotIDFieldBoundaries(t *testing.T) {
	t.Parallel()
	a := SnapshotID(Identity{Kind: "git", Name: "ab"}, "c", nil)
	b := SnapshotID(Identity{Kind: "git", Name: "a"}, "bc", nil)
	if a == b {
		t.Fatalf("field boundary collision: %s", a)
	}
}

func TestAnalysisIDDependsOnRuleSetAndConfig(t *testing.T) {
	t.Parallel()
	base := AnalysisID("snap-1", "codexploit/analysis", "0.1.0", "rules-a", "config-a")
	if base != AnalysisID("snap-1", "codexploit/analysis", "0.1.0", "rules-a", "config-a") {
		t.Fatal("analysis id is not deterministic")
	}
	for _, other := range []string{
		AnalysisID("snap-2", "codexploit/analysis", "0.1.0", "rules-a", "config-a"),
		AnalysisID("snap-1", "codexploit/analysis", "0.2.0", "rules-a", "config-a"),
		AnalysisID("snap-1", "codexploit/analysis", "0.1.0", "rules-b", "config-a"),
		AnalysisID("snap-1", "codexploit/analysis", "0.1.0", "rules-a", "config-b"),
	} {
		if other == base {
			t.Fatalf("analysis id ignored a version input: %s", other)
		}
	}
}

func TestNormalizeRepoName(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://example.invalid/org/repo.git/": "https://example.invalid/org/repo",
		"https://example.invalid/org/repo":      "https://example.invalid/org/repo",
		"git@GitHub.invalid:Org/Repo.git":       "ssh://git@github.invalid/Org/Repo",
		"  /srv/repo/  ":                        "/srv/repo",
	}
	for in, want := range cases {
		if got := NormalizeRepoName(in); got != want {
			t.Errorf("NormalizeRepoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLocalPath(t *testing.T) {
	t.Parallel()
	local := []string{"/srv/repo", "./repo", "repo", "C:\\src\\repo", "sub/dir"}
	for _, in := range local {
		if !IsLocalPath(in) {
			t.Errorf("IsLocalPath(%q) = false, want true", in)
		}
	}
	remote := []string{
		"https://example.invalid/org/repo.git",
		"ssh://git@example.invalid/org/repo.git",
		"git@example.invalid:org/repo.git",
		"git://example.invalid/org/repo",
	}
	for _, in := range remote {
		if IsLocalPath(in) {
			t.Errorf("IsLocalPath(%q) = true, want false", in)
		}
	}
}
