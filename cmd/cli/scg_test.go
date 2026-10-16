package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// scgFixture writes a Go repository with an internal call chain so the graph has
// something to resolve.
func scgFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.invalid/cli\n\ngo 1.24\n",
		"main.go": `package main

import "example.invalid/cli/internal/svc"

func main() { svc.Start() }
`,
		"internal/svc/svc.go": `package svc

func Start() { Serve() }

func Serve() { log("serving") }

func log(msg string) { _ = msg }
`,
	}
	for rel, content := range files {
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

// scgWorkspace returns a workspace path and registers cleanup that unfreezes and
// removes every snapshot before t.TempDir tries to delete the directory.
func scgWorkspace(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	workspace := filepath.Join(base, "work")
	db := filepath.Join(base, "codexploit.db")
	t.Cleanup(func() {
		mgr, err := repository.NewManager(workspace)
		if err != nil {
			return
		}
		ids, err := mgr.List()
		if err != nil {
			t.Errorf("list snapshots for cleanup: %v", err)
			return
		}
		for _, id := range ids {
			if err := mgr.Remove(id); err != nil {
				t.Errorf("remove snapshot %s: %v", id, err)
			}
		}
	})
	return workspace, db
}

// buildSCG runs `scg build --json` and returns the stored snapshot id.
func buildSCG(t *testing.T, source, workspace, db string) string {
	t.Helper()
	out, err := captureStdout(t, func() error {
		return runSCG(context.Background(), []string{
			"build", "--source", source, "--workspace", workspace, "--db", db, "--json",
		})
	})
	if err != nil {
		t.Fatalf("scg build: %v", err)
	}
	var result struct {
		Snapshot struct {
			SnapshotID string `json:"snapshot_id"`
		} `json:"snapshot"`
		Graph scg.Summary `json:"graph"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("build output is not JSON: %v\n%s", err, out)
	}
	if result.Snapshot.SnapshotID == "" || result.Graph.Symbols == 0 {
		t.Fatalf("build produced no graph: %s", out)
	}
	return result.Snapshot.SnapshotID
}

func TestSCGBuildAndQueries(t *testing.T) {
	// Not parallel: the CLI writes to stdout, which is process-wide.
	source := scgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildSCG(t, source, workspace, db)

	// The graph document and the manifest are both on disk, under names that can
	// never collide with a later build.
	snapDir := filepath.Join(workspace, "snapshots", snapID)
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	var sawGraph, sawManifest bool
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "scg-") && strings.HasSuffix(e.Name(), ".json"):
			sawGraph = true
		case e.Name() == repository.ManifestFileName:
			sawManifest = true
		}
	}
	if !sawGraph || !sawManifest {
		t.Fatalf("expected graph and manifest artifacts in %s, got %v", snapDir, entries)
	}

	cases := []struct {
		name     string
		args     []string
		mustHave []string
	}{
		{"summary", []string{"summary", "--snapshot", snapID}, []string{"graph", "structure", "calls"}},
		{"modules", []string{"modules", "--snapshot", snapID}, []string{"example.invalid/cli", "Go"}},
		{"files", []string{"files", "--snapshot", snapID}, []string{"main.go", "internal/svc/svc.go"}},
		{"symbols by name", []string{"symbols", "--snapshot", snapID, "--name", "Serve"}, []string{"Serve"}},
		{"symbols by qualified name", []string{"symbols", "--snapshot", snapID, "--qualified-name", "example.invalid/cli/internal/svc.Serve"}, []string{"Serve"}},
		{"callees", []string{"callees", "--snapshot", snapID, "--symbol", "example.invalid/cli.main", "--depth", "3"}, []string{"Start", "Serve"}},
		{"callers", []string{"callers", "--snapshot", snapID, "--symbol", "example.invalid/cli/internal/svc.log", "--depth", "3"}, []string{"Serve"}},
		{"paths", []string{"paths", "--snapshot", snapID, "--from", "example.invalid/cli.main", "--to", "example.invalid/cli/internal/svc.log", "--depth", "4"}, []string{"main -> Start -> Serve -> log"}},
		{"slice", []string{"slice", "--snapshot", snapID, "--symbol", "example.invalid/cli/internal/svc.Serve", "--include", "calls"}, []string{"func Serve()", "log("}},
		{"unresolved", []string{"unresolved", "--snapshot", snapID, "--limit", "5"}, []string{"unresolved call site"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error {
				return runSCG(context.Background(), append(tc.args, "--workspace", workspace, "--db", db))
			})
			if err != nil {
				t.Fatalf("scg %s: %v\n%s", tc.name, err, out)
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(out, want) {
					t.Errorf("output does not contain %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestSCGJSONOutput(t *testing.T) {
	source := scgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildSCG(t, source, workspace, db)

	out, err := captureStdout(t, func() error {
		return runSCG(context.Background(), []string{
			"callees", "--snapshot", snapID, "--symbol", "example.invalid/cli.main",
			"--depth", "2", "--workspace", workspace, "--db", db, "--json",
		})
	})
	if err != nil {
		t.Fatalf("callees --json: %v", err)
	}
	var neighbourhood struct {
		Nodes []struct {
			Symbol   scg.Symbol `json:"symbol"`
			Distance int        `json:"distance"`
		} `json:"nodes"`
		Meta struct {
			SnapshotID   string `json:"snapshot_id"`
			GraphVersion string `json:"graph_version"`
			Budget       struct {
				MaxDepth int `json:"max_depth"`
			} `json:"budget"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(out), &neighbourhood); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if neighbourhood.Meta.SnapshotID != snapID || neighbourhood.Meta.GraphVersion == "" {
		t.Errorf("JSON output lost provenance: %+v", neighbourhood.Meta)
	}
	if neighbourhood.Meta.Budget.MaxDepth != 2 {
		t.Errorf("budget was not reported: %+v", neighbourhood.Meta.Budget)
	}
	if len(neighbourhood.Nodes) == 0 {
		t.Fatalf("no callees returned: %s", out)
	}
}

func TestSCGErrors(t *testing.T) {
	source := scgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildSCG(t, source, workspace, db)

	cases := []struct {
		name string
		args []string
	}{
		{"no subcommand", nil},
		{"unknown subcommand", []string{"nope"}},
		{"missing source", []string{"build", "--workspace", workspace, "--db", db}},
		{"missing snapshot", []string{"summary", "--workspace", workspace, "--db", db}},
		{"unknown snapshot", []string{"summary", "--snapshot", "snap-00000000000000000000000000000000", "--workspace", workspace, "--db", db}},
		{"unknown symbol", []string{"callees", "--snapshot", snapID, "--symbol", "example.invalid/cli.nope", "--workspace", workspace, "--db", db}},
		{"ambiguous symbol", []string{"callees", "--snapshot", snapID, "--symbol", "example.invalid", "--workspace", workspace, "--db", db}},
		{"path without endpoints", []string{"paths", "--snapshot", snapID, "--workspace", workspace, "--db", db}},
		{"slice without selector", []string{"slice", "--snapshot", snapID, "--workspace", workspace, "--db", db}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := captureStdout(t, func() error { return runSCG(context.Background(), tc.args) }); err == nil {
				t.Fatalf("scg %v unexpectedly succeeded", tc.args)
			}
		})
	}
}
