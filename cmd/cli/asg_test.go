package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

// asgFixture writes a Go service with a route registration, an authentication
// middleware and a handler that touches a database and a file, so the CLI has a
// real attack surface to print.
func asgFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.invalid/cli\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
		"main.go": `package main

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func Report(c *gin.Context) {
	db, err := sql.Open("sqlite", "app.db")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	row := db.QueryRow("SELECT secret FROM tokens WHERE name = ?", c.Query("name"))
	var secret string
	if err := row.Scan(&secret); err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	body, err := os.ReadFile("config/app.yaml")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, secret+string(body))
}

func main() {
	r := gin.Default()
	r.Use(AuthRequired())
	r.GET("/users/:id", Report)
	r.Run(":8080")
}
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

// buildASG runs `asg build --json` and returns the stored snapshot id.
func buildASG(t *testing.T, source, workspace, db string) string {
	t.Helper()
	out, err := captureStdout(t, func() error {
		return runASG(context.Background(), []string{
			"build", "--source", source, "--workspace", workspace, "--db", db, "--json",
		})
	})
	if err != nil {
		t.Fatalf("asg build: %v\n%s", err, out)
	}
	var result struct {
		Snapshot struct {
			SnapshotID string `json:"snapshot_id"`
		} `json:"snapshot"`
		ASG asg.Summary `json:"asg"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("build output is not JSON: %v\n%s", err, out)
	}
	if result.Snapshot.SnapshotID == "" || result.ASG.Nodes == 0 {
		t.Fatalf("build produced no attack surface: %s", out)
	}
	return result.Snapshot.SnapshotID
}

func TestASGBuildAndQueries(t *testing.T) {
	// Not parallel: the CLI writes to stdout, which is process-wide.
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)

	// The attack-surface document is on disk next to the frozen tree.
	snapDir := filepath.Join(workspace, "snapshots", snapID)
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	sawASG := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "asg-") && strings.HasSuffix(e.Name(), ".json") {
			sawASG = true
		}
	}
	if !sawASG {
		t.Fatalf("expected an ASG artifact in %s, got %v", snapDir, entries)
	}

	cases := []struct {
		name     string
		args     []string
		mustHave []string
	}{
		{"summary", []string{"summary", "--snapshot", snapID}, []string{"attack surface", "surface", "coverage", "limitations"}},
		{"entrypoints", []string{"entrypoints", "--snapshot", snapID}, []string{"/users/:id", "gin", "network boundary", "observed"}},
		{"nodes", []string{"nodes", "--snapshot", snapID, "--kind", "EntryPoint"}, []string{"EntryPoint", "/users/:id"}},
		{"edges", []string{"edges", "--snapshot", snapID, "--kind", "REACHES"}, []string{"REACHES"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error {
				return runASG(context.Background(), append(tc.args, "--workspace", workspace, "--db", db))
			})
			if err != nil {
				t.Fatalf("asg %s: %v\n%s", tc.name, err, out)
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(out, want) {
					t.Errorf("output does not contain %q:\n%s", want, out)
				}
			}
		})
	}

	// The single-node view resolves the SCG facts behind a claim, so the node id
	// comes from the node listing.
	nodes, err := captureStdout(t, func() error {
		return runASG(context.Background(), []string{
			"nodes", "--snapshot", snapID, "--kind", "EntryPoint", "--json",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("nodes --json: %v\n%s", err, nodes)
	}
	var page struct {
		Nodes []asg.Node `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(nodes), &page); err != nil {
		t.Fatalf("nodes output is not JSON: %v\n%s", err, nodes)
	}
	if len(page.Nodes) == 0 {
		t.Fatalf("no entry point node: %s", nodes)
	}
	nodeOut, err := captureStdout(t, func() error {
		// The node id is positional, so it must follow the flags: flag parsing
		// stops at the first argument that is not a flag.
		return runASG(context.Background(), []string{
			"node", "--snapshot", snapID, "--workspace", workspace, "--db", db, page.Nodes[0].ID,
		})
	})
	if err != nil {
		t.Fatalf("asg node: %v\n%s", err, nodeOut)
	}
	if !strings.Contains(nodeOut, "evidence") || !strings.Contains(nodeOut, "Report") {
		t.Errorf("node view does not resolve evidence:\n%s", nodeOut)
	}

	// The entry-point table carries the boundary and the control accounting for
	// each route, which is the answer an auditor reads first.
	table, err := captureStdout(t, func() error {
		return runASG(context.Background(), []string{
			"entrypoints", "--snapshot", snapID, "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("asg entrypoints: %v", err)
	}
	for _, want := range []string{"BOUNDARY", "CONTROLS", "SINKS", "GET /users/:id"} {
		if !strings.Contains(table, want) {
			t.Errorf("route table does not contain %q:\n%s", want, table)
		}
	}
}

func TestASGErrors(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)

	cases := []struct {
		name     string
		args     []string
		mustHave string
	}{
		{"no subcommand", nil, "usage: codexploit asg"},
		{"unknown subcommand", []string{"nope"}, "unknown asg subcommand"},
		{"missing source", []string{"build", "--workspace", workspace, "--db", db}, "--source is required"},
		{"missing snapshot", []string{"summary", "--workspace", workspace, "--db", db}, "--snapshot is required"},
		{"unknown snapshot", []string{"summary", "--snapshot", "snap-00000000000000000000000000000000", "--workspace", workspace, "--db", db}, "no attack surface yet"},
		{"entries without snapshot", []string{"entrypoints", "--workspace", workspace, "--db", db}, "--snapshot is required"},
		{"unknown kind", []string{"nodes", "--snapshot", snapID, "--kind", "Nope", "--workspace", workspace, "--db", db}, "unknown node kind"},
		{"node without id", []string{"node", "--snapshot", snapID, "--workspace", workspace, "--db", db}, "node id is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error { return runASG(context.Background(), tc.args) })
			if err == nil {
				t.Fatalf("asg %v unexpectedly succeeded:\n%s", tc.args, out)
			}
			if !strings.Contains(err.Error(), tc.mustHave) {
				t.Errorf("error = %q, want it to contain %q", err, tc.mustHave)
			}
		})
	}

	// A missing attack surface names the command that produces it, so the fix is
	// in the message rather than in the docs.
	_, err := captureStdout(t, func() error {
		return runASG(context.Background(), []string{
			"summary", "--snapshot", snapID, "--workspace", t.TempDir(), "--db", filepath.Join(t.TempDir(), "other.db"),
		})
	})
	if err == nil {
		t.Fatal("summary against an empty workspace succeeded")
	}
	if !strings.Contains(err.Error(), "codexploit asg build") {
		t.Errorf("error is not actionable: %v", err)
	}
}
