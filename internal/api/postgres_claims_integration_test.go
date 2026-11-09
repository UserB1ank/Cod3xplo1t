package api

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/claim"
)

func TestPostgresKnowledgeClaimsPersistAcrossRebuild(t *testing.T) {
	cfg := postgresConfig(t)
	open := func() *testEnv {
		rt, err := app.Build(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return serveTestEnv(t, rt, false)
	}
	env := open()
	project := createProject(t, env.ts, newTestSource(t))
	capture := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	snap := snapshot.Snapshot.SnapshotID
	base := "/api/v1/projects/" + project.Project.ID + "/knowledge/claims"
	body := map[string]any{"snapshot_id": snap, "request_key": "pg-claim", "category": "vulnerability", "statement": "Review the entry point", "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}
	created := do(t, env.ts, http.MethodPost, base, body, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("PG submit: %d %s", created.status, created.body)
	}
	var result struct {
		Record claim.Record `json:"record"`
	}
	created.decode(t, &result)
	detail := base + "/" + result.Record.ClaimID
	question := do(t, env.ts, http.MethodPost, detail+"/questions", map[string]any{"snapshot_id": snap, "request_key": "pg-question", "statement": "Is there an authorization control?"}, nil)
	if question.status != http.StatusCreated {
		t.Fatalf("PG question: %d %s", question.status, question.body)
	}
	url := detail + "?snapshot_id=" + snap + "&revision=2"
	before := do(t, env.ts, http.MethodGet, url, nil, nil)
	env.ts.Close()
	if err := env.rt.Close(); err != nil {
		t.Fatal(err)
	}
	env = open()
	after := do(t, env.ts, http.MethodGet, url, nil, nil)
	if before.status != http.StatusOK || after.status != http.StatusOK || string(before.body) != string(after.body) {
		t.Fatalf("PG restart changed knowledge: %d %s", after.status, after.body)
	}
	replay := do(t, env.ts, http.MethodPost, base, body, nil)
	if replay.status != http.StatusOK {
		t.Fatalf("PG replay after restart: %d %s", replay.status, replay.body)
	}
	// Two application instances must agree about idempotency, not just goroutines
	// sharing one in-memory lock.
	second := open()
	var wg sync.WaitGroup
	errors := make(chan error, 12)
	for i := range 12 {
		server := env.server
		if i%2 != 0 {
			server = second.server
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := server.claimService().Submit(context.Background(), project.Project.ID, "operator", "question", result.Record.ClaimID, claim.Input{SnapshotID: snap, RequestKey: "concurrent-question", Statement: "Check shared authorization"})
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	read := do(t, env.ts, http.MethodGet, detail+"?snapshot_id="+snap, nil, nil)
	var page claim.Page
	read.decode(t, &page)
	if page.Revision != 3 || len(page.Records) != 3 {
		t.Fatalf("concurrent duplicates: %s", read.body)
	}
	assertKnowledgeCancellation(t, second)
}
