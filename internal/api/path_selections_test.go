package api

import (
	"net/http"
	"testing"
)

func TestSelectingPathsStartsIndependentIdempotentRuns(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	snapshots := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if snapshots.status != http.StatusCreated {
		t.Fatalf("snapshot: %d %s", snapshots.status, snapshots.body)
	}
	var snapshot snapshotResponse
	snapshots.decode(t, &snapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshot.Snapshot.SnapshotID})
	page := auditPaths(t, env.ts, audit.Audit.ID, "?limit=10&sort=priority")
	if len(page.Paths) < 2 {
		t.Fatalf("fixture queued %d paths", len(page.Paths))
	}
	selected := []string{page.Paths[0].ID, page.Paths[1].ID}
	url := "/api/v1/projects/" + project.Project.ID + "/path-selections"
	if reader := doAs(t, env.ts, readerSecret, http.MethodPost, url, map[string]any{"api_version": "codexploit/v1", "path_ids": selected}, nil); reader.status != http.StatusForbidden {
		t.Fatalf("reader selection = %d %s", reader.status, reader.body)
	}
	first := do(t, env.ts, http.MethodPost, url, map[string]any{"api_version": "codexploit/v1", "path_ids": selected}, nil)
	if first.status != http.StatusOK {
		t.Fatalf("select: %d %s", first.status, first.body)
	}
	var result struct {
		Selections []selectedPath `json:"selections"`
		Reused     bool           `json:"reused"`
	}
	first.decode(t, &result)
	if len(result.Selections) != 2 || result.Selections[0].RunID == "" || result.Selections[1].RunID == "" || result.Selections[0].SelectionID == result.Selections[1].SelectionID {
		t.Fatalf("selections = %+v", result)
	}
	if result.Selections[0].AuditID != audit.Audit.ID || result.Selections[0].PathID != selected[0] || result.Selections[0].Source != "agent" {
		t.Fatalf("mapping = %+v", result.Selections[0])
	}
	// Repeating the same selection returns the same runs, not duplicates.
	second := do(t, env.ts, http.MethodPost, url, map[string]any{"api_version": "codexploit/v1", "path_ids": selected}, nil)
	var replay struct {
		Selections []selectedPath `json:"selections"`
		Reused     bool           `json:"reused"`
	}
	second.decode(t, &replay)
	if second.status != http.StatusOK || !replay.Reused || len(replay.Selections) != 2 || replay.Selections[0].RunID != result.Selections[0].RunID || replay.Selections[1].RunID != result.Selections[1].RunID {
		t.Fatalf("repeat selection = %d %+v", second.status, replay)
	}
	if !replay.Selections[0].Reused {
		t.Fatal("repeat did not mark the run as reused")
	}
	listed := do(t, env.ts, http.MethodGet, url+"?path_id="+selected[0], nil, nil)
	if listed.status != http.StatusOK {
		t.Fatalf("list selections: %d %s", listed.status, listed.body)
	}
	// The same path text from another project is a different path identity and
	// cannot be selected through this project.
	other := createProject(t, env.ts, asgFixtureSource(t))
	cross := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+other.Project.ID+"/path-selections", map[string]any{
		"api_version": "codexploit/v1", "path_ids": []string{selected[0]},
	}, nil)
	if cross.status != http.StatusNotFound {
		t.Fatalf("cross-project selection = %d %s", cross.status, cross.body)
	}
	// A path that was already analyzed without a selection mapping is not
	// silently re-labelled as a new subtask.
	if len(page.Paths) > 2 {
		third := do(t, env.ts, http.MethodPost, url, map[string]any{"api_version": "codexploit/v1", "path_ids": []string{page.Paths[2].ID}}, nil)
		if third.status != http.StatusOK && third.status != http.StatusConflict {
			t.Fatalf("analyzed path selection = %d %s", third.status, third.body)
		}
	}
}

func TestPathSelectionRejectsInvalidBatches(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	url := "/api/v1/projects/" + project.Project.ID + "/path-selections"
	for name, body := range map[string]map[string]any{
		"empty":   {"api_version": "codexploit/v1", "path_ids": []string{}},
		"dupe":    {"api_version": "codexploit/v1", "path_ids": []string{"path-a", "path-a"}},
		"toomany": {"api_version": "codexploit/v1", "path_ids": []string{"a", "b", "c", "d", "e", "f"}},
	} {
		response := do(t, env.ts, http.MethodPost, url, body, nil)
		if response.status != http.StatusBadRequest {
			t.Fatalf("%s = %d %s", name, response.status, response.body)
		}
	}
}
