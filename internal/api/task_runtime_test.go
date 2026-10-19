package api

import (
	"net/http"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// TestTaskRuntimeSelection pins the public selection boundary: the deployment
// catalog decides what exists, a not-ready runtime is refused instead of falling
// back, and the choice is stored on the task.
func TestTaskRuntimeSelection(t *testing.T) {
	env := newTestEnvWithAgent(t, false, func(goal string) agent.Answer { return agentTestAnswer(goal) })
	project := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"build_graph": true, "build_asg": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)

	base := map[string]any{"name": "Runtime task", "objective": "choose a runtime", "snapshot_id": snapshot.Snapshot.SnapshotID}

	for _, runtime := range []string{"pi", "wormhole"} {
		base["runtime"] = runtime
		refused := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/tasks", base, nil)
		if refused.status != http.StatusBadRequest {
			t.Fatalf("runtime %q: status %d body %s", runtime, refused.status, refused.body)
		}
	}

	base["runtime"] = "llm"
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/tasks", base, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("selecting llm: %d %s", created.status, created.body)
	}
	var receipt struct {
		Task struct {
			Runtime string `json:"runtime"`
			AuditID string `json:"audit_id"`
		} `json:"task"`
	}
	created.decode(t, &receipt)
	if receipt.Task.Runtime != "llm" {
		t.Fatalf("task runtime = %q, want llm", receipt.Task.Runtime)
	}

	listing := do(t, env.ts, http.MethodGet, "/api/agent/runtimes", nil, nil)
	if listing.status != http.StatusOK {
		t.Fatalf("runtimes: %d %s", listing.status, listing.body)
	}
	var catalog struct {
		Runtimes []agent.RuntimeInfo `json:"runtimes"`
	}
	listing.decode(t, &catalog)
	if len(catalog.Runtimes) != 2 {
		t.Fatalf("runtimes = %+v", catalog.Runtimes)
	}
	byName := map[string]agent.RuntimeInfo{}
	for _, info := range catalog.Runtimes {
		byName[info.Name] = info
	}
	if !byName["llm"].Ready {
		t.Errorf("llm is not ready: %+v", byName["llm"])
	}
	if byName["pi"].Ready || byName["pi"].Reason == "" {
		t.Errorf("pi should be unavailable with a reason: %+v", byName["pi"])
	}

}
