// Command bench-eval runs a labeled corpus through a deployment and writes the
// samples bench-runtime aggregates. It is the explicit opt-in: without
// --allow-real it refuses to spend provider budget.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/bench"
)

type task struct {
	ID         string `json:"id"`
	Group      string `json:"group"`
	Label      string `json:"label"`
	Source     string `json:"source"`
	Objective  string `json:"objective"`
	ProjectID  string `json:"project_id,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
}

type dataset struct {
	Name     string   `json:"name"`
	PerGroup int      `json:"per_group"`
	Tasks    []task   `json:"tasks"`
	Runtimes []string `json:"runtimes,omitempty"`
}

type runView struct {
	RunID        string `json:"run_id"`
	Runtime      string `json:"runtime"`
	Status       string `json:"status"`
	StopReason   string `json:"stop_reason"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	ToolCalls    int    `json:"tool_calls"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	Metrics      *struct {
		Source        string `json:"source"`
		ModelRequests int    `json:"model_requests"`
		Repairs       int    `json:"repairs"`
		Novelty       []int  `json:"novelty"`
	} `json:"metrics"`
	Answer *struct {
		Hypothesis struct {
			Status string `json:"status"`
		} `json:"hypothesis"`
		Supporting    []json.RawMessage `json:"supporting_evidence"`
		Contradicting []json.RawMessage `json:"contradicting_evidence"`
		Obligations   []struct {
			Verdict string `json:"verdict"`
		} `json:"obligations"`
	} `json:"answer"`
}

func main() {
	base := flag.String("base", "http://127.0.0.1:18085", "deployment base URL")
	token := flag.String("token", "", "admin API token")
	datasetPath := flag.String("dataset", "bench-corpus/dataset.json", "dataset JSON")
	out := flag.String("out", "bench-samples.json", "samples output path")
	runs := flag.Int("runs", 3, "repetitions per task and runtime")
	limit := flag.Int("limit", 0, "only the first N tasks (0 means all)")
	allowReal := flag.Bool("allow-real", false, "explicitly spend provider budget")
	flag.Parse()
	if !*allowReal {
		fail("refusing to run: pass --allow-real after the provider and budget are approved")
	}
	if strings.TrimSpace(*token) == "" {
		fail("an admin API token is required")
	}
	raw, err := os.ReadFile(*datasetPath)
	if err != nil {
		fail("read dataset: %v", err)
	}
	var set dataset
	if err := json.Unmarshal(raw, &set); err != nil {
		fail("parse dataset: %v", err)
	}
	if len(set.Tasks) == 0 {
		fail("the dataset has no tasks")
	}
	if *limit > 0 && *limit < len(set.Tasks) {
		set.Tasks = set.Tasks[:*limit]
	}
	api := &client{base: strings.TrimRight(*base, "/"), token: *token, http: &http.Client{Timeout: 60 * time.Second}}
	for index := range set.Tasks {
		if err := setupTask(api, &set.Tasks[index]); err != nil {
			fail("setup %s: %v", set.Tasks[index].ID, err)
		}
	}
	runtimes := set.Runtimes
	if len(runtimes) == 0 {
		runtimes = []string{"llm", "pi"}
	}
	var samples []bench.Sample
	for _, runtime := range runtimes {
		for repetition := 0; repetition < *runs; repetition++ {
			for _, item := range set.Tasks {
				sample, err := evaluate(api, item, runtime)
				if err != nil {
					fmt.Fprintf(os.Stderr, "evaluate %s/%s: %v\n", item.ID, runtime, err)
					samples = append(samples, bench.Sample{Runtime: runtime, TaskID: item.ID, Group: item.Group, Label: item.Label, Status: "FAILED", Predicted: ""})
					continue
				}
				samples = append(samples, sample)
				fmt.Printf("%s %s -> %s\n", item.ID, runtime, sample.Predicted)
			}
		}
	}
	encoded, err := json.MarshalIndent(map[string]any{
		"dataset": set.Name, "expected_runs": len(set.Tasks) * *runs,
		"runtimes": runtimes, "real": samples,
	}, "", "  ")
	if err != nil {
		fail("encode samples: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*out, encoded, 0o600); err != nil {
		fail("write samples: %v", err)
	}
	fmt.Printf("wrote %d samples to %s\n", len(samples), *out)
}

func setupTask(api *client, item *task) error {
	if item.ProjectID != "" && item.SnapshotID != "" {
		return nil
	}
	var project struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}
	if err := api.post("/api/projects", map[string]any{"name": "bench " + item.ID, "source": item.Source}, &project); err != nil {
		return err
	}
	item.ProjectID = project.Project.ID
	var snapshot struct {
		Snapshot struct {
			ID string `json:"snapshot_id"`
		} `json:"snapshot"`
	}
	if err := api.post("/api/projects/"+item.ProjectID+"/snapshots", map[string]any{"build_graph": true, "build_asg": true}, &snapshot); err != nil {
		return err
	}
	item.SnapshotID = snapshot.Snapshot.ID
	if item.ProjectID == "" || item.SnapshotID == "" {
		return fmt.Errorf("the deployment did not return a project and snapshot")
	}
	return nil
}

func evaluate(api *client, item task, runtime string) (bench.Sample, error) {
	var created struct {
		Task struct {
			AuditID string `json:"audit_id"`
		} `json:"task"`
	}
	if err := api.post("/api/projects/"+item.ProjectID+"/tasks", map[string]any{
		"name": "bench " + item.ID, "objective": item.Objective,
		"snapshot_id": item.SnapshotID, "runtime": runtime,
	}, &created); err != nil {
		return bench.Sample{}, err
	}
	auditID := created.Task.AuditID
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		var runs struct {
			Runs []runView `json:"runs"`
		}
		if err := api.get("/api/runs?audit_id="+auditID+"&limit=20", &runs); err != nil {
			return bench.Sample{}, err
		}
		for _, run := range runs.Runs {
			if run.Runtime != runtime || !terminal(run.Status) {
				continue
			}
			return sampleFrom(item, run), nil
		}
		var paths struct {
			Paths []struct {
				Status string `json:"status"`
			} `json:"paths"`
		}
		_ = api.get("/api/audits/"+auditID+"/paths?limit=50", &paths)
		allDone := len(paths.Paths) > 0
		for _, path := range paths.Paths {
			switch path.Status {
			case "QUEUED", "ANALYZING", "HYPOTHESIS_FORMED", "PAUSED":
			default:
				continue
			}
			allDone = false
		}
		if allDone {
			// Paths finished without a run of this runtime: record it as failed.
			return bench.Sample{Runtime: runtime, TaskID: item.ID, Group: item.Group, Label: item.Label, Status: "FAILED"}, nil
		}
		time.Sleep(2 * time.Second)
	}
	return bench.Sample{}, fmt.Errorf("no terminal run within the deadline")
}

func sampleFrom(item task, run runView) bench.Sample {
	sample := bench.Sample{
		Runtime: runtimeName(run), TaskID: item.ID, Group: item.Group, Label: item.Label,
		Status: run.Status, StopReason: run.StopReason,
		InputTokens: run.InputTokens, OutputTokens: run.OutputTokens,
		ToolCalls: run.ToolCalls, ElapsedMS: run.ElapsedMS,
	}
	if run.Metrics != nil {
		sample.UsageSource = run.Metrics.Source
		sample.ModelRequests = run.Metrics.ModelRequests
		sample.Repairs = run.Metrics.Repairs
		sample.Novelty = run.Metrics.Novelty
	}
	if run.Answer != nil {
		sample.Predicted = run.Answer.Hypothesis.Status
		sample.EvidenceItems = len(run.Answer.Supporting) + len(run.Answer.Contradicting)
		sample.ValidEvidence = sample.EvidenceItems
		sample.ObligationsTotal = len(run.Answer.Obligations)
		for _, obligation := range run.Answer.Obligations {
			if obligation.Verdict == "met" || obligation.Verdict == "not_met" {
				sample.ObligationsClosed++
			}
		}
	}
	return sample
}

func runtimeName(run runView) string {
	if run.Runtime == "" {
		return "unknown"
	}
	return run.Runtime
}

func terminal(status string) bool {
	switch status {
	case "SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "INVALID_OUTPUT", "BUDGET_EXCEEDED", "PAUSED":
		return true
	}
	return false
}

type client struct {
	base  string
	token string
	http  *http.Client
}

func (c *client) get(path string, target any) error { return c.do(http.MethodGet, path, nil, target) }
func (c *client) post(path string, body any, target any) error {
	return c.do(http.MethodPost, path, body, target)
}

func (c *client) do(method, path string, body, target any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if response.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, response.StatusCode, string(raw))
	}
	if target == nil {
		return nil
	}
	return json.Unmarshal(raw, target)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
