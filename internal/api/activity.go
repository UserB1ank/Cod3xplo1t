package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// projectActivityEntry is one live execution a reviewer can watch from the
// project page: the task, the run, the stage it has reached and the queue behind
// it. It is a projection only; the run and path remain the source of truth.
type projectActivityEntry struct {
	TaskID    string `json:"task_id"`
	TaskName  string `json:"task_name"`
	RunID     string `json:"run_id,omitempty"`
	PathID    string `json:"path_id,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
	Status    string `json:"status,omitempty"`
	Stage     string `json:"stage"`
	StartedAt string `json:"started_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Queued    int    `json:"queued"`
}

type projectActivityCounts struct {
	Running int `json:"running"`
	Paused  int `json:"paused"`
	Queued  int `json:"queued"`
	Tasks   int `json:"tasks"`
}

// handleProjectActivity answers GET /api/projects/{id}/activity: the tasks in a
// project that are executing right now, the stage each run reached, and how much
// work is queued. The page polls it so a person does not have to open every task
// to find the active one.
func (s *Server) handleProjectActivity(w http.ResponseWriter, r *http.Request) {
	if s.agentUnavailable(w) {
		return
	}
	projectID := r.PathValue("id")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	audits, _, err := s.Audit.Audits(path.AuditQuery{ProjectID: projectID, Limit: 200})
	if err != nil {
		writeAuditError(w, err, "")
		return
	}
	views, err := s.taskViews(r.Context(), audits)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	byTask := make(map[string]sourceTask, len(views))
	for _, view := range views {
		byTask[view.ID] = view
	}
	entries := make([]projectActivityEntry, 0)
	counts := projectActivityCounts{}
	activeTasks := map[string]bool{}
	for _, audit := range audits {
		if audit.Archived {
			continue
		}
		view := byTask[audit.ID]
		name := view.Name
		if strings.TrimSpace(name) == "" {
			name = view.Objective
		}
		if strings.TrimSpace(name) == "" {
			name = "未命名任务"
		}
		queued := view.CountsByStatus["QUEUED"]
		counts.Queued += queued
		runs, _, err := s.Agent.Store.ListRuns(agent.RunQuery{
			AuditID: audit.ID,
			Status:  []agent.RunStatus{agent.RunRunning, agent.RunPaused},
			Limit:   50,
		})
		if err != nil {
			writeAgentError(w, err, audit.ID)
			return
		}
		for _, run := range runs {
			stage := "analyzing"
			if run.Status == agent.RunPaused {
				stage = "paused"
				counts.Paused++
			} else {
				counts.Running++
				if p, _, err := s.Audit.Path(run.PathID); err == nil && p.Status == path.StatusVerifying {
					stage = "verifying"
				}
			}
			activeTasks[audit.ID] = true
			entries = append(entries, projectActivityEntry{
				TaskID: audit.ID, TaskName: name, RunID: run.ID, PathID: run.PathID,
				Runtime: run.Runtime, Status: string(run.Status), Stage: stage,
				StartedAt: run.StartedAt, UpdatedAt: run.UpdatedAt,
				ElapsedMS: elapsedFrom(run), Queued: queued,
			})
		}
		if len(runs) == 0 && view.WorkflowStatus == "RUNNING" {
			if !activeTasks[audit.ID] {
				activeTasks[audit.ID] = true
			}
			entries = append(entries, projectActivityEntry{
				TaskID: audit.ID, TaskName: name, Status: "RUNNING", Stage: "workflow",
				Queued: queued,
			})
		}
		if len(runs) == 0 && view.WorkflowStatus != "RUNNING" && view.CountsByPathStatus[string(path.StatusVerifying)] > 0 {
			wrote := false
			for _, entry := range entries {
				if entry.TaskID == audit.ID && entry.Stage == "verifying" {
					wrote = true
				}
			}
			if !wrote {
				entries = append(entries, projectActivityEntry{
					TaskID: audit.ID, TaskName: name, Status: "RUNNING", Stage: "verifying", Queued: queued,
				})
			}
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		rank := func(stage string) int {
			switch stage {
			case "analyzing", "verifying":
				return 0
			case "workflow":
				return 1
			case "paused":
				return 2
			}
			return 3
		}
		if rank(entries[i].Stage) != rank(entries[j].Stage) {
			return rank(entries[i].Stage) < rank(entries[j].Stage)
		}
		return entries[i].StartedAt > entries[j].StartedAt
	})
	counts.Tasks = len(activeTasks)
	writeJSON(w, http.StatusOK, map[string]any{
		"project_id": projectID, "active": entries, "counts": counts,
	})
}

// elapsedFrom prefers the run's own elapsed figure and falls back to the wall
// clock for a run that is still in flight.
func elapsedFrom(run agent.Run) int64 {
	if run.ElapsedMS > 0 {
		return run.ElapsedMS
	}
	if started, err := time.Parse(time.RFC3339, run.StartedAt); err == nil {
		if elapsed := time.Since(started).Milliseconds(); elapsed > 0 {
			return elapsed
		}
	}
	return 0
}
