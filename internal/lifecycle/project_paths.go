package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

// ProjectPaths stops the project's existing path queues. This is a repeatable
// bulk operation over existing controls, not a project-wide ban on future work.
// A cancelled path fences its worker; unfinished runs remain visible until the
// owning executor acknowledges termination. Deletion keeps its separate guard.
type ProjectPaths struct {
	Store           storage.FullStore
	Paths           *path.Service
	CancelWorkflow  func(context.Context, string, string) error
	CancelLocalPath func(string)
}

type PathStopResult struct {
	APIVersion              string          `json:"api_version"`
	ProjectID               string          `json:"project_id"`
	State                   string          `json:"state"`
	CancelledPaths          int             `json:"cancelled_paths"`
	PausedTasks             int             `json:"paused_tasks"`
	RemainingPaths          int             `json:"remaining_paths"`
	PendingAgentRuns        int             `json:"pending_agent_runs"`
	PendingVerificationRuns int             `json:"pending_verification_runs"`
	PendingWorkflows        int             `json:"pending_workflows"`
	Errors                  []PathStopError `json:"errors"`
}
type PathStopError struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Message string `json:"message"`
}

func (p ProjectPaths) tasks(ctx context.Context, projectID string) ([]path.Audit, error) {
	if _, err := p.Store.GetProject(ctx, projectID); err != nil {
		return nil, err
	}
	tasks := []path.Audit{}
	for offset := 0; ; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, total, err := p.Store.ListAudits(path.AuditQuery{ProjectID: projectID, Limit: 100, Offset: offset})
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, page...)
		offset += len(page)
		if offset >= total {
			return tasks, nil
		}
		if len(page) == 0 {
			return nil, errors.New("project task listing changed; retry the operation")
		}
	}
}

func (p ProjectPaths) Stop(ctx context.Context, projectID, actor string) (PathStopResult, error) {
	tasks, err := p.tasks(ctx, projectID)
	if err != nil {
		return PathStopResult{}, err
	}
	failures := []PathStopError{}
	cancelled, paused := 0, 0
	activities := map[string]storage.TaskActivity{}
	if reader, ok := p.Store.(storage.TaskActivityReader); ok {
		ids := make([]string, len(tasks))
		for i := range tasks {
			ids[i] = tasks[i].ID
		}
		activities, err = reader.TaskActivities(ctx, ids)
		if err != nil {
			return PathStopResult{}, err
		}
	}
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			return PathStopResult{}, err
		}
		activity := activities[task.ID]
		if activity.WorkflowRunID != "" && !workflow.RunTerminal(activity.WorkflowStatus) {
			var cancelErr error
			if p.CancelWorkflow == nil {
				cancelErr = errors.New("workflow controls are unavailable")
			} else {
				cancelErr = p.CancelWorkflow(ctx, projectID, activity.WorkflowRunID)
			}
			if cancelErr != nil {
				failures = append(failures, PathStopError{"workflow", activity.WorkflowRunID, cancelErr.Error()})
			}
		}
		// Close scheduling before touching paths. CAS retries preserve concurrent
		// category/pin changes and workflow completion, rather than overwriting them.
		if err := p.pauseTask(task.ID); err != nil {
			failures = append(failures, PathStopError{"task", task.ID, err.Error()})
			continue
		}
		paused++
		for offset := 0; ; {
			if err := ctx.Err(); err != nil {
				return PathStopResult{}, err
			}
			paths, total, err := p.Store.ListPaths(path.PathQuery{AuditID: task.ID, Sort: "path_id", Limit: 100, Offset: offset})
			if err != nil {
				return PathStopResult{}, err
			}
			for _, item := range paths {
				if item.Status.Terminal() {
					if item.Status == path.StatusCancelled && p.CancelLocalPath != nil {
						p.CancelLocalPath(item.ID)
					}
					continue
				}
				changed, err := p.cancelPath(item.ID, actor)
				if err != nil {
					failures = append(failures, PathStopError{"path", item.ID, err.Error()})
				} else if changed {
					cancelled++
				}
			}
			offset += len(paths)
			if offset >= total {
				break
			}
			if len(paths) == 0 {
				return PathStopResult{}, errors.New("project paths changed; retry the operation")
			}
		}
		if stopper, ok := p.Store.(agent.PausedRunStopper); ok {
			for offset := 0; ; {
				runs, total, err := p.Store.ListRuns(agent.RunQuery{AuditID: task.ID, Limit: 100, Offset: offset})
				if err != nil {
					return PathStopResult{}, err
				}
				for _, run := range runs {
					if run.Status == agent.RunPaused {
						if err := stopper.CancelPausedRun(ctx, run.ID, actor); err != nil {
							failures = append(failures, PathStopError{"agent_run", run.ID, err.Error()})
						}
					}
				}
				offset += len(runs)
				if offset >= total {
					break
				}
				if len(runs) == 0 {
					return PathStopResult{}, errors.New("incomplete paused run listing")
				}
			}
		}
	}
	result, err := p.Status(ctx, projectID)
	if err != nil {
		return result, err
	}
	result.CancelledPaths, result.PausedTasks, result.Errors = cancelled, paused, failures
	if len(failures) > 0 {
		result.State = "PARTIAL"
	}
	return result, nil
}

func (p ProjectPaths) pauseTask(id string) error {
	for attempt := 0; attempt < 3; attempt++ {
		task, err := p.Store.GetAudit(id)
		if err != nil {
			return err
		}
		if task.Paused || task.Archived {
			return nil
		}
		version := task.Version
		task.Paused = true
		task.Version++
		task.UpdatedAt = path.NowString(time.Now().UTC())
		err = p.Store.UpdateAudit(*task, version)
		if !errors.Is(err, path.ErrConflict) {
			return err
		}
	}
	return fmt.Errorf("%w: task changed during stop; retry", path.ErrConflict)
}

func (p ProjectPaths) cancelPath(id, actor string) (bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		item, err := p.Store.GetPath(id)
		if err != nil {
			return false, err
		}
		if item.Status.Terminal() {
			return false, nil
		}
		_, err = p.Paths.Cancel(id, actor, "operator stopped project paths")
		if err == nil && p.CancelLocalPath != nil {
			p.CancelLocalPath(id)
		}
		if !errors.Is(err, path.ErrConflict) && !errors.Is(err, path.ErrInvalidTransition) {
			return err == nil, err
		}
	}
	return false, fmt.Errorf("%w: path changed during stop; retry", path.ErrConflict)
}

func (p ProjectPaths) Status(ctx context.Context, projectID string) (PathStopResult, error) {
	result := PathStopResult{APIVersion: "codexploit/v1", ProjectID: projectID, State: "STOPPED", Errors: []PathStopError{}}
	tasks, err := p.tasks(ctx, projectID)
	if err != nil {
		return result, err
	}
	ids := make([]string, len(tasks))
	for i, task := range tasks {
		ids[i] = task.ID
		if task.Paused {
			result.PausedTasks++
		}
		for offset := 0; ; {
			paths, total, err := p.Store.ListPaths(path.PathQuery{AuditID: task.ID, Sort: "path_id", Limit: 100, Offset: offset})
			if err != nil {
				return result, err
			}
			for _, item := range paths {
				if !item.Status.Terminal() {
					result.RemainingPaths++
				}
			}
			offset += len(paths)
			if offset >= total {
				break
			}
			if len(paths) == 0 {
				return result, errors.New("incomplete path listing")
			}
		}
		for offset := 0; ; {
			runs, total, err := p.Store.ListRuns(agent.RunQuery{AuditID: task.ID, Limit: 100, Offset: offset})
			if err != nil {
				return result, err
			}
			for _, run := range runs {
				if !run.Status.Terminal() {
					result.PendingAgentRuns++
				}
			}
			offset += len(runs)
			if offset >= total {
				break
			}
			if len(runs) == 0 {
				return result, errors.New("incomplete agent run listing")
			}
		}
		for offset := 0; ; {
			runs, total, err := p.Store.ListVerificationRuns(verify.RunQuery{AuditID: task.ID, Limit: 100, Offset: offset})
			if err != nil {
				return result, err
			}
			for _, run := range runs {
				if !run.Status.Terminal() {
					result.PendingVerificationRuns++
				}
			}
			offset += len(runs)
			if offset >= total {
				break
			}
			if len(runs) == 0 {
				return result, errors.New("incomplete verification run listing")
			}
		}
	}
	if reader, ok := p.Store.(storage.TaskActivityReader); ok {
		activities, err := reader.TaskActivities(ctx, ids)
		if err != nil {
			return result, err
		}
		for _, activity := range activities {
			if activity.WorkflowRunID != "" && !workflow.RunTerminal(activity.WorkflowStatus) {
				result.PendingWorkflows++
			}
		}
	}
	// A workflow may become terminal between the HTTP projection sync and
	// this read. Do not promise STOPPED while deletion still sees an active
	// AnalysisRun; the next status poll synchronizes that remaining projection.
	if _, active, err := p.Store.ActiveAnalysisRun(ctx, projectID); err != nil {
		return result, err
	} else if active && result.PendingWorkflows == 0 {
		result.PendingWorkflows = 1
	}
	if result.RemainingPaths+result.PendingAgentRuns+result.PendingVerificationRuns+result.PendingWorkflows > 0 {
		result.State = "STOPPING"
	}
	return result, nil
}
