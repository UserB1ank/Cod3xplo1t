package path

// TaskState describes the workbench state without changing path evidence.
func TaskState(task Audit) string {
	if task.Archived {
		return "ARCHIVED"
	}
	if task.Status == AuditFailed {
		return "FAILED"
	}
	for _, status := range []Status{StatusAnalyzing, StatusLocalExploring, StatusVerifying} {
		if task.CountsByStatus[string(status)] > 0 {
			return "RUNNING"
		}
	}
	if task.Paused {
		return "PAUSED"
	}
	if task.PathCount == 0 {
		return "EMPTY"
	}
	if task.CountsByStatus[string(StatusQueued)] > 0 {
		return "QUEUED"
	}
	for _, status := range []Status{StatusBlocked, StatusFailed, StatusInterrupted} {
		if task.CountsByStatus[string(status)] > 0 {
			return "BLOCKED"
		}
	}
	return "CONCLUDED"
}
