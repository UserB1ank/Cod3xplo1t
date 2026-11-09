package reviewbatch

import (
	"context"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

func TestReviewBatchProgressKeepsBlockedFailedAndPausedSeparate(t *testing.T) {
	paths := &reviewBatchPathStub{items: map[string]path.Path{
		"blocked": {ID: "blocked", Status: path.StatusBlocked},
		"failed":  {ID: "failed", Status: path.StatusFailed},
		"paused":  {ID: "paused", Status: path.StatusPaused},
		"queued":  {ID: "queued", Status: path.StatusQueued},
	}}
	manager := &Manager{Paths: paths}
	view, err := manager.view(context.Background(), Batch{
		ID: "review-batch-progress", PathIDs: []string{"blocked", "failed", "paused", "queued"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Progress.Blocked != 1 || view.Progress.Failed != 1 || view.Progress.Paused != 1 || view.Progress.Queued != 1 {
		t.Fatalf("progress = %+v", view.Progress)
	}
}

type reviewBatchPathStub struct {
	items map[string]path.Path
}

func (s *reviewBatchPathStub) Audit(string) (*path.Audit, error) {
	return nil, path.ErrNotFound
}

func (s *reviewBatchPathStub) Paths(path.PathQuery) ([]path.Path, int, error) {
	return nil, 0, nil
}

func (s *reviewBatchPathStub) Path(id string) (*path.Path, []path.FeatureRecord, error) {
	item, ok := s.items[id]
	if !ok {
		return nil, nil, path.ErrNotFound
	}
	return &item, nil, nil
}

func (s *reviewBatchPathStub) Cancel(string, string, string) (*path.Path, error) {
	return nil, path.ErrInvalidTransition
}
