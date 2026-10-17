package schedule

import (
	"errors"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

type configurableDispatcher struct {
	*recordingDispatcher
	ready bool
}

func (d *configurableDispatcher) Ready() error {
	if !d.ready {
		return errors.New("model settings pending")
	}
	return nil
}

func TestSchedulerWaitsForModelConfigurationBeforeClaiming(t *testing.T) {
	t.Parallel()
	f := newSchedFixture(t, schedPath("audit-1", "path-1"))
	dispatcher := &configurableDispatcher{recordingDispatcher: f.dispatcher}
	f.scheduler.Agent = dispatcher
	before := f.path("path-1")
	for range 3 {
		if result := f.tick(); result.Dispatched != 0 {
			t.Fatal("unconfigured model dispatched work")
		}
	}
	after := f.path("path-1")
	if after.Version != before.Version || after.Status != path.StatusQueued || f.dispatcher.total() != 0 {
		t.Fatal("waiting for settings consumed or changed queued work")
	}
	dispatcher.ready = true
	if result := f.tick(); result.Dispatched != 1 {
		t.Fatal("model did not start dispatching after live configuration")
	}
}
