package lifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// Projects owns the recoverable project deletion sequence: prove no referenced
// work is active, write a tombstone, fence every snapshot, remove filesystem
// trees and database rows, then delete the project row. A crash at any point
// leaves a pending tombstone, so a retried DELETE resumes instead of starting a
// second cleanup or reporting success early.
type Projects struct {
	Store     storage.FullStore
	Snapshots Snapshots
}

func NewProjects(store storage.FullStore, manager interface {
	Load(string) (*repository.Snapshot, error)
	Remove(string) error
}) Projects {
	return Projects{Store: store, Snapshots: Snapshots{Store: store, Manager: manager}}
}

// Delete implements the writer-facing project deletion contract.
func (p Projects) Delete(ctx context.Context, id string) error {
	if p.Store == nil {
		return fmt.Errorf("%w: project storage is unavailable", storage.ErrConflict)
	}
	deletion, err := p.Store.ProjectDeletion(ctx, id)
	switch {
	case err == nil && deletion.State == storage.ProjectDeletionCompleted:
		return nil
	case err == nil:
		// A pending intent resumes below.
	case errors.Is(err, storage.ErrNotFound):
		if _, projectErr := p.Store.GetProject(ctx, id); projectErr != nil {
			return projectErr
		}
		if _, beginErr := p.Store.BeginProjectDeletion(ctx, id); beginErr != nil {
			return beginErr
		}
	default:
		return err
	}
	records, err := p.Store.ListSnapshots(ctx, id)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := p.Snapshots.Remove(ctx, record.SnapshotID); err != nil {
			return err
		}
	}
	_, err = p.Store.FinishProjectDeletion(ctx, id)
	return err
}
