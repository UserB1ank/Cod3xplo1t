// Package lifecycle shares snapshot registration and recoverable deletion between
// the CLI and HTTP API. The store remains explicit; reads never invent records.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

type Snapshots struct {
	Store   storage.FullStore
	Manager interface {
		Load(string) (*repository.Snapshot, error)
		Remove(string) error
	}
}

func ProjectID(identity repository.Identity) string {
	sum := sha256.Sum256([]byte(identity.Kind + "\x00" + identity.Name))
	return "proj-" + hex.EncodeToString(sum[:8])
}

func ProjectName(identity repository.Identity) string {
	name := strings.TrimSuffix(identity.Name, "/")
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 && i+1 < len(name) {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, ".git")
	if name == "" {
		name = identity.Name
	}
	return name
}

func (s Snapshots) Register(ctx context.Context, snap *repository.Snapshot, source string) (string, error) {
	if snap == nil {
		return "", fmt.Errorf("%w: snapshot is required", storage.ErrConflict)
	}
	id := ProjectID(snap.Identity)
	if strings.TrimSpace(source) == "" {
		project, err := s.Store.GetProject(ctx, id)
		if err != nil {
			return "", fmt.Errorf("source is required to register a snapshot of a new project: %w", err)
		}
		source = project.Source
	}
	if repository.IsLocalPath(source) {
		var err error
		source, err = filepath.Abs(source)
		if err != nil {
			return "", err
		}
	}
	p := storage.Project{ID: id, Name: ProjectName(snap.Identity), Source: source, IdentityKind: snap.Identity.Kind, Identity: snap.Identity.Name}
	if err := s.Store.EnsureProject(ctx, p); err != nil {
		return "", err
	}
	if err := s.Store.PutSnapshot(ctx, id, snap); err != nil {
		return "", err
	}
	return id, nil
}

// PutManifest preserves the authoritative on-disk artifact on an idempotent replay.
func (s Snapshots) PutManifest(ctx context.Context, snap *repository.Snapshot, mf *analysis.Manifest) (*analysis.Manifest, error) {
	if mf == nil || mf.SnapshotID != snap.SnapshotID {
		return nil, fmt.Errorf("%w: manifest belongs to a different snapshot", storage.ErrConflict)
	}
	want, err := mf.JSON()
	if err != nil {
		return nil, err
	}
	if err := snap.WriteManifest(want); err != nil {
		got, readErr := snap.ReadManifest()
		if readErr != nil {
			return nil, fmt.Errorf("%w: existing manifest cannot be read: %v", storage.ErrConflict, readErr)
		}
		var previous analysis.Manifest
		if json.Unmarshal(got, &previous) != nil || previous.AnalysisID != mf.AnalysisID {
			return nil, fmt.Errorf("%w: snapshot already holds a different analysis", storage.ErrConflict)
		}
		mf = &previous
	}
	if err := s.Store.PutManifest(ctx, snap.SnapshotID, mf); err != nil {
		return nil, err
	}
	return mf, nil
}

func (s Snapshots) Remove(ctx context.Context, id string) error {
	pending, err := s.Store.SnapshotDeletionPending(ctx, id)
	if err != nil {
		return err
	}
	if !pending {
		_, storeErr := s.Store.GetSnapshot(ctx, id)
		if storeErr != nil && !errors.Is(storeErr, storage.ErrNotFound) {
			return storeErr
		}
		if errors.Is(storeErr, storage.ErrNotFound) {
			if _, diskErr := s.Manager.Load(id); diskErr != nil {
				// Also permit cleanup of database-only graphs left by older CLI deletes.
				if _, graphErr := s.Store.GraphSummary(ctx, id); graphErr != nil {
					if !errors.Is(graphErr, storage.ErrNotFound) {
						return graphErr
					}
					if errors.Is(diskErr, os.ErrNotExist) {
						return fmt.Errorf("%w: snapshot %s", storage.ErrNotFound, id)
					}
					return diskErr
				}
			}
		}
		if err := s.Store.BeginSnapshotDeletion(ctx, id); err != nil {
			return err
		}
	}
	if err := s.Manager.Remove(id); err != nil && !errors.Is(err, repository.ErrSnapshotNotFound) && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err = s.Store.DeleteSnapshot(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return err
}
