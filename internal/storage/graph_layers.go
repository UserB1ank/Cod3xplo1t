package storage

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

func validateGraphLayers(id string, g *scg.Graph, a *asg.Document) error {
	if err := validateGraph(id, g); err != nil {
		return err
	}
	if err := validateASG(id, a); err != nil {
		return err
	}
	if a.SCGVersion != g.GraphVersion {
		return ErrConflict
	}
	return nil
}

// ReplaceGraphLayers advances the current review view as one unit. Immutable
// standard artifacts and published knowledge revisions remain available; old
// query views detect superseded versions instead of reading a mixed engine.
func (s *SQL) ReplaceGraphLayers(ctx context.Context, id string, g *scg.Graph, a *asg.Document) error {
	if err := validateGraphLayers(id, g, a); err != nil {
		return err
	}
	return s.snapshotWrite(ctx, id, func(tx *sql.Tx) error {
		if err := s.replaceGraphTx(ctx, tx, id, g); err != nil {
			return err
		}
		return s.replaceASGTx(ctx, tx, id, a)
	})
}
func (m *Memory) ReplaceGraphLayers(ctx context.Context, id string, g *scg.Graph, a *asg.Document) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateGraphLayers(id, g, a); err != nil {
		return err
	}
	var copy struct {
		Graph   *scg.Graph
		Surface *asg.Document
	}
	raw, err := json.Marshal(struct {
		Graph   *scg.Graph
		Surface *asg.Document
	}{g, a})
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &copy); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(id); err != nil {
		return err
	}
	m.graphs[id] = &memoryGraph{graph: copy.Graph}
	m.asgDocuments[id] = copy.Surface
	return nil
}
