package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

// knowledgeScopeQuery resolves one project snapshot that is not being retired.
const knowledgeScopeQuery = `SELECT 1 FROM snapshots s
WHERE s.project_id = ? AND s.snapshot_id = ?
  AND NOT EXISTS (SELECT 1 FROM snapshot_deletions d WHERE d.snapshot_id = s.snapshot_id)`

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func knowledgeScopeExists(ctx context.Context, q rowQuerier, rebind func(string) string, scope publication.Scope) bool {
	var one int
	err := q.QueryRowContext(ctx, rebind(knowledgeScopeQuery), scope.ProjectID, scope.SnapshotID).Scan(&one)
	return err == nil
}

func (s *SQL) KnowledgeHead(ctx context.Context, scope publication.Scope) (string, error) {
	if !knowledgeScopeExists(ctx, s.db, s.rebind, scope) {
		return "", publication.ErrNotFound
	}
	var revision string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT revision FROM knowledge_revisions WHERE project_id = ? AND snapshot_id = ? ORDER BY revision_no DESC LIMIT 1`), scope.ProjectID, scope.SnapshotID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return "rev-0", nil
	}
	if err != nil {
		return "", err
	}
	return revision, nil
}

func (s *SQL) KnowledgeBatch(ctx context.Context, scope publication.Scope, batchID string) (publication.Revision, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM knowledge_revisions WHERE project_id = ? AND snapshot_id = ? AND batch_id = ?`), scope.ProjectID, scope.SnapshotID, batchID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return publication.Revision{}, publication.ErrNotFound
	}
	if err != nil {
		return publication.Revision{}, err
	}
	var document publication.RevisionDocument
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return publication.Revision{}, err
	}
	return document.Revision, nil
}

func (s *SQL) GetKnowledgeRevision(ctx context.Context, scope publication.Scope, revision string) (publication.RevisionDocument, error) {
	if !knowledgeScopeExists(ctx, s.db, s.rebind, scope) {
		return publication.RevisionDocument{}, publication.ErrNotFound
	}
	var raw string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT document_json FROM knowledge_revisions WHERE project_id = ? AND snapshot_id = ? AND revision = ?`), scope.ProjectID, scope.SnapshotID, revision).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return publication.RevisionDocument{}, publication.ErrNotFound
	}
	if err != nil {
		return publication.RevisionDocument{}, err
	}
	var document publication.RevisionDocument
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return publication.RevisionDocument{}, err
	}
	return document, nil
}

func (s *SQL) ListKnowledgeRevisions(ctx context.Context, scope publication.Scope, limit int) ([]publication.Revision, error) {
	if !knowledgeScopeExists(ctx, s.db, s.rebind, scope) {
		return nil, publication.ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT document_json FROM knowledge_revisions WHERE project_id = ? AND snapshot_id = ? ORDER BY revision_no LIMIT ?`), scope.ProjectID, scope.SnapshotID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	revisions := []publication.Revision{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var document publication.RevisionDocument
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			return nil, err
		}
		revisions = append(revisions, document.Revision)
	}
	return revisions, rows.Err()
}

func (s *SQL) ListKnowledgeOutbox(ctx context.Context, scope publication.Scope, limit int) ([]publication.OutboxEvent, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT event_id, revision, kind, payload_json, created_at FROM knowledge_outbox WHERE project_id = ? AND snapshot_id = ? ORDER BY revision, event_id LIMIT ?`), scope.ProjectID, scope.SnapshotID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []publication.OutboxEvent{}
	for rows.Next() {
		event := publication.OutboxEvent{Scope: scope}
		var payload string
		if err := rows.Scan(&event.ID, &event.Revision, &event.Kind, &payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.Payload = json.RawMessage(payload)
		events = append(events, event)
	}
	return events, rows.Err()
}

// PublishKnowledge commits the revision row and its outbox event in one
// transaction and rejects a head that moved since expectedHead was read.
func (s *SQL) PublishKnowledge(ctx context.Context, expectedHead string, document publication.RevisionDocument, event publication.OutboxEvent) error {
	scope := document.Revision.Scope
	raw, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return s.snapshotWrite(ctx, scope.SnapshotID, func(tx *sql.Tx) error {
		if !knowledgeScopeExists(ctx, tx, s.rebind, scope) {
			return publication.ErrNotFound
		}
		var headNo int
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT revision_no FROM knowledge_revisions WHERE project_id = ? AND snapshot_id = ? ORDER BY revision_no DESC LIMIT 1`), scope.ProjectID, scope.SnapshotID).Scan(&headNo)
		if errors.Is(err, sql.ErrNoRows) {
			headNo = 0
		} else if err != nil {
			return err
		}
		if headNo != document.Revision.Number-1 || expectedHead != "rev-"+strconv.Itoa(headNo) {
			return publication.ErrVersionConflict
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO knowledge_revisions (project_id, snapshot_id, revision, revision_no, batch_id, digest, base_revision, document_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)`),
			scope.ProjectID, scope.SnapshotID, document.Revision.ID, document.Revision.Number, document.Revision.BatchID, document.Revision.Digest, document.Revision.BaseRevision, string(raw), document.Revision.CreatedAt); err != nil {
			return mapSQLError(err)
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO knowledge_outbox (event_id, project_id, snapshot_id, revision, kind, payload_json, created_at) VALUES (?,?,?,?,?,?,?)`),
			event.ID, scope.ProjectID, scope.SnapshotID, event.Revision, event.Kind, string(event.Payload), event.CreatedAt); err != nil {
			return mapSQLError(err)
		}
		return nil
	})
}
