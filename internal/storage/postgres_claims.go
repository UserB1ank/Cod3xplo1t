package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/open-mcp-ai/Codexploit/internal/claim"
)

func (s *SQL) AppendClaimRecord(ctx context.Context, r claim.Record) (claim.Record, bool, error) {
	if !s.postgres {
		return claim.Record{}, false, claim.ErrUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return claim.Record{}, false, err
	}
	defer tx.Rollback()
	// Same lock and ordering as snapshot deletion; a late write cannot recreate
	// knowledge belonging to a deleted or deleting source.
	if err := s.lockSnapshotTx(ctx, tx, r.Scope.SnapshotID); err != nil {
		return claim.Record{}, false, err
	}
	var owned, deleting bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM snapshots WHERE snapshot_id=$1 AND project_id=$2),
EXISTS(SELECT 1 FROM snapshot_deletions WHERE snapshot_id=$1) OR EXISTS(SELECT 1 FROM project_deletions WHERE project_id=$2)`, r.Scope.SnapshotID, r.Scope.ProjectID).Scan(&owned, &deleting)
	if err != nil {
		return claim.Record{}, false, err
	}
	if !owned {
		return claim.Record{}, false, claim.ErrNotFound
	}
	if deleting {
		return claim.Record{}, false, claim.ErrConflict
	}
	if r.RunID != "" || r.SessionID != "" {
		var sessionRaw string
		err := tx.QueryRowContext(ctx, `SELECT document_json FROM supervisor_sessions WHERE session_id=$1 AND project_id=$2 FOR SHARE`, r.SessionID, r.Scope.ProjectID).Scan(&sessionRaw)
		if errors.Is(err, sql.ErrNoRows) {
			return claim.Record{}, false, claim.ErrConflict
		}
		if err != nil {
			return claim.Record{}, false, err
		}
		var session SupervisorSession
		if err := json.Unmarshal([]byte(sessionRaw), &session); err != nil {
			return claim.Record{}, false, err
		}
		active := false
		for _, run := range session.Runs {
			if run.ID == r.RunID && run.Status == "RUNNING" {
				active = true
			}
		}
		if !active {
			return claim.Record{}, false, claim.ErrConflict
		}
	}
	var raw, digest string
	err = tx.QueryRowContext(ctx, `SELECT document_json,request_digest FROM knowledge_claim_records WHERE snapshot_id=$1 AND request_key=$2`, r.Scope.SnapshotID, r.RequestKey).Scan(&raw, &digest)
	if err == nil {
		if digest != r.Digest {
			return claim.Record{}, false, claim.ErrConflict
		}
		var old claim.Record
		if err := json.Unmarshal([]byte(raw), &old); err != nil {
			return claim.Record{}, false, err
		}
		return old, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return claim.Record{}, false, err
	}
	var parent bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM knowledge_claim_records WHERE snapshot_id=$1 AND claim_id=$2 AND kind='claim')`, r.Scope.SnapshotID, r.ClaimID).Scan(&parent); err != nil {
		return claim.Record{}, false, err
	}
	if r.Kind != "claim" && !parent {
		return claim.Record{}, false, claim.ErrNotFound
	}
	if r.Kind == "claim" && parent {
		r.Kind = "observation"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge_claim_heads(snapshot_id,project_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, r.Scope.SnapshotID, r.Scope.ProjectID); err != nil {
		return claim.Record{}, false, err
	}
	if err := tx.QueryRowContext(ctx, `UPDATE knowledge_claim_heads SET revision=revision+1 WHERE snapshot_id=$1 AND project_id=$2 RETURNING revision`, r.Scope.SnapshotID, r.Scope.ProjectID).Scan(&r.Revision); err != nil {
		return claim.Record{}, false, err
	}
	bytes, err := json.Marshal(r)
	if err != nil {
		return claim.Record{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO knowledge_claim_records(record_id,snapshot_id,project_id,claim_id,kind,request_key,request_digest,revision,document_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.ID, r.Scope.SnapshotID, r.Scope.ProjectID, r.ClaimID, r.Kind, r.RequestKey, r.Digest, r.Revision, string(bytes))
	if err != nil {
		return claim.Record{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge_claim_outbox(record_id,snapshot_id,revision,event_type) VALUES($1,$2,$3,'knowledge_appended')`, r.ID, r.Scope.SnapshotID, r.Revision); err != nil {
		return claim.Record{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return claim.Record{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return claim.Record{}, false, err
	}
	return r, true, nil
}

func (s *SQL) ReadClaimRecords(ctx context.Context, q claim.Query) (claim.Page, error) {
	if !s.postgres {
		return claim.Page{}, claim.ErrUnavailable
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return claim.Page{}, err
	}
	defer tx.Rollback()
	p := claim.Page{Records: []claim.Record{}}
	var owned bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM snapshots WHERE snapshot_id=$1 AND project_id=$2)`, q.Scope.SnapshotID, q.Scope.ProjectID).Scan(&owned); err != nil {
		return p, err
	}
	if !owned {
		return p, claim.ErrNotFound
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM knowledge_claim_heads WHERE snapshot_id=$1 AND project_id=$2),0)`, q.Scope.SnapshotID, q.Scope.ProjectID).Scan(&p.HeadRevision); err != nil {
		return p, err
	}
	p.Revision = q.Revision
	if p.Revision == 0 {
		p.Revision = p.HeadRevision
	}
	if p.Revision > p.HeadRevision {
		return p, claim.ErrConflict
	}
	if q.ClaimID != "" {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM knowledge_claim_records WHERE snapshot_id=$1 AND claim_id=$2 AND kind='claim' AND revision<=$3)`, q.Scope.SnapshotID, q.ClaimID, p.Revision).Scan(&exists); err != nil {
			return p, err
		}
		if !exists {
			return p, claim.ErrNotFound
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT document_json FROM knowledge_claim_records WHERE snapshot_id=$1 AND project_id=$2 AND revision>$3 AND revision<=$4 AND (($5='' AND kind='claim') OR ($5<>'' AND claim_id=$5)) ORDER BY revision LIMIT $6`, q.Scope.SnapshotID, q.Scope.ProjectID, q.Cursor, p.Revision, q.ClaimID, q.Limit+1)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return p, err
		}
		if len(p.Records) == q.Limit {
			p.HasMore = true
			break
		}
		var record claim.Record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return p, err
		}
		p.Records = append(p.Records, record)
		p.NextCursor = record.Revision
	}
	if err := rows.Err(); err != nil {
		return p, err
	}
	return p, nil
}
