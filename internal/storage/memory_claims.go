package storage

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/claim"
)

type storedClaimRecord struct {
	Record claim.Record `json:"record"`
	Key    string       `json:"key"`
	Digest string       `json:"digest"`
}

func (m *Memory) claimScopeLocked(scope claim.Scope) error {
	snap, ok := m.snapshots[scope.SnapshotID]
	if !ok || snap.projectID != scope.ProjectID {
		return claim.ErrNotFound
	}
	if _, deleting := m.deleting[scope.SnapshotID]; deleting {
		return claim.ErrConflict
	}
	if _, deleting := m.projectDeletions[scope.ProjectID]; deleting {
		return claim.ErrConflict
	}
	return nil
}

func (m *Memory) AppendClaimRecord(ctx context.Context, r claim.Record) (claim.Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return claim.Record{}, false, err
	}
	if err := m.claimScopeLocked(r.Scope); err != nil {
		return claim.Record{}, false, err
	}
	if r.RunID != "" || r.SessionID != "" {
		session, ok := m.supervisorSessions[r.SessionID]
		active := false
		if ok && session.ProjectID == r.Scope.ProjectID {
			origin := claim.OriginFrom(ctx)
			for _, run := range session.Runs {
				if run.ID == r.RunID && run.Status == "RUNNING" &&
					run.ExecutionOwner == origin.Owner && run.LeaseEpoch == origin.Epoch {
					active = true
				}
			}
		}
		if !active {
			return claim.Record{}, false, claim.ErrConflict
		}
	}
	var head int64
	parent := false
	for _, raw := range m.claimRecords {
		var old storedClaimRecord
		if err := json.Unmarshal(raw, &old); err != nil {
			return claim.Record{}, false, err
		}
		if old.Record.Scope != r.Scope {
			continue
		}
		if old.Key == r.RequestKey {
			if old.Digest != r.Digest {
				return claim.Record{}, false, claim.ErrConflict
			}
			return old.Record, false, nil
		}
		if old.Record.Revision > head {
			head = old.Record.Revision
		}
		if old.Record.ClaimID == r.ClaimID && old.Record.Kind == "claim" {
			parent = true
		}
	}
	if r.Kind != "claim" && !parent {
		return claim.Record{}, false, claim.ErrNotFound
	}
	if r.Kind == "claim" && parent {
		r.Kind = "observation"
	}
	r.Revision = head + 1
	raw, err := json.Marshal(storedClaimRecord{r, r.RequestKey, r.Digest})
	if err != nil {
		return claim.Record{}, false, err
	}
	if m.claimRecords == nil {
		m.claimRecords = map[string][]byte{}
	}
	m.claimRecords[r.ID] = raw
	return r, true, nil
}

func (m *Memory) ReadClaimRecords(ctx context.Context, q claim.Query) (claim.Page, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return claim.Page{}, err
	}
	if err := m.claimScopeLocked(q.Scope); err != nil {
		return claim.Page{}, err
	}
	p := claim.Page{Records: []claim.Record{}}
	all := []claim.Record{}
	parent := q.ClaimID == ""
	for _, raw := range m.claimRecords {
		var row storedClaimRecord
		if err := json.Unmarshal(raw, &row); err != nil {
			return p, err
		}
		if row.Record.Scope != q.Scope {
			continue
		}
		all = append(all, row.Record)
		if row.Record.Revision > p.HeadRevision {
			p.HeadRevision = row.Record.Revision
		}
	}
	p.Revision = q.Revision
	if p.Revision == 0 {
		p.Revision = p.HeadRevision
	}
	if p.Revision > p.HeadRevision {
		return p, claim.ErrConflict
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Revision < all[j].Revision })
	for _, r := range all {
		if r.Revision > p.Revision {
			continue
		}
		if r.ClaimID == q.ClaimID && r.Kind == "claim" {
			parent = true
		}
		if r.Revision <= q.Cursor || (q.ClaimID == "" && r.Kind != "claim") || (q.ClaimID != "" && r.ClaimID != q.ClaimID) {
			continue
		}
		if len(p.Records) == q.Limit {
			p.HasMore = true
			break
		}
		p.Records = append(p.Records, r)
		p.NextCursor = r.Revision
	}
	if !parent {
		return p, claim.ErrNotFound
	}
	return p, nil
}

func (m *Memory) deleteClaimRecordsLocked(snapshot string) {
	for key, raw := range m.claimRecords {
		var row storedClaimRecord
		if json.Unmarshal(raw, &row) == nil && row.Record.Scope.SnapshotID == snapshot {
			delete(m.claimRecords, key)
		}
	}
}
