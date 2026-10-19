package storage

import (
	"context"
	"database/sql"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func (s *SQL) checkVerificationAuthorityTx(ctx context.Context, tx *sql.Tx, id, snapshot string) error {
	var owner, scope string
	var epoch int64
	err := tx.QueryRowContext(ctx, `SELECT host_id,host_epoch,snapshot_id FROM verification_runs WHERE run_id=$1 FOR UPDATE`, id).Scan(&owner, &epoch, &scope)
	if err != nil {
		return mapVerifySQLError(err)
	}
	if owner != s.instanceID || epoch != s.hostEpoch.Load() || scope != snapshot {
		return verify.ErrConflict
	}
	if s.checkHostLeaseTx(ctx, tx, owner, epoch) != nil {
		return verify.ErrConflict
	}
	return nil
}
