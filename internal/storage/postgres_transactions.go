package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Only transactions the server explicitly rolled back may be retried. A
// connection failure at commit has an unknown outcome and is returned as-is.
func (s *SQL) postgresTransaction(ctx context.Context, write func(*sql.Tx) error) error {
	for attempt := 0; attempt < 8; attempt++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		err = write(tx)
		if err == nil {
			err = tx.Commit()
		}
		_ = tx.Rollback()
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || (pg.Code != "40001" && pg.Code != "40P01") || attempt == 7 {
			return err
		}
		timer := time.NewTimer(time.Millisecond * time.Duration(1<<attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ErrConflict
}
