package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
)

func (s *SQL) GetTaskCategories(ctx context.Context, project string) (TaskCategories, error) {
	var catalog TaskCategories
	var document string
	if err := s.db.QueryRowContext(ctx, s.rebind("SELECT task_categories_json, task_categories_version FROM projects WHERE id = ?"), project).Scan(&document, &catalog.Version); err != nil {
		return TaskCategories{}, mapSQLError(err)
	}
	err := json.Unmarshal([]byte(document), &catalog.Categories)
	return catalog, err
}

func (s *SQL) SetTaskCategories(ctx context.Context, project string, categories []string, version int64) (TaskCategories, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskCategories{}, mapSQLError(err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, s.rebind("UPDATE projects SET task_categories_version = task_categories_version WHERE id = ? AND task_categories_version = ?"), project, version)
	if err != nil {
		return TaskCategories{}, mapSQLError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return TaskCategories{}, err
	}
	if count != 1 {
		return TaskCategories{}, ErrConflict
	}
	rows, err := tx.QueryContext(ctx, s.rebind("SELECT DISTINCT task_category FROM audits WHERE task_category <> '' AND snapshot_id IN (SELECT snapshot_id FROM snapshots WHERE project_id = ?)"), project)
	if err != nil {
		return TaskCategories{}, err
	}
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			rows.Close()
			return TaskCategories{}, err
		}
		if !slices.Contains(categories, category) {
			rows.Close()
			return TaskCategories{}, ErrCategoryInUse
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return TaskCategories{}, err
	}
	rows.Close()
	document, err := json.Marshal(categories)
	if err != nil {
		return TaskCategories{}, err
	}
	if _, err := tx.ExecContext(ctx, s.rebind("UPDATE projects SET task_categories_json = ?, task_categories_version = task_categories_version + 1 WHERE id = ?"), string(document), project); err != nil {
		return TaskCategories{}, mapSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return TaskCategories{}, mapSQLError(err)
	}
	return TaskCategories{Categories: append([]string{}, categories...), Version: version + 1}, nil
}

func (s *SQL) validateTaskCategoryTx(ctx context.Context, tx *sql.Tx, snapshot, category string) error {
	if category == "" {
		return nil
	}
	var document string
	if err := tx.QueryRowContext(ctx, s.rebind("SELECT task_categories_json FROM projects WHERE id = (SELECT project_id FROM snapshots WHERE snapshot_id = ?)"), snapshot).Scan(&document); err != nil {
		return invalidTaskCategory()
	}
	var categories []string
	if err := json.Unmarshal([]byte(document), &categories); err != nil {
		return err
	}
	if !slices.Contains(categories, category) {
		return invalidTaskCategory()
	}
	return nil
}
