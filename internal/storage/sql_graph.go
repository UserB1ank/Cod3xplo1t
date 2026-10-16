package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// ReplaceGraph implements GraphStore. The whole graph of a snapshot is replaced
// inside one transaction: a rebuild is idempotent and a concurrent reader sees
// either the old graph or the new one, never a mixture.
func (s *SQL) ReplaceGraph(ctx context.Context, snapshotID string, g *scg.Graph) error {
	if err := validateGraph(snapshotID, g); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	if err := s.snapshotWritableTx(ctx, tx, snapshotID); err != nil {
		return err
	}

	for _, table := range []string{"scg_modules", "scg_files", "scg_symbols", "scg_call_sites", "scg_edges", "graph_builds"} {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM `+table+` WHERE snapshot_id = ?`), snapshotID); err != nil {
			return mapSQLError(err)
		}
	}

	moduleStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO scg_modules (module_id, snapshot_id, path, name, language, manifest_file, files, symbols, lines)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer moduleStmt.Close()
	for _, mod := range g.Modules {
		if _, err := moduleStmt.ExecContext(ctx, mod.ID, snapshotID, mod.Path, mod.Name, mod.Language, mod.ManifestFile, mod.Files, mod.Symbols, mod.Lines); err != nil {
			return mapSQLError(err)
		}
	}

	fileStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO scg_files (file_id, snapshot_id, module_id, path, language, bytes, lines, parse_status, parse_error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer fileStmt.Close()
	for _, f := range g.Files {
		if _, err := fileStmt.ExecContext(ctx, f.ID, snapshotID, f.ModuleID, f.Path, f.Language, f.Bytes, f.Lines, f.ParseStatus, f.ParseError); err != nil {
			return mapSQLError(err)
		}
	}

	symbolStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO scg_symbols (symbol_id, snapshot_id, module_id, file_id, file, language, kind, name, qualified_name,
    signature, receiver, result_type, exported, start_line, end_line, start_col, end_col)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer symbolStmt.Close()
	for _, sym := range g.Symbols {
		if _, err := symbolStmt.ExecContext(ctx, sym.ID, snapshotID, sym.ModuleID, sym.FileID, sym.File, sym.Language,
			string(sym.Kind), sym.Name, sym.QualifiedName, sym.Signature, sym.Receiver, sym.ResultType,
			boolToInt(sym.Exported), sym.StartLine, sym.EndLine, sym.StartCol, sym.EndCol); err != nil {
			return mapSQLError(err)
		}
	}

	callStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO scg_call_sites (call_site_id, snapshot_id, caller_symbol_id, file_id, file, line, col, callee_text,
    callee_symbol_id, callee_qualified, resolution, confidence, detail, analyzer, analyzer_version,
    args_json, receiver_from)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer callStmt.Close()
	for _, cs := range g.CallSites {
		args, err := json.Marshal(cs.Args)
		if err != nil {
			return err
		}
		if _, err := callStmt.ExecContext(ctx, cs.ID, snapshotID, cs.CallerSymbolID, cs.FileID, cs.File, cs.Line, cs.Col,
			cs.CalleeText, cs.CalleeSymbolID, cs.CalleeQualified, string(cs.Resolution), string(cs.Confidence),
			cs.Detail, cs.Analyzer, cs.AnalyzerVersion, string(args), cs.ReceiverFrom); err != nil {
			return mapSQLError(err)
		}
	}

	edgeStmt, err := tx.PrepareContext(ctx, s.rebind(`
INSERT INTO scg_edges (edge_id, snapshot_id, from_id, to_id, kind, resolution, confidence, file, line, col,
    analyzer, analyzer_version, call_site_id, detail_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return mapSQLError(err)
	}
	defer edgeStmt.Close()
	for _, e := range g.Edges {
		detail := "{}"
		if len(e.Detail) > 0 {
			data, merr := json.Marshal(e.Detail)
			if merr != nil {
				return merr
			}
			detail = string(data)
		}
		if _, err := edgeStmt.ExecContext(ctx, e.ID, snapshotID, e.From, e.To, string(e.Kind), string(e.Resolution),
			string(e.Confidence), e.SourceLocation.File, e.SourceLocation.Line, e.SourceLocation.Col,
			e.Analyzer, e.AnalyzerVersion, e.CallSiteID, detail); err != nil {
			return mapSQLError(err)
		}
	}

	summary := g.Summarize()
	frontends, err := json.Marshal(summary.Frontends)
	if err != nil {
		return err
	}
	coverage, err := json.Marshal(summary.Coverage)
	if err != nil {
		return err
	}
	limitations, err := json.Marshal(summary.Limitations)
	if err != nil {
		return err
	}
	resolution, err := json.Marshal(summary.Resolution)
	if err != nil {
		return err
	}
	edgesByKind, err := json.Marshal(summary.EdgesByKind)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`
INSERT INTO graph_builds (snapshot_id, graph_version, engine, engine_version, frontends_json, coverage_json,
    limitations_json, resolution_json, edges_by_kind_json, modules, files, symbols, call_sites, edges, built_at, build_duration_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		snapshotID, summary.GraphVersion, summary.Engine.Name, summary.Engine.Version,
		string(frontends), string(coverage), string(limitations), string(resolution), string(edgesByKind),
		summary.Modules, summary.Files, summary.Symbols, summary.CallSites, summary.Edges,
		summary.BuiltAt, summary.BuildDurationMS); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// DeleteGraph implements GraphStore.
func (s *SQL) DeleteGraph(ctx context.Context, snapshotID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"scg_modules", "scg_files", "scg_symbols", "scg_call_sites", "scg_edges", "graph_builds"} {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM `+table+` WHERE snapshot_id = ?`), snapshotID); err != nil {
			return mapSQLError(err)
		}
	}
	return tx.Commit()
}

// GraphSummary implements GraphStore.
func (s *SQL) GraphSummary(ctx context.Context, snapshotID string) (*scg.Summary, error) {
	row := s.db.QueryRowContext(ctx, s.rebind(`
SELECT graph_version, engine, engine_version, frontends_json, coverage_json, limitations_json, resolution_json,
       edges_by_kind_json, modules, files, symbols, call_sites, edges, built_at, build_duration_ms
FROM graph_builds WHERE snapshot_id = ?`), snapshotID)
	var (
		out                              scg.Summary
		frontends, coverage, limitations string
		resolution, edgesByKind          string
	)
	if err := row.Scan(&out.GraphVersion, &out.Engine.Name, &out.Engine.Version, &frontends, &coverage,
		&limitations, &resolution, &edgesByKind, &out.Modules, &out.Files, &out.Symbols, &out.CallSites,
		&out.Edges, &out.BuiltAt, &out.BuildDurationMS); err != nil {
		return nil, mapSQLError(err)
	}
	out.SnapshotID = snapshotID
	if err := json.Unmarshal([]byte(frontends), &out.Frontends); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(coverage), &out.Coverage); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(limitations), &out.Limitations); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(resolution), &out.Resolution); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(edgesByKind), &out.EdgesByKind); err != nil {
		return nil, err
	}
	if out.Limitations == nil {
		out.Limitations = []string{}
	}
	if out.EdgesByKind == nil {
		out.EdgesByKind = map[string]int{}
	}
	return &out, nil
}

// requireGraph fails with ErrNotFound when a snapshot has no graph, so that a
// query against an unindexed snapshot is never answered with an empty list.
// "No callers" and "no graph" must not look the same to a caller.
func (s *SQL) requireGraph(ctx context.Context, snapshotID string) error {
	var count int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM graph_builds WHERE snapshot_id = ?`), snapshotID).Scan(&count); err != nil {
		return mapSQLError(err)
	}
	if count == 0 {
		return fmt.Errorf("%w: graph for snapshot %s", ErrNotFound, snapshotID)
	}
	return nil
}

// ListModules implements GraphStore.
func (s *SQL) ListModules(ctx context.Context, snapshotID string) ([]scg.Module, error) {
	if err := s.requireGraph(ctx, snapshotID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`
SELECT module_id, snapshot_id, path, name, language, manifest_file, files, symbols, lines
FROM scg_modules WHERE snapshot_id = ? ORDER BY path`), snapshotID)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []scg.Module
	for rows.Next() {
		var mod scg.Module
		if err := rows.Scan(&mod.ID, &mod.SnapshotID, &mod.Path, &mod.Name, &mod.Language, &mod.ManifestFile,
			&mod.Files, &mod.Symbols, &mod.Lines); err != nil {
			return nil, err
		}
		out = append(out, mod)
	}
	return out, rows.Err()
}

// GetModule implements GraphStore.
func (s *SQL) GetModule(ctx context.Context, snapshotID, moduleID string) (scg.Module, error) {
	if err := s.requireGraph(ctx, snapshotID); err != nil {
		return scg.Module{}, err
	}
	row := s.db.QueryRowContext(ctx, s.rebind(`
SELECT module_id, snapshot_id, path, name, language, manifest_file, files, symbols, lines
FROM scg_modules WHERE snapshot_id = ? AND (module_id = ? OR path = ?)`), snapshotID, moduleID, moduleID)
	var mod scg.Module
	if err := row.Scan(&mod.ID, &mod.SnapshotID, &mod.Path, &mod.Name, &mod.Language, &mod.ManifestFile,
		&mod.Files, &mod.Symbols, &mod.Lines); err != nil {
		return scg.Module{}, mapSQLError(err)
	}
	return mod, nil
}

// ListFiles implements GraphStore.
func (s *SQL) ListFiles(ctx context.Context, snapshotID, moduleID string) ([]scg.File, error) {
	if err := s.requireGraph(ctx, snapshotID); err != nil {
		return nil, err
	}
	query := `
SELECT file_id, snapshot_id, module_id, path, language, bytes, lines, parse_status, parse_error
FROM scg_files WHERE snapshot_id = ?`
	args := []any{snapshotID}
	if moduleID != "" {
		query += ` AND module_id = ?`
		args = append(args, moduleID)
	}
	query += ` ORDER BY path`
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []scg.File
	for rows.Next() {
		var f scg.File
		if err := rows.Scan(&f.ID, &f.SnapshotID, &f.ModuleID, &f.Path, &f.Language, &f.Bytes, &f.Lines,
			&f.ParseStatus, &f.ParseError); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFile implements GraphStore.
func (s *SQL) GetFile(ctx context.Context, snapshotID, fileID string) (scg.File, error) {
	if err := s.requireGraph(ctx, snapshotID); err != nil {
		return scg.File{}, err
	}
	row := s.db.QueryRowContext(ctx, s.rebind(`
SELECT file_id, snapshot_id, module_id, path, language, bytes, lines, parse_status, parse_error
FROM scg_files WHERE snapshot_id = ? AND (file_id = ? OR path = ?)`), snapshotID, fileID, fileID)
	var f scg.File
	if err := row.Scan(&f.ID, &f.SnapshotID, &f.ModuleID, &f.Path, &f.Language, &f.Bytes, &f.Lines,
		&f.ParseStatus, &f.ParseError); err != nil {
		return scg.File{}, mapSQLError(err)
	}
	return f, nil
}

const symbolColumns = `symbol_id, snapshot_id, module_id, file_id, file, language, kind, name, qualified_name,
	signature, receiver, result_type, exported, start_line, end_line, start_col, end_col`

func scanSymbol(scan func(...any) error) (scg.Symbol, error) {
	var (
		sym      scg.Symbol
		kind     string
		exported int
	)
	if err := scan(&sym.ID, &sym.SnapshotID, &sym.ModuleID, &sym.FileID, &sym.File, &sym.Language, &kind, &sym.Name,
		&sym.QualifiedName, &sym.Signature, &sym.Receiver, &sym.ResultType, &exported,
		&sym.StartLine, &sym.EndLine, &sym.StartCol, &sym.EndCol); err != nil {
		return scg.Symbol{}, err
	}
	sym.Kind = scg.SymbolKind(kind)
	sym.Exported = exported != 0
	return sym, nil
}

// symbolFilter builds the shared WHERE clause of symbol reads.
func symbolFilter(q SymbolQuery) (string, []any) {
	where := []string{"snapshot_id = ?"}
	args := []any{q.SnapshotID}
	if q.ModuleID != "" {
		where = append(where, "module_id = ?")
		args = append(args, q.ModuleID)
	}
	if q.FileID != "" {
		where = append(where, "file_id = ?")
		args = append(args, q.FileID)
	}
	if len(q.Kinds) > 0 {
		placeholders := make([]string, 0, len(q.Kinds))
		for _, k := range q.Kinds {
			placeholders = append(placeholders, "?")
			args = append(args, string(k))
		}
		where = append(where, "kind IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.NameContains != "" {
		where = append(where, "name LIKE ?")
		args = append(args, "%"+q.NameContains+"%")
	}
	if q.QualifiedName != "" {
		where = append(where, "qualified_name = ?")
		args = append(args, q.QualifiedName)
	}
	return strings.Join(where, " AND "), args
}

// ListSymbols implements GraphStore.
func (s *SQL) ListSymbols(ctx context.Context, q SymbolQuery) ([]scg.Symbol, int, error) {
	if err := s.requireGraph(ctx, q.SnapshotID); err != nil {
		return nil, 0, err
	}
	where, args := symbolFilter(q)
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM scg_symbols WHERE `+where), args...).Scan(&total); err != nil {
		return nil, 0, mapSQLError(err)
	}
	sqlQuery := `SELECT ` + symbolColumns + ` FROM scg_symbols WHERE ` + where + ` ORDER BY qualified_name, symbol_id LIMIT ? OFFSET ?`
	args = append(args, normaliseLimit(q.Limit, 100, 1000), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(sqlQuery), args...)
	if err != nil {
		return nil, 0, mapSQLError(err)
	}
	defer rows.Close()
	var out []scg.Symbol
	for rows.Next() {
		sym, err := scanSymbol(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sym)
	}
	return out, total, rows.Err()
}

// GetSymbol implements GraphStore.
func (s *SQL) GetSymbol(ctx context.Context, snapshotID, symbolID string) (scg.Symbol, error) {
	if err := s.requireGraph(ctx, snapshotID); err != nil {
		return scg.Symbol{}, err
	}
	row := s.db.QueryRowContext(ctx, s.rebind(`SELECT `+symbolColumns+` FROM scg_symbols
WHERE snapshot_id = ? AND (symbol_id = ? OR qualified_name = ?)`), snapshotID, symbolID, symbolID)
	sym, err := scanSymbol(row.Scan)
	if err != nil {
		return scg.Symbol{}, mapSQLError(err)
	}
	return sym, nil
}

const callSiteColumns = `call_site_id, snapshot_id, caller_symbol_id, file_id, file, line, col, callee_text,
	callee_symbol_id, callee_qualified, resolution, confidence, detail, analyzer, analyzer_version,
	args_json, receiver_from`

func scanCallSite(scan func(...any) error) (scg.CallSite, error) {
	var (
		cs         scg.CallSite
		resolution string
		confidence string
		args       string
	)
	if err := scan(&cs.ID, &cs.SnapshotID, &cs.CallerSymbolID, &cs.FileID, &cs.File, &cs.Line, &cs.Col,
		&cs.CalleeText, &cs.CalleeSymbolID, &cs.CalleeQualified, &resolution, &confidence, &cs.Detail,
		&cs.Analyzer, &cs.AnalyzerVersion, &args, &cs.ReceiverFrom); err != nil {
		return scg.CallSite{}, err
	}
	cs.Resolution = scg.Resolution(resolution)
	cs.Confidence = scg.Confidence(confidence)
	if args != "" && args != "[]" {
		if err := json.Unmarshal([]byte(args), &cs.Args); err != nil {
			return scg.CallSite{}, fmt.Errorf("storage: decode call-site arguments: %w", err)
		}
	}
	return cs, nil
}

// ListCallSites implements GraphStore.
func (s *SQL) ListCallSites(ctx context.Context, q CallSiteQuery) ([]scg.CallSite, int, error) {
	if err := s.requireGraph(ctx, q.SnapshotID); err != nil {
		return nil, 0, err
	}
	where := []string{"snapshot_id = ?"}
	args := []any{q.SnapshotID}
	if q.CallSiteID != "" {
		where = append(where, "call_site_id = ?")
		args = append(args, q.CallSiteID)
	}
	if q.CallerSymbolID != "" {
		where = append(where, "caller_symbol_id = ?")
		args = append(args, q.CallerSymbolID)
	}
	if len(q.CallerIn) > 0 {
		placeholders := make([]string, 0, len(q.CallerIn))
		for _, id := range q.CallerIn {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		where = append(where, "caller_symbol_id IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.FileID != "" {
		where = append(where, "file_id = ?")
		args = append(args, q.FileID)
	}
	if q.CalleeSymbolID != "" {
		where = append(where, "callee_symbol_id = ?")
		args = append(args, q.CalleeSymbolID)
	}
	if len(q.Resolution) > 0 {
		placeholders := make([]string, 0, len(q.Resolution))
		for _, r := range q.Resolution {
			placeholders = append(placeholders, "?")
			args = append(args, string(r))
		}
		where = append(where, "resolution IN ("+strings.Join(placeholders, ", ")+")")
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM scg_call_sites WHERE `+clause), args...).Scan(&total); err != nil {
		return nil, 0, mapSQLError(err)
	}
	query := `SELECT ` + callSiteColumns + ` FROM scg_call_sites WHERE ` + clause + ` ORDER BY file, line, call_site_id LIMIT ? OFFSET ?`
	args = append(args, normaliseLimit(q.Limit, 100, 1000), max(q.Offset, 0))
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, 0, mapSQLError(err)
	}
	defer rows.Close()
	var out []scg.CallSite
	for rows.Next() {
		cs, err := scanCallSite(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, cs)
	}
	return out, total, rows.Err()
}

// EdgesFrom implements GraphStore.
func (s *SQL) EdgesFrom(ctx context.Context, snapshotID string, from []string, kinds []scg.EdgeKind) ([]scg.Edge, error) {
	return s.edges(ctx, snapshotID, "from_id", from, kinds)
}

// EdgesTo implements GraphStore.
func (s *SQL) EdgesTo(ctx context.Context, snapshotID string, to []string, kinds []scg.EdgeKind) ([]scg.Edge, error) {
	return s.edges(ctx, snapshotID, "to_id", to, kinds)
}

func (s *SQL) edges(ctx context.Context, snapshotID, column string, ids []string, kinds []scg.EdgeKind) ([]scg.Edge, error) {
	if err := s.requireGraph(ctx, snapshotID); err != nil {
		return nil, err
	}
	where := []string{"snapshot_id = ?"}
	args := []any{snapshotID}
	if len(ids) > 0 {
		placeholders := make([]string, 0, len(ids))
		for _, id := range ids {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		where = append(where, column+" IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(kinds) > 0 {
		placeholders := make([]string, 0, len(kinds))
		for _, k := range kinds {
			placeholders = append(placeholders, "?")
			args = append(args, string(k))
		}
		where = append(where, "kind IN ("+strings.Join(placeholders, ", ")+")")
	}
	query := `SELECT edge_id, snapshot_id, from_id, to_id, kind, resolution, confidence, file, line, col,
		analyzer, analyzer_version, call_site_id, detail_json FROM scg_edges WHERE ` +
		strings.Join(where, " AND ") + ` ORDER BY edge_id`
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []scg.Edge
	for rows.Next() {
		var (
			e          scg.Edge
			kind       string
			resolution string
			confidence string
			detail     string
		)
		if err := rows.Scan(&e.ID, &e.SnapshotID, &e.From, &e.To, &kind, &resolution, &confidence,
			&e.SourceLocation.File, &e.SourceLocation.Line, &e.SourceLocation.Col, &e.Analyzer,
			&e.AnalyzerVersion, &e.CallSiteID, &detail); err != nil {
			return nil, err
		}
		e.Kind = scg.EdgeKind(kind)
		e.Resolution = scg.Resolution(resolution)
		e.Confidence = scg.Confidence(confidence)
		if detail != "" && detail != "{}" {
			if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
				return nil, fmt.Errorf("storage: decode edge detail for %s: %w", e.ID, err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// max returns the larger of two ints (declared here to keep the storage package
// free of helper imports).
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
