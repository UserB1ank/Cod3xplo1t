// Package testpostgres provisions isolated schemas for opt-in integration tests.
package testpostgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// DSNFile never includes credentials in failure output and removes the schema
// after the caller's runtimes have closed. No shared absolute paths are used.
func DSNFile(t testing.TB) string {
	t.Helper()
	file := os.Getenv("CODEXPLOIT_TEST_POSTGRES_DSN_FILE")
	if file == "" {
		t.Skip("real PostgreSQL acceptance requires CODEXPLOIT_TEST_POSTGRES_DSN_FILE")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("cannot read PostgreSQL test credential file")
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || u.Scheme != "postgres" {
		t.Fatal("test DSN must be a PostgreSQL URL")
	}
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal("cannot open PostgreSQL test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	schema := "catalog_test_" + hex.EncodeToString(id[:])
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		db.Close()
		t.Fatal("cannot create isolated PostgreSQL test schema")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("cannot clean isolated PostgreSQL schema")
		}
		db.Close()
	})
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	result := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(result, []byte(u.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return result
}
