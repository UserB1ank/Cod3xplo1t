// Package migrations ships the Codexploit SQL schema as an embeddable file
// system so that binaries do not depend on the source tree layout at runtime.
package migrations

import (
	"embed"
	"io/fs"
)

// FS holds every migration, named <version>_<description>.sql and applied in
// lexicographic order.
//
//go:embed *.sql
var FS embed.FS

//go:embed postgres/*.sql
var postgresFS embed.FS

// Postgres contains only the wired catalog profile, independently versioned
// from the complete SQLite schema.
var Postgres, _ = fs.Sub(postgresFS, "postgres")
