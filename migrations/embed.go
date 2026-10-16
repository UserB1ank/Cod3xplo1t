// Package migrations ships the Codexploit SQL schema as an embeddable file
// system so that binaries do not depend on the source tree layout at runtime.
package migrations

import "embed"

// FS holds every migration, named <version>_<description>.sql and applied in
// lexicographic order.
//
//go:embed *.sql
var FS embed.FS
