// Package contracts contains the design-time v1 schemas and synthetic examples.
// It does not imply that a runtime adapter implements any of these contracts.
package contracts

import "embed"

// Files is the offline source of truth shared by contract tests and consumers.
// No schema reference needs network retrieval.
//
//go:embed *.schema.json examples.json examples/*.json
var Files embed.FS
