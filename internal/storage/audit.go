package storage

import "github.com/open-mcp-ai/Codexploit/internal/path"

// AuditStore is the persistence contract of the path engine. It is an alias, not
// a copy: the engine declares what it needs next to its model, and the store
// implements exactly that. Duplicating the interface would let the two drift.
type AuditStore = path.Store
