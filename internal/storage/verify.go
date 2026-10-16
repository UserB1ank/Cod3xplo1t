package storage

import "github.com/open-mcp-ai/Codexploit/internal/verify"

// VerificationStore is the persistence contract of the verification layer (P6).
// It is an alias, not a copy, for the same reason AuditStore and AgentStore are:
// the layer declares what it needs next to its model (`internal/verify`), and the
// store implements exactly that. Duplicating the interface would let the two drift.
//
// The alias also fixes the error vocabulary. A verification run, an evidence
// object and a finding answer with the verification sentinels (`verify.ErrNotFound`,
// `verify.ErrConflict`, `verify.ErrInvalidArgument`), which the API maps to distinct
// answers, while the graph, ASG and audit entities keep returning
// `storage.ErrNotFound`.
type VerificationStore = verify.Store
