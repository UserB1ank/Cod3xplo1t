package storage

import "github.com/open-mcp-ai/Codexploit/internal/agent"

// AgentStore is the persistence contract of the agent runtime (P5). It is an
// alias, not a copy, for the same reason AuditStore is: the runtime declares what
// it needs next to its model (`internal/agent`), and the store implements exactly
// that. Duplicating the interface would let the two drift.
//
// The alias also matters at the API boundary. A run, its event log and its
// hypotheses answer with the agent sentinels (`agent.ErrNotFound`,
// `agent.ErrConflict`), which the API maps to distinct answers, while the graph,
// ASG and audit entities keep returning `storage.ErrNotFound`. Aliasing the
// runtime's own interface is what keeps the SQL backend honest about which
// vocabulary a given method belongs to.
type AgentStore = agent.Store
