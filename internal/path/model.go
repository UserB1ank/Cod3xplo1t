// Package path turns an attack surface into auditable work items.
//
// The package owns the third object of the design: the AuditPath. The SCG is the
// fact layer, the ASG is the security-semantics layer, and an AuditPath is the
// scheduling unit a path auditor will be handed — so everything here is written
// to be reproducible: ids are content-derived, scores carry their version and
// their feature snapshot, and a rebuild of the same snapshot produces the same
// paths.
//
// The engine consumes two read-only views (ASGReader, SCGReader) that are
// declared in this package in terms of this package's own facts. That keeps the
// dependency direction acyclic — storage implements Store, the query layer
// implements the readers — and lets the whole engine be tested against in-memory
// fixtures without a graph service.
package path

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ScoreVersion identifies the feature mapping and weights behind a score. Any
// change to how a feature is derived or weighted must bump it: a priority that
// cannot be replayed cannot be reviewed.
const ScoreVersion = 1

// SchemaVersion identifies the serialised shape of a path document.
const SchemaVersion = 1

// Status is the audit lifecycle position of a path (implementation guide §11,
// design §7). The lifecycle states (PAUSED, FAILED, CANCELLED, INTERRUPTED) are
// deliberately separate from the audit conclusion: a paused path has no verdict,
// and a cancelled path is not a refuted one.
type Status string

const (
	StatusDiscovered       Status = "DISCOVERED"
	StatusQueued           Status = "QUEUED"
	StatusAnalyzing        Status = "ANALYZING"
	StatusLocalExploring   Status = "LOCAL_EXPLORING"
	StatusHypothesisFormed Status = "HYPOTHESIS_FORMED"
	StatusVerifying        Status = "VERIFYING"
	StatusConcluded        Status = "CONCLUDED"
	StatusBlocked          Status = "BLOCKED"
	StatusPaused           Status = "PAUSED"
	StatusFailed           Status = "FAILED"
	StatusCancelled        Status = "CANCELLED"
	StatusInterrupted      Status = "INTERRUPTED"
)

// AllStatuses returns every status in lifecycle order.
func AllStatuses() []Status {
	return []Status{
		StatusDiscovered, StatusQueued, StatusAnalyzing, StatusLocalExploring,
		StatusHypothesisFormed, StatusVerifying, StatusConcluded, StatusBlocked,
		StatusPaused, StatusFailed, StatusCancelled, StatusInterrupted,
	}
}

// ValidStatus reports whether a status is part of the vocabulary.
func ValidStatus(s Status) bool {
	for _, known := range AllStatuses() {
		if s == known {
			return true
		}
	}
	return false
}

// Claimable reports whether a worker may lease a path in this status.
func (s Status) Claimable() bool { return s == StatusQueued }

// Active reports whether the status means "a worker holds this path now".
//
// HYPOTHESIS_FORMED is deliberately not active: the analysis run is over and its
// claim is recorded, so no worker holds the path any more. Counting it as active
// would keep its lease alive, spend the audit's active-lease ceiling on finished
// work, and leave an expired lease in a state reclaim cannot legally leave.
func (s Status) Active() bool {
	return s == StatusAnalyzing || s == StatusLocalExploring || s == StatusVerifying
}

// Terminal reports whether no further transition is expected.
func (s Status) Terminal() bool { return s == StatusConcluded || s == StatusCancelled }

// Waiting reports whether the path is out of the queue but not finished.
func (s Status) Waiting() bool {
	return s == StatusPaused || s == StatusBlocked || s == StatusInterrupted || s == StatusFailed
}

// PathStatus is the evidence class of a candidate path (implementation guide
// §8.1.5): it says how much static support the path has, and never that the
// vulnerability exists.
type PathStatus string

const (
	// PathCandidate is call-graph reachability only: the attack surface links an
	// entry point to a sensitive operation, but the intermediate chain could not
	// be resolved into observed call edges.
	PathCandidate PathStatus = "candidate"
	// PathStaticallySupported means every hop of the chain is an observed call
	// edge and the endpoint is an observed sensitive operation. It still does not
	// mean that data flows from an input to the sink.
	PathStaticallySupported PathStatus = "statically_supported"
	// PathUnresolved means a needed fact is missing: an unresolved handler, a
	// truncated reachability walk, or a chain that exceeded its budget.
	PathUnresolved PathStatus = "unresolved"
)

// AllPathStatuses returns the path status vocabulary.
func AllPathStatuses() []PathStatus {
	return []PathStatus{PathCandidate, PathStaticallySupported, PathUnresolved}
}

// ValidPathStatus reports whether a path status is known.
func ValidPathStatus(s PathStatus) bool {
	for _, known := range AllPathStatuses() {
		if s == known {
			return true
		}
	}
	return false
}

// Budget bounds what one audit of a path may consume. The defaults are the
// documented starting values (design §3.3, §7), not tuned numbers.
type Budget struct {
	MaxDepth     int `json:"max_depth"`
	MaxBranches  int `json:"max_branches"`
	MaxToolCalls int `json:"max_tool_calls"`
}

// DefaultBudget returns the MVP budget: 2 hops, 4 active branches, 30 tool calls.
func DefaultBudget() Budget {
	return Budget{MaxDepth: 2, MaxBranches: 4, MaxToolCalls: 30}
}

// Normalize fills unset budget fields with the defaults.
func (b Budget) Normalize() Budget {
	d := DefaultBudget()
	if b.MaxDepth <= 0 {
		b.MaxDepth = d.MaxDepth
	}
	if b.MaxBranches <= 0 {
		b.MaxBranches = d.MaxBranches
	}
	if b.MaxToolCalls <= 0 {
		b.MaxToolCalls = d.MaxToolCalls
	}
	return b
}

// Limits bounds generation and scheduling for a whole audit.
type Limits struct {
	MaxEntries       int `json:"max_entries"`
	MaxSinksPerEntry int `json:"max_sinks_per_entry"`
	MaxChainsPerPair int `json:"max_chains_per_pair"`
	MaxPaths         int `json:"max_paths"`
	MaxActiveLeases  int `json:"max_active_leases"`
	MaxAttempts      int `json:"max_attempts"`
	ChainQueryBudget int `json:"chain_query_budget"`
	LeaseTTLSeconds  int `json:"lease_ttl_seconds"`
	// ExplorationFraction is the share of picks reserved for low-coverage paths so
	// the score model cannot close off whole regions (implementation guide §8.3).
	ExplorationFraction float64 `json:"exploration_fraction"`
}

// DefaultLimits returns the MVP generation and scheduling budgets.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:          200,
		MaxSinksPerEntry:    20,
		MaxChainsPerPair:    2,
		MaxPaths:            2000,
		MaxActiveLeases:     4,
		MaxAttempts:         3,
		ChainQueryBudget:    2000,
		LeaseTTLSeconds:     300,
		ExplorationFraction: 0.20,
	}
}

// Normalize fills unset limits with the defaults and clamps the exploration
// fraction to the documented 15%–25% band.
func (l Limits) Normalize() Limits {
	d := DefaultLimits()
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxSinksPerEntry <= 0 {
		l.MaxSinksPerEntry = d.MaxSinksPerEntry
	}
	if l.MaxChainsPerPair <= 0 {
		l.MaxChainsPerPair = d.MaxChainsPerPair
	}
	if l.MaxPaths <= 0 {
		l.MaxPaths = d.MaxPaths
	}
	if l.MaxActiveLeases <= 0 {
		l.MaxActiveLeases = d.MaxActiveLeases
	}
	if l.MaxAttempts <= 0 {
		l.MaxAttempts = d.MaxAttempts
	}
	if l.ChainQueryBudget <= 0 {
		l.ChainQueryBudget = d.ChainQueryBudget
	}
	if l.LeaseTTLSeconds <= 0 {
		l.LeaseTTLSeconds = d.LeaseTTLSeconds
	}
	switch {
	case l.ExplorationFraction <= 0:
		l.ExplorationFraction = d.ExplorationFraction
	case l.ExplorationFraction < 0.15:
		l.ExplorationFraction = 0.15
	case l.ExplorationFraction > 0.25:
		l.ExplorationFraction = 0.25
	}
	return l
}

// Step is one hop of the canonical path: an ASG edge, or a call edge of the
// resolved symbol chain. SCG call hops are what make a path reviewable; ASG hops
// are what make it a security statement.
type Step struct {
	// Layer is "asg" or "scg".
	Layer string `json:"layer"`
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	// Subject and File/Line describe the target for display, so a caller does not
	// have to resolve ids just to render a path.
	Subject    string `json:"subject,omitempty"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Resolution string `json:"resolution,omitempty"`
}

// Cluster records the approximate-dedup grouping of a path (implementation guide
// §8.2). Members of a cluster stay separate paths: they differ in branches that
// may matter, and collapsing them would hide that.
type Cluster struct {
	ID             string   `json:"cluster_id"`
	Representative bool     `json:"representative"`
	Size           int      `json:"size"`
	Differences    []string `json:"differences"`
}

// Features is the normalised feature snapshot behind a score. Every value is in
// [0,1]; the names follow the design's formulas (E I S T B, F D V Q, N G H, K)
// so a reader can check the arithmetic against the documents.
type Features struct {
	Exposure             float64 `json:"exposure"`              // E
	Impact               float64 `json:"impact"`                // I
	Controllability      float64 `json:"controllability"`       // S
	TrustBoundary        float64 `json:"trust_boundary"`        // T
	BusinessSensitivity  float64 `json:"business_sensitivity"`  // B
	ReachabilityEvidence float64 `json:"reachability_evidence"` // F
	DataflowEvidence     float64 `json:"dataflow_evidence"`     // D
	ControlSuspicion     float64 `json:"control_suspicion"`     // V
	AnalysisQuality      float64 `json:"analysis_quality"`      // Q
	Novelty              float64 `json:"novelty"`               // N
	InformationGain      float64 `json:"information_gain"`      // G
	ReuseValue           float64 `json:"reuse_value"`           // H
	EstimatedCost        float64 `json:"estimated_cost"`        // K
	DedupDiscount        float64 `json:"dedup_discount"`        // D_dup
	// Reasons explains each feature that is not an obvious mapping, so a ranking
	// can be challenged without re-running the analysis.
	Reasons map[string]string `json:"reasons,omitempty"`
}

// Score is the ranking of one path. Risk (R), support (C) and utility (U) are the
// design's components; Priority (P) is the scheduling number. None of them is a
// probability of a vulnerability.
type Score struct {
	Risk         float64            `json:"risk"`
	Support      float64            `json:"support"`
	Utility      float64            `json:"utility"`
	Priority     float64            `json:"priority"`
	ScoreVersion int                `json:"score_version"`
	Weights      map[string]float64 `json:"weights"`
	ComputedAt   string             `json:"computed_at"`
}

// Path is one audit task: an entry point, a target sensitive operation, the
// chain between them, and everything the orchestrator needs to schedule it.
type Path struct {
	ID            string     `json:"path_id"`
	AuditID       string     `json:"audit_id"`
	SnapshotID    string     `json:"snapshot_id"`
	SCGVersion    string     `json:"scg_version"`
	ASGVersion    string     `json:"asg_version"`
	EntryNodeID   string     `json:"entry_node_id"`
	EntryKind     string     `json:"entry_kind"`
	EntrySubject  string     `json:"entry_subject"`
	TargetNodeID  string     `json:"target_node_id"`
	TargetSubject string     `json:"target_subject"`
	TargetKind    string     `json:"target_kind"`
	PathKind      string     `json:"path_kind"`
	PathStatus    PathStatus `json:"path_status"`
	Status        Status     `json:"status"`

	// Steps is the canonical path: ASG hops plus the resolved call chain.
	Steps []Step `json:"steps"`
	// Signature is the exact dedup key: snapshot + entry + target + canonical
	// sequence (implementation guide §8.2).
	Signature string `json:"signature"`
	// Cluster carries the approximate grouping.
	Cluster Cluster `json:"cluster"`

	// Evidence links. SCGRefs and ASGRefs are what make the path auditable.
	SCGRefs []string `json:"scg_refs"`
	ASGRefs []string `json:"asg_refs"`
	// Objectives are the security goals this path is a candidate for, derived from
	// the sink kind and the controls observed on it.
	Objectives    []string `json:"objectives"`
	Boundaries    []string `json:"boundaries"`
	Controls      []string `json:"controls"`
	Inputs        []string `json:"inputs"`
	Assets        []string `json:"assets"`
	OpenQuestions []string `json:"open_questions"`
	Limitations   []string `json:"limitations"`

	Depth       int      `json:"depth"`
	BranchCount int      `json:"branch_count"`
	Budget      Budget   `json:"budget"`
	Features    Features `json:"features"`
	Score       Score    `json:"score"`

	// ScoreSeq counts the score snapshots stored for this path, so a recomputation
	// appends rather than overwrites.
	ScoreSeq int64 `json:"score_seq"`

	LeaseOwner  string `json:"lease_owner,omitempty"`
	LeaseUntil  string `json:"lease_until,omitempty"`
	HeartbeatAt string `json:"heartbeat_at,omitempty"`
	Attempts    int    `json:"attempts"`
	MaxAttempts int    `json:"max_attempts"`
	LastError   string `json:"last_error,omitempty"`
	// NextAttemptAt is when a path already back in the queue may run again. It is
	// part of the document, not a timer in a process: a scheduler that restarts
	// still knows which paths are in backoff, and a path with an empty value is due
	// immediately. RFC3339, so comparing two of them as strings compares times.
	NextAttemptAt string `json:"next_attempt_at,omitempty"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// Version is the optimistic-concurrency counter for status and score updates.
	Version int64 `json:"version"`
}

// Audit is one run of path generation over one snapshot.
type Audit struct {
	// Named audits are project tasks; their graph remains owned by the snapshot.
	Name         string   `json:"name,omitempty"`
	Objective    string   `json:"objective,omitempty"`
	Scope        []string `json:"scope,omitempty"`
	Paused       bool     `json:"paused"`
	ID           string   `json:"audit_id"`
	SnapshotID   string   `json:"snapshot_id"`
	SCGVersion   string   `json:"scg_version"`
	ASGVersion   string   `json:"asg_version"`
	Status       string   `json:"status"`
	Budget       Budget   `json:"budget"`
	Limits       Limits   `json:"limits"`
	ScoreVersion int      `json:"score_version"`
	// ConfigHash covers the inputs that change the produced set, so the same
	// request maps to the same audit.
	ConfigHash         string         `json:"config_hash"`
	PathCount          int            `json:"path_count"`
	CountsByStatus     map[string]int `json:"counts_by_status"`
	CountsByPathStatus map[string]int `json:"counts_by_path_status"`
	Coverage           Coverage       `json:"coverage"`
	Limitations        []string       `json:"limitations"`
	CreatedAt          string         `json:"created_at"`
	UpdatedAt          string         `json:"updated_at"`
	Version            int64          `json:"version"`
}

// Audit statuses.
const (
	AuditGenerating = "GENERATING"
	AuditReady      = "READY"
	AuditFailed     = "FAILED"
)

// Coverage records how much of the attack surface the audit reached, and where
// generation stopped early. A path ranking without this is not reviewable.
type Coverage struct {
	EntryPointsExamined int      `json:"entry_points_examined"`
	EntryPointsSkipped  int      `json:"entry_points_skipped"`
	SinksExamined       int      `json:"sinks_examined"`
	SinksSkipped        int      `json:"sinks_skipped"`
	ChainsResolved      int      `json:"chains_resolved"`
	ChainsUnresolved    int      `json:"chains_unresolved"`
	ChainQueries        int      `json:"chain_queries"`
	ChainQueryBudget    int      `json:"chain_query_budget"`
	PathsConsidered     int      `json:"paths_considered"`
	PathsEmitted        int      `json:"paths_emitted"`
	PathsSkipped        int      `json:"paths_skipped"`
	DuplicatePaths      int      `json:"duplicate_paths"`
	Clusters            int      `json:"clusters"`
	Truncated           bool     `json:"truncated"`
	TruncationReasons   []string `json:"truncation_reasons"`
}

// Event is one append-only entry of the path event log. State and events are
// written together so a replay never disagrees with the state.
type Event struct {
	ID        string            `json:"event_id"`
	AuditID   string            `json:"audit_id"`
	PathID    string            `json:"path_id,omitempty"`
	Seq       int64             `json:"seq"`
	Type      string            `json:"type"`
	From      Status            `json:"from,omitempty"`
	To        Status            `json:"to,omitempty"`
	Actor     string            `json:"actor"`
	Reason    string            `json:"reason,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
	CreatedAt string            `json:"created_at"`
}

// Event types.
const (
	EventAuditCreated     = "audit_created"
	EventAuditReady       = "audit_ready"
	EventPathDiscovered   = "path_discovered"
	EventPathQueued       = "path_queued"
	EventPathClaimed      = "path_claimed"
	EventPathHeartbeat    = "path_heartbeat"
	EventPathReleased     = "path_released"
	EventPathLeaseExpired = "path_lease_expired"
	EventPathStatusChange = "path_status_changed"
	EventScoreRecomputed  = "score_recomputed"
)

// PathID derives the id of a path from its identity: the audit, the snapshot, the
// entry, the target and the canonical edge sequence.
//
// The audit is part of the id because two audits of one snapshot are two
// scheduling units that may legitimately hold the same path; the cross-audit
// identity of a path is its Signature, which excludes the audit.
func PathID(auditID, snapshotID, entryNodeID, targetNodeID string, canonicalEdges []string, pathKind string) string {
	h := sha256.New()
	edges := append([]string(nil), canonicalEdges...)
	sort.Strings(edges)
	for _, field := range append([]string{
		"codexploit/path/v1", auditID, snapshotID, entryNodeID, targetNodeID, pathKind,
	}, edges...) {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "path-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// AuditID derives the id of an audit from the snapshot and the configuration that
// changes its result set.
func AuditID(snapshotID, configHash string) string {
	h := sha256.New()
	for _, field := range []string{"codexploit/audit/v1", snapshotID, configHash, fmt.Sprint(ScoreVersion)} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "audit-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// ClusterID derives the id of the approximate-dedup cluster: same entry, same
// target, same security-boundary sequence.
func ClusterID(snapshotID, entryNodeID, targetNodeID string, boundaries []string) string {
	h := sha256.New()
	sorted := append([]string(nil), boundaries...)
	sort.Strings(sorted)
	for _, field := range append([]string{
		"codexploit/path-cluster/v1", snapshotID, entryNodeID, targetNodeID,
	}, sorted...) {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "pcluster-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// EventID derives the id of an event from its position in the log.
func EventID(auditID, pathID string, seq int64) string {
	h := sha256.New()
	for _, field := range []string{"codexploit/path-event/v1", auditID, pathID, fmt.Sprint(seq)} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "pev-" + hex.EncodeToString(h.Sum(nil)[:8])
}

// Signature computes the exact dedup signature of a path document.
func Signature(snapshotID, entryNodeID, targetNodeID, pathKind string, canonicalEdges []string) string {
	h := sha256.New()
	edges := append([]string(nil), canonicalEdges...)
	sort.Strings(edges)
	for _, field := range append([]string{
		"codexploit/path-signature/v1", snapshotID, entryNodeID, targetNodeID, pathKind,
	}, edges...) {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// CanonicalEdges returns the sorted edge ids of a path, which is the sequence the
// exact dedup key is built from.
func (p Path) CanonicalEdges() []string {
	out := make([]string, 0, len(p.Steps))
	for _, step := range p.Steps {
		if step.Kind == "" {
			continue
		}
		out = append(out, step.Layer+":"+step.From+"->"+step.To+":"+step.Kind)
	}
	sort.Strings(out)
	return out
}

// AllNodes returns every ASG or SCG node id the path mentions, sorted, which is
// what coverage and marginal-gain accounting iterate over.
func (p Path) AllNodes() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(p.EntryNodeID)
	add(p.TargetNodeID)
	for _, id := range p.ASGRefs {
		add(id)
	}
	for _, id := range p.Controls {
		add(id)
	}
	for _, id := range p.Inputs {
		add(id)
	}
	for _, id := range p.Assets {
		add(id)
	}
	for _, step := range p.Steps {
		add(step.From)
		add(step.To)
	}
	sort.Strings(out)
	return out
}

// ASGNodes returns the subset of the path's nodes that belong to the attack
// surface, which is the set schedules use for coverage.
func (p Path) ASGNodes() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] || !strings.HasPrefix(id, "asgn-") {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(p.EntryNodeID)
	add(p.TargetNodeID)
	for _, id := range p.ASGRefs {
		add(id)
	}
	sort.Strings(out)
	return out
}

// NowString formats a timestamp the way the whole API and storage layer expects.
func NowString(t time.Time) string { return t.UTC().Format(time.RFC3339) }
