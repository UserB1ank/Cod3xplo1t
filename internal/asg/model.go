// Package asg implements the Attack Surface Graph (ASG) candidate of
// Codexploit: the security-semantics layer derived from the Source Code Graph.
//
// Two rules shape everything here (design doc §3.2, implementation guide §7):
//
//   - the ASG is derived, never authoritative. It reads the SCG through the
//     graph service and every node and edge records the SCG node ids it came
//     from. A node without evidence is rejected by Validate instead of being
//     published.
//   - presence is not effectiveness. A rule may observe that an authentication
//     middleware is registered; it may not claim that the check works. That
//     distinction lives in the evidence status and in the limitations.
package asg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// SchemaVersion is the ASG document version.
const SchemaVersion = 1

// NodeKind enumerates the ASG node types of design doc §3.2. Hypothesis is
// declared for the semantic agent (a later phase) and is never produced by the
// P3 rule extractor.
type NodeKind string

const (
	NodeEntryPoint              NodeKind = "EntryPoint"
	NodeAttackerControlledInput NodeKind = "AttackerControlledInput"
	NodeTrustBoundary           NodeKind = "TrustBoundary"
	NodeSecurityControl         NodeKind = "SecurityControl"
	NodeSensitiveOperation      NodeKind = "SensitiveOperation"
	NodeAsset                   NodeKind = "Asset"
	NodeHypothesis              NodeKind = "Hypothesis"
)

// AllNodeKinds lists every node kind in a stable order.
func AllNodeKinds() []NodeKind {
	return []NodeKind{
		NodeEntryPoint, NodeAttackerControlledInput, NodeTrustBoundary,
		NodeSecurityControl, NodeSensitiveOperation, NodeAsset, NodeHypothesis,
	}
}

// EdgeKind enumerates the ASG edge types of design doc §3.2. SUPPORTED_BY and
// VERIFIED_BY belong to the hypothesis and verification phases; they are declared
// so consumers can rely on the vocabulary, and the P3 extractor does not emit
// them.
type EdgeKind string

const (
	EdgeReaches     EdgeKind = "REACHES"
	EdgeCrosses     EdgeKind = "CROSSES"
	EdgeProtectedBy EdgeKind = "PROTECTED_BY"
	EdgeMayAffect   EdgeKind = "MAY_AFFECT"
	EdgeDerivedFrom EdgeKind = "DERIVED_FROM"
	EdgeSupportedBy EdgeKind = "SUPPORTED_BY"
	EdgeVerifiedBy  EdgeKind = "VERIFIED_BY"
)

// AllEdgeKinds lists every edge kind in a stable order.
func AllEdgeKinds() []EdgeKind {
	return []EdgeKind{
		EdgeReaches, EdgeCrosses, EdgeProtectedBy, EdgeMayAffect,
		EdgeDerivedFrom, EdgeSupportedBy, EdgeVerifiedBy,
	}
}

// EvidenceStatus is the ASG's own account of how sure a claim is. It is
// deliberately separate from the confidence class: "observed" means a rule read
// it from the SCG, "inferred" means a rule derived it, "verified"/"refuted" are
// reserved for the verification phase.
type EvidenceStatus string

const (
	StatusObserved EvidenceStatus = "observed"
	StatusInferred EvidenceStatus = "inferred"
	StatusVerified EvidenceStatus = "verified"
	StatusRefuted  EvidenceStatus = "refuted"
)

// Node is one attack-surface fact.
type Node struct {
	ID         string   `json:"node_id"`
	SnapshotID string   `json:"snapshot_id"`
	Kind       NodeKind `json:"kind"`
	// Subject is the stable identity of the fact inside the snapshot, for example
	// "http_route:GET /users/:id", "input:query:id", "sink:sql_execution".
	Subject    string            `json:"subject"`
	Label      string            `json:"label"`
	Detail     map[string]string `json:"detail,omitempty"`
	Evidence   EvidenceStatus    `json:"evidence_status"`
	Confidence scg.Confidence    `json:"confidence"`
	// Generator names the rule that produced this node, so a reviewer can find
	// and challenge it.
	Generator string `json:"generator"`
	ModuleID  string `json:"module_id,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	// SCGRefs are the SCG node ids this node was derived from.
	SCGRefs []string `json:"scg_refs"`
}

// Edge is one ASG relationship. DERIVED_FROM edges point at SCG node ids; every
// other kind connects two ASG nodes of this document.
type Edge struct {
	ID         string            `json:"edge_id"`
	SnapshotID string            `json:"snapshot_id"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	Kind       EdgeKind          `json:"kind"`
	Evidence   EvidenceStatus    `json:"evidence_status"`
	Confidence scg.Confidence    `json:"confidence"`
	Generator  string            `json:"generator"`
	Detail     map[string]string `json:"detail,omitempty"`
	SCGRefs    []string          `json:"scg_refs"`
}

// Coverage states how much of the SCG the extraction actually examined.
type Coverage struct {
	CallSitesExamined int `json:"call_sites_examined"`
	SymbolsExamined   int `json:"symbols_examined"`
	NodesSkipped      int `json:"nodes_skipped"`
	EdgesSkipped      int `json:"edges_skipped"`
	// ReachabilityDepth and ReachabilityBudget describe the bounded call-graph
	// walk behind REACHES edges.
	ReachabilityDepth  int `json:"reachability_depth"`
	ReachabilityBudget int `json:"reachability_budget"`
	// EntryPointsTruncated counts entry points whose reachability hit a budget,
	// so a short sink list is never read as "nothing beyond".
	EntryPointsTruncated int `json:"entry_points_truncated"`
}

// Engine identifies the component that built the document.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Document is the ASG candidate of one snapshot.
type Document struct {
	SchemaVersion   int            `json:"schema_version"`
	SnapshotID      string         `json:"snapshot_id"`
	ASGVersion      string         `json:"asg_version"`
	SCGVersion      string         `json:"scg_version"`
	Engine          Engine         `json:"engine"`
	RulesetHash     string         `json:"ruleset_hash"`
	Nodes           []Node         `json:"nodes"`
	Edges           []Edge         `json:"edges"`
	NodesByKind     map[string]int `json:"nodes_by_kind"`
	EdgesByKind     map[string]int `json:"edges_by_kind"`
	EvidenceCounts  map[string]int `json:"evidence_counts"`
	Coverage        Coverage       `json:"coverage"`
	Limitations     []string       `json:"limitations"`
	BuiltAt         string         `json:"built_at"`
	BuildDurationMS int64          `json:"build_duration_ms"`
}

// Summary is the cheap description of a stored ASG.
type Summary struct {
	SnapshotID      string         `json:"snapshot_id"`
	ASGVersion      string         `json:"asg_version"`
	SCGVersion      string         `json:"scg_version"`
	Engine          Engine         `json:"engine"`
	RulesetHash     string         `json:"ruleset_hash"`
	Nodes           int            `json:"nodes"`
	Edges           int            `json:"edges"`
	NodesByKind     map[string]int `json:"nodes_by_kind"`
	EdgesByKind     map[string]int `json:"edges_by_kind"`
	EvidenceCounts  map[string]int `json:"evidence_counts"`
	Coverage        Coverage       `json:"coverage"`
	Limitations     []string       `json:"limitations"`
	BuiltAt         string         `json:"built_at"`
	BuildDurationMS int64          `json:"build_duration_ms"`
}

// JSON renders the document deterministically.
func (d *Document) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ArtifactName is the content-addressed file name of an ASG document.
func (d *Document) ArtifactName() (string, error) {
	doc, err := d.JSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(doc)
	return fmt.Sprintf("asg-%s-%s.json", strings.TrimPrefix(d.ASGVersion, "asg-"), hex.EncodeToString(sum[:6])), nil
}

// Summarize derives the summary from a document.
func (d *Document) Summarize() *Summary {
	d.finalizeCounts()
	return &Summary{
		SnapshotID:      d.SnapshotID,
		ASGVersion:      d.ASGVersion,
		SCGVersion:      d.SCGVersion,
		Engine:          d.Engine,
		RulesetHash:     d.RulesetHash,
		Nodes:           len(d.Nodes),
		Edges:           len(d.Edges),
		NodesByKind:     d.NodesByKind,
		EdgesByKind:     d.EdgesByKind,
		EvidenceCounts:  d.EvidenceCounts,
		Coverage:        d.Coverage,
		Limitations:     d.Limitations,
		BuiltAt:         d.BuiltAt,
		BuildDurationMS: d.BuildDurationMS,
	}
}

// finalizeCounts recomputes the kind and evidence histograms.
func (d *Document) finalizeCounts() {
	d.NodesByKind = map[string]int{}
	for _, n := range d.Nodes {
		d.NodesByKind[string(n.Kind)]++
	}
	d.EdgesByKind = map[string]int{}
	for _, e := range d.Edges {
		d.EdgesByKind[string(e.Kind)]++
	}
	d.EvidenceCounts = map[string]int{}
	for _, n := range d.Nodes {
		d.EvidenceCounts[string(n.Evidence)]++
	}
}

// normalize replaces nil collections with empty ones so a stored document and a
// fresh one serialise identically.
func (d *Document) normalize() {
	if d.Nodes == nil {
		d.Nodes = []Node{}
	}
	if d.Edges == nil {
		d.Edges = []Edge{}
	}
	if d.Limitations == nil {
		d.Limitations = []string{}
	}
}

// sortForDeterminism orders every collection by id.
func (d *Document) sortForDeterminism() {
	sort.Slice(d.Nodes, func(i, j int) bool { return d.Nodes[i].ID < d.Nodes[j].ID })
	sort.Slice(d.Edges, func(i, j int) bool { return d.Edges[i].ID < d.Edges[j].ID })
	sort.Strings(d.Limitations)
	d.finalizeCounts()
}

// addLimitation appends a unique coverage statement.
func (d *Document) addLimitation(format string, args ...any) {
	note := fmt.Sprintf(format, args...)
	for _, existing := range d.Limitations {
		if existing == note {
			return
		}
	}
	d.Limitations = append(d.Limitations, note)
}

// Validate enforces the "no claim without evidence" rule and the internal
// consistency of the document. It returns the first problem it finds.
func (d *Document) Validate() error {
	nodeIDs := make(map[string]bool, len(d.Nodes))
	for _, n := range d.Nodes {
		if n.ID == "" {
			return fmt.Errorf("asg: node of kind %s has no id", n.Kind)
		}
		if nodeIDs[n.ID] {
			return fmt.Errorf("asg: duplicate node id %s", n.ID)
		}
		nodeIDs[n.ID] = true
		if len(n.SCGRefs) == 0 {
			return fmt.Errorf("asg: node %s (%s) asserts %q without SCG evidence", n.ID, n.Kind, n.Subject)
		}
		if !knownNodeKind(n.Kind) {
			return fmt.Errorf("asg: node %s has unknown kind %q", n.ID, n.Kind)
		}
		if n.Generator == "" {
			return fmt.Errorf("asg: node %s does not name the rule that produced it", n.ID)
		}
	}
	for _, e := range d.Edges {
		if !knownEdgeKind(e.Kind) {
			return fmt.Errorf("asg: edge %s has unknown kind %q", e.ID, e.Kind)
		}
		if len(e.SCGRefs) == 0 {
			return fmt.Errorf("asg: edge %s (%s) asserts a relationship without SCG evidence", e.ID, e.Kind)
		}
		if e.Kind == EdgeDerivedFrom {
			if !isSCGID(e.To) {
				return fmt.Errorf("asg: DERIVED_FROM edge %s points at %s, which is not an SCG id", e.ID, e.To)
			}
			continue
		}
		if !nodeIDs[e.From] || !nodeIDs[e.To] {
			return fmt.Errorf("asg: edge %s (%s) connects %s -> %s, and an endpoint is not a node of this document", e.ID, e.Kind, e.From, e.To)
		}
	}
	return nil
}

func knownNodeKind(kind NodeKind) bool {
	for _, k := range AllNodeKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

func knownEdgeKind(kind EdgeKind) bool {
	for _, k := range AllEdgeKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// isSCGID reports whether an id belongs to the SCG id space.
func isSCGID(id string) bool {
	for _, prefix := range []string{"sym-", "cs-", "file-", "mod-", "edge-"} {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

// Version derives the ASG version from what produced it: the snapshot, the SCG
// version it read, the engine and the rule set. A different rule set, or a
// rebuilt SCG, is a different attack surface and must not be compared with the
// previous one.
func Version(snapshotID, scgVersion string, engine Engine, rulesetHash string) string {
	h := sha256.New()
	for _, field := range []string{"codexploit/asg/v1", snapshotID, scgVersion, engine.Name, engine.Version, rulesetHash} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "asg-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// NodeID derives the stable id of an ASG node from its kind, subject and a
// discriminator. The discriminator is what keeps two occurrences of the same
// shape apart — two `POST /login` registrations are two entry points with two
// independent pieces of evidence, not one node.
func NodeID(snapshotID string, kind NodeKind, subject, discriminator string) string {
	h := sha256.New()
	for _, field := range []string{"codexploit/asg/node/v1", snapshotID, string(kind), subject, discriminator} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "asgn-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// EdgeID derives the stable id of an ASG edge.
func EdgeID(snapshotID string, kind EdgeKind, from, to, discriminator string) string {
	h := sha256.New()
	for _, field := range []string{"codexploit/asg/edge/v1", snapshotID, string(kind), from, to, discriminator} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "asge-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// BuiltAtNow is the timestamp format used for ASG builds.
func BuiltAtNow() string { return time.Now().UTC().Format(time.RFC3339) }
