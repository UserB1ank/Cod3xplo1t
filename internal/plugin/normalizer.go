package plugin

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

const SemanticID = "builtin.security-semantics"

type NativeReport struct {
	Format      string               `json:"format"`
	Scope       artifact.Scope       `json:"scope"`
	Graph       *scg.Graph           `json:"graph"`
	Surface     *asg.Document        `json:"surface"`
	Coverage    Coverage             `json:"coverage"`
	Limitations []string             `json:"limitations"`
	Paths       *path.GenerateResult `json:"paths,omitempty"`
}

type DiscoveryPath struct {
	ID            string      `json:"id"`
	Kind          string      `json:"path_kind"`
	Completeness  string      `json:"completeness"`
	EvidenceClass string      `json:"evidence_class"`
	Steps         []path.Step `json:"steps"`
	SCGRefs       []string    `json:"scg_refs"`
	ASGRefs       []string    `json:"asg_refs"`
	EvidenceRefs  []string    `json:"evidence_refs"`
	Limitations   []string    `json:"limitations"`
}
type Candidate struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	Title        string   `json:"title"`
	SeverityHint string   `json:"severity_hint,omitempty"`
	RuleID       string   `json:"rule_id,omitempty"`
	RuleVersion  string   `json:"rule_version,omitempty"`
	PathRefs     []string `json:"path_refs"`
	EvidenceRefs []string `json:"evidence_refs"`
	File         string   `json:"file"`
	Line         int      `json:"line"`
	Limitations  []string `json:"limitations"`
}

type DiscoveryDocument struct {
	APIVersion     string            `json:"api_version"`
	Kind           string            `json:"kind"`
	Scope          artifact.Scope    `json:"scope"`
	Producer       artifact.Producer `json:"producer"`
	Inputs         []artifact.Ref    `json:"inputs"`
	NativeArtifact artifact.Ref      `json:"native_artifact"`
	CanonicalIDs   []string          `json:"canonical_ids"`
	Nodes          []asg.Node        `json:"nodes"`
	Edges          []asg.Edge        `json:"edges"`
	Coverage       Coverage          `json:"coverage"`
	Limitations    []string          `json:"limitations"`
	Paths          []DiscoveryPath   `json:"paths"`
	Candidates     []Candidate       `json:"candidates"`
}

// Normalizer binds native claims to host-verified inputs and immutable evidence.
// It has no finding store and cannot change a verdict or severity assessment.
type Normalizer struct{}

func (Normalizer) Normalize(inv Invocation, native artifact.Ref, raw []byte) (DiscoveryDocument, error) {
	var report NativeReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
		return DiscoveryDocument{}, ErrInvalid
	}
	if report.Format != "codexploit/semantic-native/v1" && report.Format != "codexploit/paths-native/v1" {
		return DiscoveryDocument{}, ErrUnsupported
	}
	if report.Scope != inv.Request.Scope || native.Scope != report.Scope || native.SHA256 != digest(raw) || native.Bytes != int64(len(raw)) || native.Producer.InvocationID != inv.ID || report.Graph == nil || report.Surface == nil {
		return DiscoveryDocument{}, ErrInvalid
	}
	expected := artifact.Producer{PluginID: inv.Request.PluginID, PluginVersion: inv.Request.PluginVersion, InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest}
	if native.Producer != expected {
		return DiscoveryDocument{}, ErrInvalid
	}
	if report.Graph.SnapshotID != report.Scope.SnapshotID || report.Surface.SnapshotID != report.Scope.SnapshotID || report.Surface.SCGVersion != report.Graph.GraphVersion || report.Surface.Validate() != nil {
		return DiscoveryDocument{}, ErrInvalid
	}
	canonical := map[string]bool{}
	for _, file := range report.Graph.Files {
		if file.SnapshotID != report.Scope.SnapshotID {
			return DiscoveryDocument{}, ErrInvalid
		}
		canonical[file.ID] = true
	}
	for _, symbol := range report.Graph.Symbols {
		if symbol.SnapshotID != report.Scope.SnapshotID {
			return DiscoveryDocument{}, ErrInvalid
		}
		canonical[symbol.ID] = true
	}
	for _, call := range report.Graph.CallSites {
		if call.SnapshotID != report.Scope.SnapshotID {
			return DiscoveryDocument{}, ErrInvalid
		}
		canonical[call.ID] = true
	}
	for _, mod := range report.Graph.Modules {
		if mod.SnapshotID != report.Scope.SnapshotID {
			return DiscoveryDocument{}, ErrInvalid
		}
		canonical[mod.ID] = true
	}
	for _, edge := range report.Graph.Edges {
		if edge.SnapshotID != report.Scope.SnapshotID {
			return DiscoveryDocument{}, ErrInvalid
		}
		canonical[edge.ID] = true
	}
	for _, node := range report.Surface.Nodes {
		if node.SnapshotID != report.Scope.SnapshotID || (node.Evidence != asg.StatusObserved && node.Evidence != asg.StatusInferred) {
			return DiscoveryDocument{}, ErrInvalid
		}
		for _, id := range node.SCGRefs {
			if !canonical[id] {
				return DiscoveryDocument{}, ErrInvalid
			}
		}
	}
	// Legacy ASG relation provenance may name another ASG node. Resolve those
	// through the same validated snapshot index rather than changing their IDs.
	for _, node := range report.Surface.Nodes {
		canonical[node.ID] = true
	}
	for _, edge := range report.Surface.Edges {
		if edge.SnapshotID != report.Scope.SnapshotID || (edge.Evidence != asg.StatusObserved && edge.Evidence != asg.StatusInferred) {
			return DiscoveryDocument{}, ErrInvalid
		}
		for _, id := range edge.SCGRefs {
			if !canonical[id] {
				return DiscoveryDocument{}, ErrInvalid
			}
		}
	}
	for _, node := range report.Surface.Nodes {
		canonical[node.ID] = true
	}
	for _, edge := range report.Surface.Edges {
		canonical[edge.ID] = true
	}
	ids := []string{}
	for id := range canonical {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	document := DiscoveryDocument{APIVersion: "codexploit/v1", Kind: "security.facts", Scope: report.Scope, Producer: native.Producer, Inputs: inv.Request.Inputs, NativeArtifact: native, CanonicalIDs: ids, Nodes: report.Surface.Nodes, Edges: report.Surface.Edges, Coverage: report.Coverage, Limitations: report.Limitations, Paths: []DiscoveryPath{}, Candidates: []Candidate{}}
	if report.Format == "codexploit/paths-native/v1" {
		if report.Paths == nil || report.Paths.SnapshotID != report.Scope.SnapshotID || report.Paths.SCGVersion != report.Graph.GraphVersion || report.Paths.ASGVersion != report.Surface.ASGVersion {
			return DiscoveryDocument{}, ErrInvalid
		}
		document.Kind = "discovery.paths"
		nodes := map[string]asg.Node{}
		for _, node := range report.Surface.Nodes {
			nodes[node.ID] = node
		}
		for _, p := range report.Paths.Paths {
			if p.SnapshotID != report.Scope.SnapshotID || p.SCGVersion != report.Graph.GraphVersion || p.ASGVersion != report.Surface.ASGVersion || p.PathKind != path.PathKindCallGraph || !path.ValidPathStatus(p.PathStatus) {
				return DiscoveryDocument{}, ErrInvalid
			}
			if _, ok := nodes[p.EntryNodeID]; !ok {
				return DiscoveryDocument{}, ErrInvalid
			}
			if _, ok := nodes[p.TargetNodeID]; !ok {
				return DiscoveryDocument{}, ErrInvalid
			}
			for _, id := range append(append([]string{}, p.SCGRefs...), p.ASGRefs...) {
				if !canonical[id] {
					return DiscoveryDocument{}, ErrInvalid
				}
			}
			for _, step := range p.Steps {
				if !canonical[step.From] || !canonical[step.To] || (step.Layer != "asg" && step.Layer != "scg") {
					return DiscoveryDocument{}, ErrInvalid
				}
			}
			kind, completeness := "hypothesis", "partial"
			if p.PathStatus == path.PathStaticallySupported {
				kind, completeness = "call_reachability", "complete"
			}
			evidence := []string{native.ID}
			notes := append(append([]string{}, p.Limitations...), "Call reachability is not taint flow or proof of exploitability")
			document.Paths = append(document.Paths, DiscoveryPath{ID: p.ID, Kind: kind, Completeness: completeness, EvidenceClass: string(p.PathStatus), Steps: p.Steps, SCGRefs: p.SCGRefs, ASGRefs: p.ASGRefs, EvidenceRefs: evidence, Limitations: notes})
			target := nodes[p.TargetNodeID]
			hint := "medium"
			if target.Subject == "sink:process_execution" || target.Subject == "sink:sql_execution" {
				hint = "high"
			}
			document.Candidates = append(document.Candidates, Candidate{ID: "obs-" + digest([]byte(inv.ID + "\x00" + p.ID))[:32], Status: "candidate", Title: p.EntrySubject + " → " + p.TargetSubject, SeverityHint: hint, PathRefs: []string{p.ID}, EvidenceRefs: evidence, File: target.File, Line: target.Line, Limitations: notes})
		}
	}
	return document, nil
}
