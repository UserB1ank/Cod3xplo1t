package path

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// The formulas are the design's initial heuristics (§6.3, implementation guide
// §8.3):
//
//	R = 0.25E + 0.20I + 0.20S + 0.20T + 0.15B
//	C = 0.35F + 0.25D + 0.25V + 0.15Q
//	U = 0.40N + 0.35G + 0.25H
//	P = 100 · (0.55R + 0.25C + 0.20U) · D_dup / (1 + 0.30K)
//
// They are heuristics, not probabilities, and the coefficients are explicitly
// subject to calibration. What is not negotiable is that every feature has a
// stated derivation (see Features.Reasons), that the weights and the version are
// stored with the score, and that a recomputation can be replayed.
var (
	riskWeights    = map[string]float64{"exposure": 0.25, "impact": 0.20, "controllability": 0.20, "trust_boundary": 0.20, "business_sensitivity": 0.15}
	supportWeights = map[string]float64{"reachability_evidence": 0.35, "dataflow_evidence": 0.25, "control_suspicion": 0.25, "analysis_quality": 0.15}
	utilityWeights = map[string]float64{"novelty": 0.40, "information_gain": 0.35, "reuse_value": 0.25}
	priorityMix    = map[string]float64{"risk": 0.55, "support": 0.25, "utility": 0.20}
	priorityScale  = 100.0
	costPenalty    = 0.30
)

// exposureByEntryKind is how exposed an entry point is to an attacker. A route
// reachable from the network is more exposed than a command-line flag; nothing
// here says whether it is protected.
var exposureByEntryKind = map[string]float64{
	"http_route":       1.00,
	"rpc_handler":      0.90,
	"graphql_handler":  0.90,
	"message_consumer": 0.70,
	"cli_command":      0.50,
	"file_input":       0.60,
}

// impactBySinkKind is the potential impact of a sensitive operation if the path
// is real. It ranks attention, and it is the value most in need of calibration.
var impactBySinkKind = map[string]float64{
	"sink:process_execution": 1.00,
	"sink:sql_execution":     0.90,
	"sink:file_write":        0.80,
	"sink:deserialization":   0.70,
	"sink:network_request":   0.60,
	"sink:sensitive_output":  0.50,
}

// controllabilityBySourceKind is how much an external party can shape a value
// read at that source.
var controllabilityBySourceKind = map[string]float64{
	"input:body":            1.00,
	"input:query_param":     0.90,
	"input:path_param":      0.80,
	"input:form":            0.80,
	"input:message_payload": 0.80,
	"input:cli_arg":         0.70,
	"input:file_content":    0.70,
	"input:header":          0.60,
	"input:cookie":          0.60,
	"input:env":             0.40,
}

// boundaryWeightByKind is how strong a trust boundary crossing is. Crossing from
// the network into the process is the strongest statement the ASG can make.
var boundaryWeightByKind = map[string]float64{
	"network":    1.00,
	"message":    0.90,
	"process":    0.70,
	"filesystem": 0.60,
}

// defaultSensitivity is the neutral business-sensitivity prior. Business value
// cannot be derived from source code, so the default is deliberately mid-scale and
// an audit may override it per asset or subject substring.
const defaultSensitivity = 0.50

// sensitivityHints is the built-in table applied when an audit supplies no
// override: asset and subject names that usually indicate valuable data.
var sensitivityHints = []struct {
	needle string
	weight float64
}{
	{"payment", 0.95}, {"billing", 0.90}, {"invoice", 0.85},
	{"account", 0.85}, {"user", 0.80}, {"credential", 0.95},
	{"password", 0.95}, {"token", 0.85}, {"session", 0.80},
	{"order", 0.80}, {"admin", 0.90}, {"audit", 0.70},
	{"config", 0.60}, {"log", 0.50}, {"tmp", 0.30},
}

// ScoreInput is everything scoring needs beyond the path itself.
type ScoreInput struct {
	// Covered is the coverage of paths scheduled before this one.
	Covered *CoverageSet
	// Sensitivity overrides the built-in sensitivity hints.
	Sensitivity map[string]float64
	// Now stamps the score.
	Now string
	// ClusterSize is the number of paths in this path's cluster.
	ClusterSize int
	// FirstVersion is the number of score snapshots already stored for this path.
	FirstVersion int64
}

// ScorePath normalises the features of a path and computes R, C, U and P.
//
// Every feature is derived from evidence the path already carries, and each
// non-obvious derivation writes a reason. The dataflow feature D is zero in this
// phase: there is no dataflow analysis, and a heuristic must not invent one.
func ScorePath(p Path, in ScoreInput) Path {
	if in.Covered == nil {
		in.Covered = NewCoverageSet()
	}
	reasons := map[string]string{}
	features := Features{Reasons: reasons}

	// E: exposure of the entry point.
	// The generator always records the entry kind. A path without one is scored as
	// an unknown entry point rather than guessed from a display subject.
	entryKind := p.EntryKind
	features.Exposure = lookupFeature(exposureByEntryKind, entryKind, 0.50)
	reasons["exposure"] = "entry kind " + nonEmpty(entryKind, "unknown")

	// I: impact of the target operation.
	subject := p.TargetSubject
	if subject == "" {
		subject = targetSubjectOf(p)
	}
	features.Impact = impactFor(subject)
	reasons["impact"] = "target " + subject

	// S: controllability is the strongest input on the path; a body parameter is
	// easier to shape than an environment variable.
	features.Controllability = 0
	for _, input := range p.Inputs {
		if value := lookupFeature(controllabilityBySourceKind, input, 0); value > features.Controllability {
			features.Controllability = value
		}
	}
	reasons["controllability"] = "strongest of " + strings.Join(p.Inputs, ", ")

	// T: the strongest trust boundary the path crosses.
	features.TrustBoundary = 0
	for _, boundary := range p.Boundaries {
		if value := lookupFeature(boundaryWeightByKind, "boundary:"+boundary, 0); value > features.TrustBoundary {
			features.TrustBoundary = value
		}
	}
	if features.TrustBoundary == 0 && len(p.Boundaries) > 0 {
		features.TrustBoundary = 0.50
	}
	reasons["trust_boundary"] = "boundaries " + strings.Join(p.Boundaries, ", ")

	// B: business sensitivity is an input, never a derivation from code.
	features.BusinessSensitivity = sensitivityFor(p, in.Sensitivity)
	reasons["business_sensitivity"] = "configured or default prior; business value cannot be read from source code"

	// F: reachability evidence — a fully observed chain is stronger than an
	// attack-surface reachability edge.
	switch p.PathStatus {
	case PathStaticallySupported:
		features.ReachabilityEvidence = 1.0
	case PathCandidate:
		features.ReachabilityEvidence = 0.6
	default:
		features.ReachabilityEvidence = 0.3
	}
	if !chainFullyObserved(p) && p.PathStatus == PathStaticallySupported {
		features.ReachabilityEvidence = 0.7
	}
	reasons["reachability_evidence"] = "path status " + string(p.PathStatus)

	// D: dataflow evidence. This phase has none, and says so.
	features.DataflowEvidence = 0
	reasons["dataflow_evidence"] = "no dataflow analysis exists in this phase; every path reports 0"

	// V: control suspicion. Absence of a control is suspicion; a control whose
	// behaviour was never analysed is weaker suspicion.
	switch {
	case len(p.Controls) == 0:
		features.ControlSuspicion = 1.0
		reasons["control_suspicion"] = "no security control observed on the path"
	case !anyObservedControl(p):
		features.ControlSuspicion = 0.6
		reasons["control_suspicion"] = "controls are reachable but none was observed as registered middleware"
	default:
		features.ControlSuspicion = 0.3
		reasons["control_suspicion"] = "a control is registered, but its effectiveness is not analysed"
	}

	// Q: analysis quality from the resolution of the hops actually walked.
	features.AnalysisQuality = analysisQuality(p)
	reasons["analysis_quality"] = "share of observed call hops, penalised for truncation"

	// N: novelty against everything scheduled so far.
	features.Novelty = in.Covered.Novelty(p)
	reasons["novelty"] = "share of attack-surface nodes not yet covered by earlier paths"

	// G: expected information gain — a candidate with open questions and an
	// untouched control is worth more than a re-confirmation.
	features.InformationGain = clamp01(0.20*float64(len(p.OpenQuestions))/3 + boolFeature(len(p.Controls) > 0, 0.30) + boolFeature(len(p.Inputs) >= 2, 0.20))
	reasons["information_gain"] = "derived from open questions, control presence and input variety"

	// H: reuse value — shared controls and assets make one audit pay off elsewhere.
	features.ReuseValue = clamp01(0.5*boolFeature(len(p.Controls) > 0, 1) + 0.5*math.Min(1, float64(len(p.Assets))/2))
	reasons["reuse_value"] = "shared controls and assets this path would resolve"

	// K: estimated cost grows with depth and internal branching.
	depth := float64(p.Depth) / math.Max(1, float64(p.Budget.MaxDepth))
	branch := 0.0
	if p.Budget.MaxBranches > 0 {
		branch = float64(p.BranchCount) / float64(p.Budget.MaxBranches)
	}
	features.EstimatedCost = clamp01(0.5*depth + 0.5*branch)
	reasons["estimated_cost"] = "normalised chain depth and internal branching"

	// D_dup: discount for duplication and clustering. Members of a cluster are not
	// deleted — they are scheduled later, not never.
	features.DedupDiscount = clampRange(1-0.4*in.Covered.Overlap(p)-boolFeature(in.ClusterSize > 1, 0.2), 0.2, 1.0)
	reasons["dedup_discount"] = "coverage overlap and cluster membership"

	weights := map[string]float64{}
	for k, v := range riskWeights {
		weights["risk."+k] = v
	}
	for k, v := range supportWeights {
		weights["support."+k] = v
	}
	for k, v := range utilityWeights {
		weights["utility."+k] = v
	}
	for k, v := range priorityMix {
		weights["priority."+k] = v
	}
	weights["priority.cost_penalty"] = costPenalty

	risk := riskWeights["exposure"]*features.Exposure +
		riskWeights["impact"]*features.Impact +
		riskWeights["controllability"]*features.Controllability +
		riskWeights["trust_boundary"]*features.TrustBoundary +
		riskWeights["business_sensitivity"]*features.BusinessSensitivity
	support := supportWeights["reachability_evidence"]*features.ReachabilityEvidence +
		supportWeights["dataflow_evidence"]*features.DataflowEvidence +
		supportWeights["control_suspicion"]*features.ControlSuspicion +
		supportWeights["analysis_quality"]*features.AnalysisQuality
	utility := utilityWeights["novelty"]*features.Novelty +
		utilityWeights["information_gain"]*features.InformationGain +
		utilityWeights["reuse_value"]*features.ReuseValue
	priority := priorityScale * (priorityMix["risk"]*risk + priorityMix["support"]*support + priorityMix["utility"]*utility) *
		features.DedupDiscount / (1 + costPenalty*features.EstimatedCost)

	p.Features = features
	p.Score = Score{
		Risk:         round4(risk),
		Support:      round4(support),
		Utility:      round4(utility),
		Priority:     round4(priority),
		ScoreVersion: ScoreVersion,
		Weights:      weights,
		ComputedAt:   in.Now,
	}
	if p.Score.ComputedAt == "" {
		p.Score.ComputedAt = NowString(nowUTC())
	}
	return p
}

// FeatureRecordOf snapshots a scored path for replay.
func FeatureRecordOf(p Path, seq int64) FeatureRecord {
	return FeatureRecord{
		PathID:       p.ID,
		AuditID:      p.AuditID,
		Seq:          seq,
		ScoreVersion: p.Score.ScoreVersion,
		Risk:         p.Score.Risk,
		Support:      p.Score.Support,
		Utility:      p.Score.Utility,
		Priority:     p.Score.Priority,
		Features:     p.Features,
		Weights:      p.Score.Weights,
		Reasons:      p.Features.Reasons,
		ComputedAt:   p.Score.ComputedAt,
	}
}

// PriorityBreakdown renders the arithmetic of a priority for an operator.
func PriorityBreakdown(p Path) string {
	f := p.Features
	return strings.Join([]string{
		"R=" + format4(p.Score.Risk),
		"C=" + format4(p.Score.Support),
		"U=" + format4(p.Score.Utility),
		"D_dup=" + format4(f.DedupDiscount),
		"K=" + format4(f.EstimatedCost),
		"P=" + format4(p.Score.Priority),
	}, " ")
}

// impactFor maps a sink node id or subject to the impact feature.
func impactFor(subject string) float64 {
	if value, ok := impactBySinkKind[subject]; ok {
		return value
	}
	if !strings.HasPrefix(subject, "sink:") && strings.HasPrefix(subject, "asgn-") {
		// A node id reached us; impact cannot be derived from it here.
		return 0.50
	}
	if value, ok := impactBySinkKind["sink:"+subject]; ok {
		return value
	}
	return 0.50
}

func targetSubjectOf(p Path) string {
	for _, step := range p.Steps {
		if step.Layer == "asg" && step.Kind == "REACHES" && step.To == p.TargetNodeID {
			return step.Subject
		}
	}
	return p.TargetNodeID
}

func lookupFeature(table map[string]float64, key string, fallback float64) float64 {
	if value, ok := table[key]; ok {
		return value
	}
	return fallback
}

// sensitivityFor applies explicit overrides first, then the built-in hints.
func sensitivityFor(p Path, overrides map[string]float64) float64 {
	haystack := strings.ToLower(strings.Join(append(append([]string{}, p.Assets...), p.Objectives...), " "))
	for needle, weight := range overrides {
		if strings.Contains(haystack, strings.ToLower(needle)) {
			return clamp01(weight)
		}
	}
	best := defaultSensitivity
	for _, hint := range sensitivityHints {
		if strings.Contains(haystack, hint.needle) && hint.weight > best {
			best = hint.weight
		}
	}
	return clamp01(best)
}

func analysisQuality(p Path) float64 {
	hops, observed := 0, 0
	for _, step := range p.Steps {
		if step.Layer != "scg" {
			continue
		}
		hops++
		if step.Resolution == "" || step.Resolution == "resolved" {
			observed++
		}
	}
	quality := 0.4
	if hops > 0 {
		quality = float64(observed) / float64(hops)
	}
	if p.PathStatus == PathUnresolved {
		quality *= 0.6
	}
	quality = clamp01(quality)
	// A path with no chain at all cannot score full analysis quality.
	if hops == 0 && p.PathStatus != PathStaticallySupported {
		quality = math.Min(quality, 0.5)
	}
	return quality
}

func chainFullyObserved(p Path) bool {
	hops := 0
	for _, step := range p.Steps {
		if step.Layer != "scg" {
			continue
		}
		hops++
		if step.Resolution != "" && step.Resolution != "resolved" {
			return false
		}
	}
	return hops > 0
}

func anyObservedControl(p Path) bool {
	for _, step := range p.Steps {
		if step.Kind == "PROTECTED_BY" && step.Evidence == "observed" {
			return true
		}
	}
	return false
}

func boolFeature(condition bool, value float64) float64 {
	if condition {
		return value
	}
	return 0
}

func clamp01(value float64) float64 { return clampRange(value, 0, 1) }

func clampRange(value, low, high float64) float64 {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func round4(value float64) float64 { return math.Round(value*10000) / 10000 }

// format4 prints a feature or a score without trailing zeros, and never as an
// empty string: a zero cost must read as "0", not as a missing value.
func format4(value float64) string {
	out := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.4f", value), "0"), ".")
	if out == "" || out == "-" || out == "-0" {
		return "0"
	}
	return out
}

func nowUTC() time.Time { return time.Now().UTC() }

// FeatureNames returns the feature keys in the order the documents list them.
func FeatureNames() []string {
	return []string{
		"exposure", "impact", "controllability", "trust_boundary", "business_sensitivity",
		"reachability_evidence", "dataflow_evidence", "control_suspicion", "analysis_quality",
		"novelty", "information_gain", "reuse_value", "estimated_cost", "dedup_discount",
	}
}

// SortedReasons returns the feature reasons in a stable order for display.
func SortedReasons(features Features) [][2]string {
	keys := make([]string, 0, len(features.Reasons))
	for key := range features.Reasons {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, [2]string{key, features.Reasons[key]})
	}
	return out
}
