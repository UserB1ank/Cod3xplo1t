package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// VerifyPlanner turns a hypothesis into a finding and a bounded verification plan.
//
// It lives in the query layer, not in internal/verify, for the same reason
// AgentFacts and AgentCoordinator do: the storage layer implements verify.Store, so
// `verify → graph → storage → verify` would be an import cycle. This package may
// import verify, agent and path; none of them may import this one.
//
// The planner is deliberately conservative. It never invents evidence: a plan it
// builds states the claim, the goal and what the upstream layers could not
// establish, names the dataflow gap as the thing to close, and asks for a dynamic
// proof only when the scope already allows network access — and then marks that
// step as needing a recorded human approval. A plan that a caller supplies itself
// is still validated by verify.Prepare, but it is the caller's plan, not this
// one's.
type VerifyPlanner struct {
	Store storage.FullStore
	// Graph is optional. The planner does not need it to derive a plan from a
	// stored path, but a caller may wire it so the reachability query it emits can
	// be replayed against the same service.
	Graph *Service
	// Now is injectable so a replayed build produces the same timestamp.
	Now func() time.Time
	// MaxSteps bounds a generated plan. Zero means defaultPlanSteps, which is well
	// under verify.MaxSteps because a generated plan has no business filling the
	// ceiling.
	MaxSteps int
	// MaxSliceLines bounds the optional source slice a plan may name. Zero means
	// the graph service's own default. The generated plan does not inline source:
	// a plan is a declaration of what would run, not a dump of the code.
	MaxSliceLines int
}

// Bounds and provenance of generated evidence. The tool name is what a reviewer
// greps for when asking "where did this evidence object come from".
const (
	// evidenceTool names the producer of the evidence the planner derives from a
	// hypothesis's own citations.
	evidenceTool = "hypothesis-evidence"
	// evidenceToolVersion is the version of that producer.
	evidenceToolVersion = "1"
	// defaultPlanSteps bounds a generated plan.
	defaultPlanSteps = 8
	// maxPlanLimitations bounds the caveats a generated plan carries, so a plan
	// cannot spend its whole step budget on restating caveats.
	maxPlanLimitations = 12
	// contradictionNote explains, on the evidence object itself, why the planner
	// marked it as contradicting the claim.
	contradictionNote = "the hypothesis records this citation as contradicting its own claim"
)

// NewVerifyPlanner builds the planner over a full store and (optionally) the graph
// query service.
func NewVerifyPlanner(store storage.FullStore, g *Service) *VerifyPlanner {
	return &VerifyPlanner{Store: store, Graph: g, Now: func() time.Time { return time.Now().UTC() }}
}

func (p *VerifyPlanner) now() time.Time {
	if p == nil || p.Now == nil {
		return time.Now().UTC()
	}
	return p.Now().UTC()
}

func (p *VerifyPlanner) maxSteps() int {
	if p != nil && p.MaxSteps > 0 {
		if p.MaxSteps > verify.MaxSteps {
			return verify.MaxSteps
		}
		return p.MaxSteps
	}
	return defaultPlanSteps
}

func (p *VerifyPlanner) maxSliceLines() int {
	if p != nil && p.MaxSliceLines > 0 {
		return p.MaxSliceLines
	}
	return defaultSliceLines
}

// EnsureFinding loads a hypothesis, derives its finding id, and seeds the candidate
// finding with the hypothesis's own citations turned into evidence objects.
//
// It seeds once and never again. A finding that verification has already touched —
// a conclusive status, or any evidence list — is returned untouched: the lists
// belong to the verification service after the first run, and a re-derivation must
// not let a hypothesis's static citations masquerade as verification evidence.
//
// Idempotence means byte-identical: a second call on an unchanged finding returns
// the stored document without writing, so its UpdatedAt and Version do not move. The
// evidence ids are content-addressed and re-appending an identical object is a
// no-op, but the equality check happens first so an equal document is never written
// at all.
func (p *VerifyPlanner) EnsureFinding(ctx context.Context, hypothesisID string) (*verify.Finding, error) {
	if p == nil || p.Store == nil {
		return nil, errors.New("graph: verify planner has no store")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(hypothesisID)
	if id == "" {
		return nil, fmt.Errorf("%w: a hypothesis id is required to ensure a finding", verify.ErrInvalidArgument)
	}
	hypothesis, err := p.hypothesis(id)
	if err != nil {
		return nil, err
	}
	findingID := verify.FindingID(hypothesis.ID)

	existing, err := p.Store.GetFinding(findingID)
	switch {
	case err == nil:
	case isVerifyNotFound(err):
		existing = nil
	default:
		return nil, err
	}
	// Seeded already, or settled by verification: hand back what is stored.
	if existing != nil && !seedableFinding(existing) {
		return existing, nil
	}

	evidence, citations, err := p.hypothesisEvidence(hypothesis, findingID)
	if err != nil {
		return nil, err
	}

	now := verify.NowString(p.now())
	candidate := verify.Finding{
		ID:           findingID,
		HypothesisID: hypothesis.ID,
		PathID:       hypothesis.PathID,
		AuditID:      firstNonEmpty(hypothesis.AuditID, p.auditIDOf(hypothesis.PathID)),
		SnapshotID:   hypothesis.SnapshotID,
		Title:        firstNonEmpty(hypothesis.Statement, findingID),
		Severity:     verify.NormalizeSeverity(hypothesis.SeverityHint),
		Status:       verify.FindingCandidate,
		Confidence:   hypothesis.Confidence,
		// Every citation the hypothesis records is claim-time context, so it lands in
		// Supporting. The contradicting/inconclusive lists are owned by the
		// verification service: a citation the planner wrote into them would be read
		// as a verdict it never reached. A citation the hypothesis itself records as
		// contradicting keeps that polarity on the evidence object (MarkContradicting
		// above), which is where DeriveOutcome and a reviewer read it.
		Supporting:         citations,
		Contradicting:      []string{},
		Inconclusive:       []string{},
		Limitations:        p.limitations(hypothesis, nil),
		CreatedAt:          now,
		UpdatedAt:          now,
		VerificationRunIDs: []string{},
		Environments:       []string{},
	}
	if existing != nil {
		// Carry the stored identity forward so the equality check compares content,
		// not the clock: an unchanged re-derivation must not touch UpdatedAt or
		// Version.
		candidate.CreatedAt = firstNonEmpty(existing.CreatedAt, now)
		candidate.UpdatedAt = existing.UpdatedAt
		candidate.Version = existing.Version
		if sameSeededFinding(candidate, *existing) {
			return existing, nil
		}
		candidate.UpdatedAt = now
	}
	if len(evidence) > 0 {
		if err := p.Store.AppendEvidence(evidence); err != nil {
			return nil, err
		}
	}
	if err := p.Store.UpsertFinding(candidate); err != nil {
		return nil, err
	}
	stored, err := p.Store.GetFinding(findingID)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// BuildPlan produces a bounded, honest plan for a hypothesis and validates it.
//
// The plan always passes verify.Prepare before it is returned: a caller that holds
// the *Prepared has no excuse for executing an unvalidated plan. The plan carries
// the claim verbatim, the security goal, the limitations inherited from the path
// and the hypothesis, and a scope that was passed through — an auto-built plan may
// narrow what it asks for, never what it is allowed to do.
func (p *VerifyPlanner) BuildPlan(ctx context.Context, hypothesisID string, scope verify.Scope, env verify.Environment) (*verify.Prepared, error) {
	if p == nil || p.Store == nil {
		return nil, errors.New("graph: verify planner has no store")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hypothesisID = strings.TrimSpace(hypothesisID)
	if hypothesisID == "" {
		return nil, fmt.Errorf("%w: a hypothesis id is required to build a plan", verify.ErrInvalidArgument)
	}
	// Ensuring the finding first is what makes a run's finding_id resolvable: a
	// plan that names a finding nobody stored would leave the verdict undecidable.
	finding, err := p.EnsureFinding(ctx, hypothesisID)
	if err != nil {
		return nil, err
	}
	hypothesis, err := p.hypothesis(hypothesisID)
	if err != nil {
		return nil, err
	}
	target, err := p.path(hypothesis.PathID)
	if err != nil {
		return nil, err
	}

	env = env.Normalize()
	if strings.TrimSpace(scope.SnapshotID) == "" {
		scope.SnapshotID = hypothesis.SnapshotID
	}
	steps := p.steps(hypothesis, target, scope)
	if len(steps) == 0 {
		return nil, fmt.Errorf("%w: no verification step could be derived for hypothesis %s", verify.ErrInvalidPlan, hypothesis.ID)
	}

	plan := verify.Plan{
		SchemaVersion: verify.SchemaVersion,
		HypothesisID:  hypothesis.ID,
		FindingID:     finding.ID,
		PathID:        hypothesis.PathID,
		AuditID:       firstNonEmpty(hypothesis.AuditID, target.AuditID),
		SnapshotID:    hypothesis.SnapshotID,
		SecurityGoal:  firstNonEmpty(hypothesis.SecurityGoal, securityGoal(*target)),
		Claim:         hypothesis.Statement,
		Steps:         steps,
		Environment:   env,
		Scope:         scope,
		Limitations:   p.limitations(hypothesis, target),
		GeneratedAt:   verify.NowString(p.now()),
	}
	prepared, err := verify.Prepare(plan)
	if err != nil {
		return nil, err
	}
	return prepared, nil
}

// steps derives the plan from the security goal. Every step states what it
// expects and what would contradict the claim, because a step that cannot fail is
// not a test.
func (p *VerifyPlanner) steps(hypothesis *agent.Hypothesis, target *path.Path, scope verify.Scope) []verify.Step {
	claim := hypothesis.Statement
	steps := make([]verify.Step, 0, 3)

	// The reachability claim is the one thing the path engine already established,
	// so re-checking it is cheap and it is the first thing a refutation attacks.
	steps = append(steps, verify.Step{
		Kind: verify.StepStaticCheck,
		StaticQuery: map[string]string{
			"query":          "path.reachability",
			"snapshot_id":    target.SnapshotID,
			"path_id":        target.ID,
			"audit_id":       target.AuditID,
			"entry_node_id":  target.EntryNodeID,
			"target_node_id": target.TargetNodeID,
			"max_lines":      fmt.Sprint(p.maxSliceLines()),
		},
		Expectation: fmt.Sprintf(
			"the call graph still resolves a path from %s to %s in snapshot %s, with no unresolved call site on the chain",
			firstNonEmpty(target.EntrySubject, target.EntryNodeID),
			firstNonEmpty(target.TargetSubject, target.TargetNodeID),
			target.SnapshotID),
		Contradiction: "an unresolved or removed call site on the chain breaks reachability, which refutes the claim",
	})

	// The gap that keeps a hypothesis from being a finding is the missing dataflow
	// fact; the step names it instead of pretending the path proved it.
	steps = append(steps, verify.Step{
		Kind: verify.StepDataflowProbe,
		StaticQuery: map[string]string{
			"query":          "dataflow.gap",
			"claim":          claim,
			"path_id":        target.ID,
			"snapshot_id":    target.SnapshotID,
			"entry_node_id":  target.EntryNodeID,
			"target_node_id": target.TargetNodeID,
		},
		Expectation:   "a dataflow answer that shows attacker-controlled input reaching the sensitive operation, or names the unresolved edge that prevents the analysis",
		Contradiction: "the dataflow answer shows the sensitive operation's arguments do not derive from the entry point, which refutes the claim",
	})

	// A dynamic proof is added only when the scope already allows network access.
	// It is marked as requiring approval, and the approval is recorded with the run
	// rather than asserted here.
	if scope.AllowNetwork {
		steps = append(steps, verify.Step{
			Kind:             verify.StepDynamicProof,
			Command:          dynamicProofCommand(*target, scope),
			RequiresApproval: true,
			Expectation:      "the proof reproduces the claimed effect against the authorized target and the run records the shortest reproduction",
			Contradiction:    "the target rejects or neutralises the proof, which refutes the claim for this environment",
		})
	}

	if max := p.maxSteps(); len(steps) > max {
		steps = steps[:max]
	}
	return steps
}

// dynamicProofCommand names the proof a dynamic step would run. It is an argv, not
// a shell string, and it is a declaration: an operator that needs a specific
// proof-of-concept supplies the plan explicitly instead.
func dynamicProofCommand(target path.Path, scope verify.Scope) []string {
	argv := []string{"verify-dynamic-proof", "--path", target.ID}
	for _, allowed := range scope.AllowedTargets {
		if allowed = strings.TrimSpace(allowed); allowed != "" {
			argv = append(argv, "--target", allowed)
			break
		}
	}
	return argv
}

// hypothesisEvidence converts a hypothesis's own citations into immutable evidence
// objects. A citation with a file and a line is source evidence; an id-only
// citation is a static query. The transformation goes through verify.NewEvidence,
// so redaction, hashing and id derivation cannot be skipped.
//
// It returns the citation ids exactly once, in a stable order, because a finding is
// seeded once: the caller writes them into the finding's supporting list and never
// touches the other two.
func (p *VerifyPlanner) hypothesisEvidence(hypothesis *agent.Hypothesis, findingID string) ([]verify.Evidence, []string, error) {
	if strings.TrimSpace(hypothesis.SnapshotID) == "" {
		return nil, nil, fmt.Errorf("%w: hypothesis %s has no snapshot id, so its citations cannot become evidence",
			verify.ErrInvalidArgument, hypothesis.ID)
	}
	now := verify.NowString(p.now())
	evidence := make([]verify.Evidence, 0, len(hypothesis.Supporting)+len(hypothesis.Contradicting))
	ids := make([]string, 0, len(hypothesis.Supporting)+len(hypothesis.Contradicting))
	seen := map[string]bool{}

	// The hypothesis's own two lists are rendered in order: what it offers in
	// favour first, then what it records against itself. The polarity survives on
	// the object as the contradiction marker, so a reviewer can still tell the two
	// apart inside Supporting.
	for _, side := range []struct {
		refs          []agent.EvidenceRef
		contradicting bool
	}{
		{hypothesis.Supporting, false},
		{hypothesis.Contradicting, true},
	} {
		for _, ref := range side.refs {
			content := evidenceContent(ref)
			if content == "" {
				continue
			}
			kind := verify.EvidenceSource
			if strings.TrimSpace(ref.File) == "" {
				kind = verify.EvidenceStaticQuery
			}
			item, err := verify.NewEvidence(kind, content, verify.EvidenceOptions{
				Tool:         evidenceTool,
				ToolVersion:  evidenceToolVersion,
				SnapshotID:   hypothesis.SnapshotID,
				HypothesisID: hypothesis.ID,
				FindingID:    findingID,
				PathID:       hypothesis.PathID,
				File:         ref.File,
				Line:         ref.Line,
				Now:          now,
			})
			if err != nil {
				return nil, nil, err
			}
			// Content-addressed ids collapse identical citations. A citation the
			// hypothesis records on both sides keeps the first polarity.
			if seen[item.ID] {
				continue
			}
			seen[item.ID] = true
			if side.contradicting {
				item = verify.MarkContradicting(item, contradictionNote)
			}
			evidence = append(evidence, item)
			ids = append(ids, item.ID)
		}
	}
	return evidence, ids, nil
}

// seedableFinding reports whether a finding may still be seeded from its
// hypothesis. A finding that verification has touched keeps its lists and its
// verdict: only a missing finding, or a candidate whose lists are still empty, can
// be filled in.
func seedableFinding(finding *verify.Finding) bool {
	if finding == nil {
		return true
	}
	if finding.Status != verify.FindingCandidate {
		return false
	}
	return len(finding.Supporting) == 0 && len(finding.Contradicting) == 0 &&
		len(finding.Inconclusive) == 0 && len(finding.VerificationRunIDs) == 0
}

// sameSeededFinding reports whether a re-derivation would store the document that
// is already there. Timestamps and the version are compared too, but the caller
// copies them from the stored finding before calling, so an unchanged re-derivation
// is byte-identical and is never written.
func sameSeededFinding(candidate, stored verify.Finding) bool {
	if candidate.ID != stored.ID || candidate.HypothesisID != stored.HypothesisID ||
		candidate.PathID != stored.PathID || candidate.AuditID != stored.AuditID ||
		candidate.SnapshotID != stored.SnapshotID || candidate.Title != stored.Title ||
		candidate.Severity != stored.Severity || candidate.Status != stored.Status ||
		candidate.Confidence != stored.Confidence || candidate.ReproduceSteps != stored.ReproduceSteps ||
		candidate.CreatedAt != stored.CreatedAt || candidate.UpdatedAt != stored.UpdatedAt ||
		candidate.Version != stored.Version {
		return false
	}
	for _, pair := range [][2][]string{
		{candidate.Supporting, stored.Supporting},
		{candidate.Contradicting, stored.Contradicting},
		{candidate.Inconclusive, stored.Inconclusive},
		{candidate.Limitations, stored.Limitations},
		{candidate.VerificationRunIDs, stored.VerificationRunIDs},
		{candidate.Environments, stored.Environments},
	} {
		if !sameStrings(pair[0], pair[1]) {
			return false
		}
	}
	return true
}

// sameStrings compares two string lists, treating nil and empty as equal because a
// store is free to return either for an empty JSON array.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// evidenceContent renders one citation deterministically. Everything the citation
// carries is included, so two citations that differ anywhere produce two evidence
// objects and two identical citations produce one.
func evidenceContent(ref agent.EvidenceRef) string {
	parts := make([]string, 0, 3)
	if location := strings.TrimSpace(ref.File); location != "" {
		if ref.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, ref.Line)
		}
		parts = append(parts, location)
	}
	if id := strings.TrimSpace(ref.ID); id != "" {
		parts = append(parts, id)
	}
	if summary := strings.TrimSpace(ref.Summary); summary != "" {
		parts = append(parts, summary)
	}
	return strings.Join(parts, " | ")
}

// limitations merges what the plan and the finding must admit: the two properties
// of this phase that no snapshot changes, the path's own caveats, and the
// limitations of the agent run that produced the hypothesis.
func (p *VerifyPlanner) limitations(hypothesis *agent.Hypothesis, target *path.Path) []string {
	out := make([]string, 0, maxPlanLimitations)
	out = append(out, standardTaskLimitations...)
	if target != nil {
		out = append(out, target.Limitations...)
	}
	out = append(out, p.hypothesisLimitations(hypothesis)...)
	return mergeLimitations(out, nil)
}

// hypothesisLimitations reads the limitations the producing run carried. A run
// that cannot be read degrades to no extra caveats rather than failing the
// planner: the standard statements are always there, so the plan never claims to be
// complete.
func (p *VerifyPlanner) hypothesisLimitations(hypothesis *agent.Hypothesis) []string {
	if hypothesis == nil || strings.TrimSpace(hypothesis.RunID) == "" {
		return nil
	}
	run, err := p.Store.GetRun(hypothesis.RunID)
	if err != nil || run == nil {
		return nil
	}
	return run.Task.Limitations
}

// hypothesis loads one claim, mapping "absent" onto verify.ErrNotFound so the API
// can answer 404 without knowing the agent runtime's sentinels.
func (p *VerifyPlanner) hypothesis(hypothesisID string) (*agent.Hypothesis, error) {
	hypothesis, err := p.Store.GetHypothesis(hypothesisID)
	if err != nil {
		if isVerifyNotFound(err) {
			return nil, fmt.Errorf("%w: hypothesis %s", verify.ErrNotFound, hypothesisID)
		}
		return nil, err
	}
	return hypothesis, nil
}

// path loads the path a hypothesis was recorded over.
func (p *VerifyPlanner) path(pathID string) (*path.Path, error) {
	if strings.TrimSpace(pathID) == "" {
		return nil, fmt.Errorf("%w: the hypothesis has no path id", verify.ErrInvalidArgument)
	}
	target, err := p.Store.GetPath(pathID)
	if err != nil {
		if isVerifyNotFound(err) {
			return nil, fmt.Errorf("%w: path %s", verify.ErrNotFound, pathID)
		}
		return nil, err
	}
	return target, nil
}

// auditIDOf falls back to the stored path when a hypothesis lost its audit id.
func (p *VerifyPlanner) auditIDOf(pathID string) string {
	target, err := p.path(pathID)
	if err != nil {
		return ""
	}
	return target.AuditID
}

// isVerifyNotFound reports whether an error means "the record is absent", across
// the three vocabularies the store joins.
func isVerifyNotFound(err error) bool {
	return errors.Is(err, verify.ErrNotFound) ||
		errors.Is(err, agent.ErrNotFound) ||
		errors.Is(err, storage.ErrNotFound)
}

// mergeLimitations deduplicates two caveat lists, keeping the first list's order so
// the standard statements stay at the front, and caps the result.
func mergeLimitations(primary, extra []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(primary)+len(extra))
	for _, list := range [][]string{primary, extra} {
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			out = append(out, item)
			if len(out) >= maxPlanLimitations {
				return out
			}
		}
	}
	return out
}
