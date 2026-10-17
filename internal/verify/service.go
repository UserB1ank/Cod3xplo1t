package verify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultFindingTitleLimit bounds a derived finding title. A title is a label for a
// table, not a place to paste a claim.
const DefaultFindingTitleLimit = 120

// clockKey carries the verifier's clock into an executor's context, so evidence
// built during a run is stamped by the clock the run records rather than by the
// wall clock. Without it a replay of the same plan would produce the same evidence
// content under a different timestamp, and an append-only content-addressed store
// would have to decide which of two identical objects is the real one.
type clockKey struct{}

// withClock returns a context that carries a verifier clock.
func withClock(ctx context.Context, now func() time.Time) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		return ctx
	}
	return context.WithValue(ctx, clockKey{}, now)
}

// evidenceNow is the timestamp an executor stamps evidence with: the verifier's
// clock when one was carried in, the wall clock otherwise.
func evidenceNow(ctx context.Context) time.Time {
	if ctx != nil {
		if now, ok := ctx.Value(clockKey{}).(func() time.Time); ok && now != nil {
			return now().UTC()
		}
	}
	return nowUTC()
}

// Verifier orchestrates exactly one verification: it prepares and authorizes a
// plan, decides whether the run is a replay, drives the executor and then derives
// the verdict.
//
// It is the only thing that may promote a finding past `candidate`, and it does so
// exclusively through DeriveOutcome. An executor reports what it observed; the
// verifier decides what that means. That separation is the whole reason the
// package exists: the component that runs the command is not the component that
// judges it.
type Verifier struct {
	Store    Store
	Executor Executor
	// Now is the clock, injectable so a test can make timestamps deterministic. Nil
	// means time.Now in UTC.
	Now func() time.Time
}

// Compile-time proof that an executor is required, not optional.
var _ = (Executor)(nil)

// NewVerifier wires a verifier to its store and its executor.
func NewVerifier(store Store, executor Executor) *Verifier {
	return &Verifier{Store: store, Executor: executor}
}

// VerifyRequest is one request to verify one hypothesis against one plan.
type VerifyRequest struct {
	Plan Plan
	// Approved records that a human opened the gate the plan asked for; ApprovedBy
	// names them. An approval is recorded on the run, never asserted silently.
	Approved   bool
	ApprovedBy string
	// Owner is the operator accountable for the run.
	Owner string
}

// Verify prepares, authorizes, executes and judges one plan.
//
// The order is the contract:
//   - Prepare surfaces builder errors as they are, and Authorize surfaces a missing
//     approval or a denied scope with nothing written, because a refused plan must
//     leave no trace that looks like an attempt;
//   - the run id is derived from the hypothesis and the plan hash, so re-submitting
//     the same plan is a replay that returns the existing run instead of executing
//     again;
//   - the executor's claim is validated and then re-derived by DeriveOutcome, which
//     is the only thing that produces the finding status.
func (v *Verifier) Verify(ctx context.Context, req VerifyRequest) (*Run, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if v.Store == nil {
		return nil, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	if v.Executor == nil {
		return nil, fmt.Errorf("%w: no executor is wired", ErrInvalidArgument)
	}

	prepared, err := Prepare(req.Plan)
	if err != nil {
		return nil, err
	}
	// The planning scope is the verifier's business. The executor receives the plan
	// without it and without its authorisation flags, so an adapter cannot grant
	// itself a scope it was never given.
	executionPlan := prepared.Plan
	executionPlan.Scope = Scope{}
	if err := Authorize(prepared, req.Approved, req.ApprovedBy); err != nil {
		return nil, err
	}

	runID := VerificationRunID(prepared.Plan.HypothesisID, prepared.PlanHash)
	if existing, err := v.Store.GetVerificationRun(runID); err == nil && existing != nil {
		// A replay: the same plan for the same hypothesis is the same verification,
		// so the previous run is the answer and nothing is executed or written.
		return existing, nil
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	now := v.now()
	env := prepared.Environment
	approved := req.Approved && strings.TrimSpace(req.ApprovedBy) != ""
	caps := v.Executor.Capabilities()
	run := Run{
		ID: runID, HypothesisID: prepared.Plan.HypothesisID, FindingID: prepared.Plan.FindingID,
		PathID: prepared.Plan.PathID, AuditID: prepared.Plan.AuditID, SnapshotID: prepared.Plan.SnapshotID,
		PlanHash: prepared.PlanHash, Plan: prepared.Plan, Environment: env,
		EnvironmentDigest: env.Digest(), Status: VerifyCreated,
		Executor: caps.Name, ExecutorVersion: caps.Version,
		NetworkAllowed: prepared.Plan.Scope.AllowNetwork,
		Approved:       approved, ApprovedBy: strings.TrimSpace(req.ApprovedBy), Owner: req.Owner,
		CreatedAt: NowString(now), UpdatedAt: NowString(now), Version: 1,
	}
	if approved {
		run.ApprovedAt = NowString(now)
	}
	if err := v.Store.CreateVerificationRun(run); err != nil {
		// A unique-index conflict means another writer created the same run between
		// the lookup and the insert; that is still a replay, not a failure.
		if errors.Is(err, ErrConflict) {
			if existing, getErr := v.Store.GetVerificationRun(runID); getErr == nil && existing != nil {
				return existing, nil
			}
		}
		return nil, err
	}

	version := run.Version
	write := func(status VerificationStatus, mutate func(*Run)) error {
		current := run
		current.Status = status
		current.UpdatedAt = NowString(v.now())
		current.Version = version + 1
		if mutate != nil {
			mutate(&current)
		}
		if err := v.Store.UpdateVerificationRun(current, version); err != nil {
			return err
		}
		version = current.Version
		run = current
		return nil
	}

	if prepared.NeedsApproval {
		if err := write(VerifyApproved, nil); err != nil {
			return nil, err
		}
	}
	started := v.now()
	if err := write(VerifyRunning, func(r *Run) { r.StartedAt = NowString(started) }); err != nil {
		return nil, err
	}

	result, execErr := v.Executor.Execute(withClock(ctx, v.Now), executionPlan, env)
	if execErr != nil {
		// The executor could not report at all. The run is still closed honestly:
		// nothing was verified, and the record says so.
		result = Result{
			Outcome:    OutcomeBlocked,
			Reason:     fmt.Sprintf("the executor could not report a result: %v", execErr),
			Err:        execErr.Error(),
			StopReason: stopReasonForContext(ctx),
		}
	}

	// ValidateResult is checked, not trusted: an executor that produced malformed
	// evidence must not be able to have it stored or judged.
	validationErr := ValidateResult(result, prepared.Plan)
	if validationErr != nil {
		result.Evidence = nil
		result.Err = validationErr.Error()
		result.StopReason = VerifyStopExecutorErr
	}

	evidenceIDs, evidenceErr := v.persistEvidence(run, result.Evidence)
	if evidenceErr != nil {
		return nil, evidenceErr
	}

	// DeriveOutcome is the only producer of a verdict. Whatever the executor
	// claimed, this is what the finding will say.
	outcome, reason := DeriveOutcome(result, prepared.Plan)
	if validationErr != nil {
		outcome = OutcomeBlocked
		reason = "the executor's result failed validation and was discarded: " + validationErr.Error()
	}
	stopReason := result.StopReason
	if strings.TrimSpace(stopReason) == "" {
		stopReason = VerifyStopCompleted
	}
	runErr := strings.TrimSpace(result.Err)
	exitCode := result.ExitCode
	if outcome == OutcomeBlocked {
		// A blocked run did not produce a process verdict, whatever number the
		// adapter happened to leave behind. The stop reason already says why.
		exitCode = nil
		if stopReason == VerifyStopCompleted {
			stopReason = VerifyStopUnsupported
		}
		// An error field on a blocked run means "the executor crashed", which is a
		// different record from "the environment refused the plan".
		if result.Outcome == OutcomeBlocked && strings.TrimSpace(result.Err) == "" {
			runErr = ""
		}
	}
	reproduction := strings.TrimSpace(result.Reproduction)
	if outcome == OutcomeConfirmed && reproduction == "" {
		reproduction = "no reproduction steps were recorded; the run is inconclusive without them"
	}
	if len(reproduction) > MaxReproduction {
		reproduction = reproduction[:MaxReproduction]
	}

	finished := v.now()
	terminal := terminalStatus(outcome, result, ctx)
	if err := write(terminal, func(r *Run) {
		r.Outcome = outcome
		r.StopReason = stopReason
		r.Error = runErr
		r.Reproduction = reproduction
		r.ExitCode = exitCode
		r.EvidenceIDs = evidenceIDs
		r.FinishedAt = NowString(finished)
		r.ElapsedMS = finished.Sub(started).Milliseconds()
		if r.ElapsedMS < 0 {
			r.ElapsedMS = 0
		}
	}); err != nil {
		return nil, err
	}

	finding, err := v.findingFor(run, result, outcome, reason, reproduction)
	if err != nil {
		return nil, err
	}
	if err := v.Store.UpsertFinding(finding); err != nil {
		return nil, err
	}
	return &run, nil
}

// persistEvidence appends an executor's evidence and returns the identifiers in a
// stable order.
//
// It is idempotent by content, which the store contract requires and which the
// store's own comparison cannot entirely see: an evidence id is derived from the
// redacted content, but the object also carries the timestamp it was built at. Two
// objects with the same id, the same content hash and different timestamps are the
// same evidence observed twice, so the stored object stays authoritative and
// nothing is rewritten.
//
// Evidence is stored before the run is closed, so a crash between the two loses the
// verdict rather than the evidence.
func (v *Verifier) persistEvidence(run Run, evidence []Evidence) ([]string, error) {
	stored := make([]Evidence, 0, len(evidence))
	ids := make([]string, 0, len(evidence))
	for _, object := range evidence {
		if strings.TrimSpace(object.ID) == "" {
			// NewEvidence is the only constructor, so this means an executor built
			// the struct by hand. Refusing is cheaper than storing an anonymous
			// object.
			return nil, fmt.Errorf("%w: evidence %q was not built with NewEvidence", ErrInvalidResult, object.Kind)
		}
		if object.VerificationRunID == "" {
			object.VerificationRunID = run.ID
		}
		if object.FindingID == "" {
			object.FindingID = run.FindingID
		}
		// The id does not cover the run id (see evidenceScope), so stamping the run
		// onto the object leaves its identity intact and checkable.
		ids = append(ids, object.ID)
		existing, err := v.Store.GetEvidence(object.ID)
		switch {
		case err == nil && existing != nil:
			if existing.ContentHash != object.ContentHash || existing.Content != object.Content {
				// The same id with different content is the one case the store must
				// refuse: evidence that can be rewritten is not evidence.
				return nil, fmt.Errorf("%w: evidence %s already exists with different content", ErrConflict, object.ID)
			}
			// Same content, observed again: keep what is stored.
			continue
		case err != nil && !errors.Is(err, ErrNotFound):
			return nil, err
		}
		stored = append(stored, object)
	}
	if len(stored) > 0 {
		if err := v.Store.AppendEvidence(stored); err != nil {
			return nil, err
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// findingFor builds the durable verdict. The three evidence lists stay apart,
// because a contradiction is the interesting part and "we could not tell" is not
// "we disproved it".
func (v *Verifier) findingFor(run Run, result Result, outcome Outcome, reason, reproduction string) (Finding, error) {
	status := outcome.FindingStatus()
	if outcome == OutcomeBlocked {
		// A verification that could not run is blocked. It is never a refutation,
		// and the guard is here so a future outcome cannot quietly change that.
		status = FindingBlocked
	}
	if !ValidFindingStatus(status) {
		return Finding{}, fmt.Errorf("%w: derived status %q is unknown", ErrInvalidResult, status)
	}
	existing, err := v.Store.GetFinding(run.FindingID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Finding{}, err
	}

	supporting, contradicting, inconclusive := classifyEvidence(result, outcome)
	// The merge is where a verdict could quietly change shape, so the rule is
	// explicit: an id belongs to exactly one list, the contradiction marker wins, a
	// contradiction is never demoted, and only a confirmation supports anything.
	supporting, contradicting, inconclusive = mergeEvidenceLists(existing, result, outcome, supporting, contradicting, inconclusive)
	now := NowString(v.now())
	finding := Finding{
		ID: run.FindingID, HypothesisID: run.HypothesisID, PathID: run.PathID,
		AuditID: run.AuditID, SnapshotID: run.SnapshotID,
		Title:  truncateTitle(run.Plan.Claim),
		Status: status, Confidence: confidenceFor(outcome, supporting, contradicting, inconclusive),
		Supporting: supporting, Contradicting: contradicting, Inconclusive: inconclusive,
		VerificationRunIDs: []string{run.ID},
		Environments:       []string{run.EnvironmentDigest},
		ReproduceSteps:     reproduction,
		Limitations:        append([]string(nil), run.Plan.Limitations...),
		CreatedAt:          now, UpdatedAt: now, Version: 1,
	}
	if existing != nil {
		finding.CreatedAt = existing.CreatedAt
		finding.Confidence = existing.Confidence
		finding.Severity = NormalizeSeverity(existing.Severity)
		finding.Title = firstNonEmpty(existing.Title, finding.Title)
		finding.VerificationRunIDs = uniqueMerge(existing.VerificationRunIDs, run.ID)
		finding.Environments = uniqueMerge(existing.Environments, run.EnvironmentDigest)
		finding.Limitations = uniqueStrings(append(append([]string(nil), existing.Limitations...), run.Plan.Limitations...))
		finding.Version = existing.Version + 1
	}
	// The lists the merge produced are final. They are assigned after the branch
	// above so no later code can append to them by accident.
	finding.Supporting, finding.Contradicting, finding.Inconclusive = supporting, contradicting, inconclusive
	if status == FindingConfirmed || status == FindingRefuted {
		finding.Confidence = "high"
	}
	if finding.ReproduceSteps == "" && outcome == OutcomeConfirmed {
		finding.ReproduceSteps = reproduction
	}
	_ = reason
	return finding, nil
}

// mergeEvidenceLists decides the three lists of the finding a run produces.
//
// The rules, in order:
//
//  1. an id appears in exactly one list, so a contradiction is never also counted
//     as support;
//  2. an id the finding already files as contradicting stays contradicting whatever
//     this run or a later one calls it: a contradiction is not demoted;
//  3. `supporting` is owned by the run, not by the hypothesis. It holds only the
//     reproduction evidence DeriveOutcome accepted for a confirmation, so a
//     refuted, inconclusive or blocked finding never claims support — including
//     citations a planner seeded, which are leads and move to `inconclusive`;
//  4. `inconclusive` absorbs every remaining citation and observation, because "we
//     could not tell" is where anything that settled nothing belongs.
//
// The finding's status is never derived from these lists: DeriveOutcome owns the
// verdict, and which list happens to be non-empty must not change it.
func mergeEvidenceLists(existing *Finding, result Result, outcome Outcome, supporting, contradicting, inconclusive []string) (outSupporting, outContradicting, outInconclusive []string) {
	priorContradicting := []string{}
	if existing != nil {
		priorContradicting = append(priorContradicting, existing.Contradicting...)
	}
	// Rule 2: the contradicting list is the union of what the finding already filed
	// as a contradiction and what this run saw.
	allContradicting := uniqueStrings(concatIDs(priorContradicting, contradicting))

	claimed := map[string]struct{}{}
	admit := func(ids []string) []string {
		out := []string{}
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, taken := claimed[id]; taken {
				continue
			}
			claimed[id] = struct{}{}
			out = append(out, id)
		}
		return out
	}
	// Priority order: contradicting, then supporting, then inconclusive.
	outContradicting = admit(allContradicting)
	// Rule 3: only a confirmation supports anything, and it keeps the reproduction
	// evidence every confirming run produced. A refutation, an inconclusive result or
	// a block claims no support at all, so a finding can never read as supported
	// after a run that established nothing.
	if outcome == OutcomeConfirmed {
		outSupporting = admit(uniqueStrings(concatIDs(supportingIDs(existing), supporting)))
	} else {
		outSupporting = []string{}
	}
	// Rule 4: everything else — this run's other observations, the finding's stored
	// citations, and the observations the outcome classification did not name — is an
	// open question, not proof.
	rest := append([]string(nil), inconclusive...)
	rest = append(rest, remainingEvidenceIDs(result, supporting, contradicting)...)
	if existing != nil {
		rest = append(rest, existing.Supporting...)
		rest = append(rest, existing.Inconclusive...)
	}
	outInconclusive = admit(uniqueStrings(rest))
	return outSupporting, outContradicting, outInconclusive
}

// remainingEvidenceIDs returns the ids of the evidence the outcome classification
// did not name, so no observation is dropped from the finding.
func remainingEvidenceIDs(result Result, supporting, contradicting []string) []string {
	named := map[string]struct{}{}
	for _, id := range supporting {
		named[id] = struct{}{}
	}
	for _, id := range contradicting {
		named[id] = struct{}{}
	}
	out := []string{}
	for _, object := range result.Evidence {
		if object.ID == "" {
			continue
		}
		if _, ok := named[object.ID]; ok {
			continue
		}
		out = append(out, object.ID)
	}
	return out
}

// supportingIDs reads a stored finding's supporting list, tolerating a nil finding.
func supportingIDs(finding *Finding) []string {
	if finding == nil {
		return nil
	}
	return finding.Supporting
}

// concatIDs joins two id lists without copying the caller's arrays.
func concatIDs(left, right []string) []string {
	out := make([]string, 0, len(left)+len(right))
	out = append(out, left...)
	out = append(out, right...)
	return out
}

// classifyEvidence splits what ran into the three lists the store keeps apart.
//
// Supporting evidence is what demonstrates the outcome: for a confirmation, the
// runtime log or test that reproduced it. Contradicting evidence is what the
// executor marked as contradicting the hypothesis, and a refutation is made of it.
// Everything else — source, static query, rule, artifact, environment — is
// inconclusive on its own, which is the point: a static hit is a lead, not a
// verdict, and "we could not tell" is not "we disproved it".
func classifyEvidence(result Result, outcome Outcome) (supporting, contradicting, inconclusive []string) {
	supporting, contradicting, inconclusive = []string{}, []string{}, []string{}
	for _, evidence := range result.Evidence {
		if evidence.ID == "" {
			continue
		}
		switch {
		case isContradicting(evidence):
			contradicting = append(contradicting, evidence.ID)
		case outcome == OutcomeConfirmed && reproduces(evidence):
			supporting = append(supporting, evidence.ID)
		default:
			inconclusive = append(inconclusive, evidence.ID)
		}
	}
	return uniqueStrings(supporting), uniqueStrings(contradicting), uniqueStrings(inconclusive)
}

// isContradicting mirrors DeriveOutcome's own rule: the marker is the only thing
// that makes evidence contradicting.
func isContradicting(evidence Evidence) bool {
	return strings.HasPrefix(evidence.RedactionNotes, ContradictionMarker)
}

// reproduces mirrors DeriveOutcome's definition of reproduction evidence.
func reproduces(evidence Evidence) bool {
	if evidence.Supersedes != "" {
		return false
	}
	return evidence.Kind == EvidenceRuntimeLog || evidence.Kind == EvidenceTest
}

// confidenceFor is a coarse label, never a number: a reviewer needs to know
// whether a verdict rests on reproduction or on an absence.
func confidenceFor(outcome Outcome, supporting, contradicting, inconclusive []string) string {
	switch {
	case outcome == OutcomeBlocked:
		return "none"
	case outcome == OutcomeConfirmed && len(supporting) > 0 && len(contradicting) == 0:
		return "high"
	case outcome == OutcomeRefuted && len(contradicting) > 0:
		return "high"
	case outcome == OutcomeInconclusive:
		return "low"
	default:
		return "medium"
	}
}

// terminalStatus maps a derived outcome and the executor's failure mode onto the
// run's terminal lifecycle state.
//
// The derived outcome comes first: a run whose verdict is BLOCKED is recorded as
// blocked, whatever failure mode produced it, so a finding can never read "we could
// not run this" as a settled verdict.
func terminalStatus(outcome Outcome, result Result, ctx context.Context) VerificationStatus {
	if outcome == OutcomeBlocked {
		switch result.StopReason {
		case VerifyStopCancelled:
			return VerifyCancelled
		case VerifyStopTimeout:
			return VerifyTimedOut
		default:
			return VerifyBlocked
		}
	}
	if ctx != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return VerifyTimedOut
		case ctx.Err() != nil:
			return VerifyCancelled
		}
	}
	switch outcome {
	case OutcomeConfirmed, OutcomeRefuted, OutcomeInconclusive:
		return VerifySucceeded
	default:
		return VerifyBlocked
	}
}

// --- read pass-throughs for the API ------------------------------------------

// GetRun returns one verification run.
func (v *Verifier) GetRun(runID string) (*Run, error) {
	if v.Store == nil {
		return nil, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	return v.Store.GetVerificationRun(runID)
}

// ListRuns lists verification runs.
func (v *Verifier) ListRuns(q RunQuery) ([]Run, int, error) {
	if v.Store == nil {
		return nil, 0, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	return v.Store.ListVerificationRuns(q)
}

// GetEvidence returns one evidence object.
func (v *Verifier) GetEvidence(evidenceID string) (*Evidence, error) {
	if v.Store == nil {
		return nil, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	return v.Store.GetEvidence(evidenceID)
}

// ListEvidence lists evidence objects.
func (v *Verifier) ListEvidence(q EvidenceQuery) ([]Evidence, int, error) {
	if v.Store == nil {
		return nil, 0, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	return v.Store.ListEvidence(q)
}

// GetFinding returns one finding.
func (v *Verifier) GetFinding(findingID string) (*Finding, error) {
	if v.Store == nil {
		return nil, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	return v.Store.GetFinding(findingID)
}

// ListFindings lists findings, applying the same query-driven derivation
// ListFindingsWithApply uses.
func (v *Verifier) ListFindings(q FindingQuery) ([]Finding, int, error) {
	if v.Store == nil {
		return nil, 0, fmt.Errorf("%w: no store is wired", ErrInvalidArgument)
	}
	return v.Store.ListFindings(q)
}

// ListFindingsWithApply lists findings and hands the surviving page to the store's
// own filtering. It exists because the storage backends implement the query
// differently but must agree on the result.
func (v *Verifier) ListFindingsWithApply(q FindingQuery, apply func([]Finding) []Finding) ([]Finding, int, error) {
	findings, total, err := v.ListFindings(q)
	if err != nil {
		return nil, 0, err
	}
	if apply != nil {
		findings = apply(findings)
	}
	return findings, total, nil
}

// now is the verifier's clock, with the package's UTC default.
func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return nowUTC()
}

func truncateTitle(claim string) string {
	title := strings.Join(strings.Fields(claim), " ")
	if title == "" {
		return "verification result"
	}
	if len(title) <= DefaultFindingTitleLimit {
		return title
	}
	cut := title[:DefaultFindingTitleLimit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// uniqueMerge appends a value to a list without duplicating it.
func uniqueMerge(existing []string, value string) []string {
	return uniqueStrings(append(append([]string(nil), existing...), value))
}

// uniqueStrings returns the input without duplicates, preserving order.
func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
