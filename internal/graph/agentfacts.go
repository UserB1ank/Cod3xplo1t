package graph

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// AgentFacts builds the task an audit agent receives, and the bounded code slice
// inside it.
//
// It lives in the query layer, not in internal/agent, for the same reason the ASG
// and path adapters do: the storage layer implements agent.Store, so
// `agent → graph → storage → agent` would be an import cycle. This package may
// import agent and path; neither may import this one.
type AgentFacts struct {
	Graph *Service
	ASG   *ASGService
	// Build carries the task bounds. Normalize is applied at construction and
	// again on use, so a struct literal cannot smuggle a zero bound in.
	Build agent.BuildOptions
	// Now is injectable so a replayed build produces the same timestamp.
	Now func() time.Time
	// MaxSectionRunes bounds one section's content. Content is cut on a rune
	// boundary when it hits the cap; zero means defaultMaxSliceRunes. It is a field
	// and not a constant because it is the only cap small enough to unit-test with
	// a readable fixture.
	MaxSectionRunes int
}

// Caps on what a task carries forward. They are declared here because they bound
// one agent's context, not the graph's storage.
const (
	// maxTaskLimitations bounds the whole limitation list: a task that restates
	// every caveat of every upstream layer spends the run's budget on caveats.
	maxTaskLimitations = 12
	// maxASGLimitations bounds how many attack-surface statements are copied. The
	// first ones are the most structural ones, and the rest are enumerations.
	maxASGLimitations = 5
	// defaultMaxSliceRunes bounds one section's content. A single minified line can
	// be a megabyte; the line budget alone does not bound the text.
	defaultMaxSliceRunes = 4000
	// maxSkipNoteChars bounds how much of one resolution failure is quoted.
	maxSkipNoteChars = 240
)

// standardTaskLimitations are the statements every task carries regardless of the
// snapshot: they are properties of this phase, not of one graph. They are worded
// so a reader can match them against the design's confidence model.
var standardTaskLimitations = []string{
	"a path is call-graph reachability, not dataflow: the graph never establishes that data from an input reaches the sensitive operation",
	"a control's presence on a path is not its effectiveness: a PROTECTED_BY fact records registration or reachability only, and bypass branches are not analysed",
}

// NewAgentFacts builds the task builder over the two graph services.
func NewAgentFacts(g *Service, a *ASGService, opts agent.BuildOptions) *AgentFacts {
	return &AgentFacts{
		Graph: g,
		ASG:   a,
		Build: opts.Normalize(),
		Now:   func() time.Time { return time.Now().UTC() },
	}
}

func (f *AgentFacts) now() time.Time {
	if f == nil || f.Now == nil {
		return time.Now().UTC()
	}
	return f.Now().UTC()
}

// build normalizes on every use: a caller that built the struct literal instead of
// calling the constructor must get the same bounds as one that did not.
func (f *AgentFacts) build() agent.BuildOptions { return f.Build.Normalize() }

func (f *AgentFacts) maxSectionRunes() int {
	if f != nil && f.MaxSectionRunes > 0 {
		return f.MaxSectionRunes
	}
	return defaultMaxSliceRunes
}

// CodeSlice returns the bounded source of one path.
//
// A symbol it cannot resolve is skipped and reported, never fatal: a path's SCG
// refs mix symbol ids with call-site and edge ids, the tree of an old snapshot may
// be gone, and one bad id must not cost the agent the sections that do resolve.
func (f *AgentFacts) CodeSlice(ctx context.Context, req agent.SliceRequest) ([]agent.SliceSection, error) {
	if f == nil || f.Graph == nil {
		return nil, errors.New("graph: agent facts have no source graph service")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.SnapshotID) == "" {
		return nil, fmt.Errorf("%w: snapshot id is required to build a code slice", ErrInvalidArgument)
	}
	build := f.build()
	maxLines := req.MaxLines
	if maxLines <= 0 {
		maxLines = build.MaxSliceLines
	}
	maxSections := req.MaxSections
	if maxSections <= 0 {
		maxSections = build.MaxSliceSections
	}
	if maxLines <= 0 || maxSections <= 0 {
		return []agent.SliceSection{}, nil
	}

	// Files restricts the slice to the files the path touches. An empty list means
	// "no restriction", exactly as it does for the graph service, and the file of a
	// symbol that was explicitly requested is always allowed: the symbol is part of
	// the path whether or not a call step named its file.
	restrictFiles := false
	allowedFiles := map[string]bool{}
	for _, file := range req.Files {
		if file = strings.TrimSpace(file); file != "" {
			restrictFiles = true
			allowedFiles[file] = true
		}
	}

	out := make([]agent.SliceSection, 0, min(maxSections, len(req.SymbolIDs)+1))
	windows := make([]sliceWindow, 0, len(req.SymbolIDs))
	seen := map[string]bool{}
	usedLines := 0
	var skipped []string

	for _, raw := range req.SymbolIDs {
		if len(out) >= maxSections || usedLines >= maxLines {
			break
		}
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The task's slice is the declarations of the path's symbols, and nothing
		// more: caller and call-site windows would spend the section budget on
		// context the agent can request explicitly with the get_code_slice tool,
		// whose bounds it can see and choose.
		slice, err := f.Graph.Slice(ctx, req.SnapshotID, SliceRequest{
			SymbolID:    id,
			Include:     SectionDeclaration,
			MaxLines:    maxLines - usedLines,
			MaxSections: maxSections - len(out),
			Options:     Options{},
		})
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			skipped = append(skipped, sliceSkipReason(id, err))
			continue
		}
		if restrictFiles && slice.Root.File != "" {
			allowedFiles[slice.Root.File] = true
		}
		for _, section := range slice.Sections {
			if len(out) >= maxSections || usedLines >= maxLines {
				break
			}
			if restrictFiles && !allowedFiles[section.File] {
				continue
			}
			if coveredByWindow(windows, section.File, section.StartLine, section.EndLine) {
				continue
			}
			total := len(section.Lines)
			remaining := maxLines - usedLines
			cut := total > remaining
			lines := section.Lines
			if cut {
				lines = lines[:remaining]
			}
			content, runeCut := cutRunes(strings.Join(lines, "\n"), f.maxSectionRunes())
			endLine := section.StartLine + len(lines) - 1
			if len(lines) == 0 {
				endLine = section.StartLine
			}
			reason := section.Reason
			if reason == "" {
				reason = SectionDeclaration
			}
			var notes []string
			// A cut is reported from either side: the service cuts the window at the
			// budget this call passed it, and the guard below repeats the cut if a
			// service ever returns more than it was asked for. Both mean the same
			// thing to the agent, so both read the same way.
			if cut || section.Truncated {
				notes = append(notes, fmt.Sprintf("truncated to %d of %d line(s) by the task line budget of %d",
					len(lines), total, maxLines))
			}
			if runeCut {
				notes = append(notes, fmt.Sprintf("content cut after %d rune(s) on a rune boundary by the content cap", utf8.RuneCountInString(content)))
			}
			if len(notes) > 0 {
				reason += " [" + strings.Join(notes, "; ") + "]"
			}
			out = append(out, agent.SliceSection{
				File:      section.File,
				Symbol:    section.Symbol,
				StartLine: section.StartLine,
				EndLine:   endLine,
				Reason:    reason,
				Content:   content,
			})
			usedLines += len(lines)
			windows = append(windows, sliceWindow{file: section.File, start: section.StartLine, end: endLine})
			if cut {
				break
			}
		}
	}

	// The skips are reported in one section of their own so a skip cannot crowd out
	// the source the agent is supposed to read, and so "no slice" and "the slice was
	// empty" stay distinguishable.
	if len(skipped) > 0 && len(out) < maxSections {
		out = append(out, agent.SliceSection{Reason: "unresolved symbol(s) skipped: " + strings.Join(skipped, "; ")})
	}
	return out, nil
}

// TaskLimitations merges the upstream coverage statements a task must carry: how
// much of the call graph resolved, what the attack surface says about itself, and
// the two properties of this phase that no snapshot changes.
//
// A summary that cannot be read degrades into a limitation instead of an error:
// failing the run would hide the very fact the agent needs to know.
func (f *AgentFacts) TaskLimitations(ctx context.Context, snapshotID string) ([]string, error) {
	if f == nil {
		return nil, errors.New("graph: agent facts are not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(snapshotID) == "" {
		return nil, fmt.Errorf("%w: snapshot id is required to collect task limitations", ErrInvalidArgument)
	}
	out := make([]string, 0, maxTaskLimitations)
	out = append(out, standardTaskLimitations...)

	if f.Graph == nil {
		out = append(out, "the source graph service is not configured, so this task carries no call-graph coverage statement")
	} else if summary, err := f.Graph.Summary(ctx, snapshotID); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		out = append(out, "the call-graph summary could not be read ("+capRunes(err.Error(), maxSkipNoteChars)+
			"); the resolution mix behind this task is unknown")
	} else {
		out = append(out, resolutionLimitation(summary.Resolution))
	}

	if f.ASG == nil {
		out = append(out, "the attack-surface service is not configured, so this task carries no attack-surface coverage statement")
	} else if summary, err := f.ASG.Summary(ctx, snapshotID); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		out = append(out, "the attack-surface summary could not be read ("+capRunes(err.Error(), maxSkipNoteChars)+
			"); the facts behind this task cannot be qualified")
	} else {
		for i, limitation := range summary.Limitations {
			if i >= maxASGLimitations {
				break
			}
			out = append(out, limitation)
		}
	}
	return boundLimitations(out), nil
}

// resolutionLimitation states the call graph's resolution mix as one sentence with
// its numbers. A task that does not say how much of the graph resolved invites an
// agent to read a missing edge as an absent call.
//
// Resolved and builtin call sites are accounted for; the rest are the blind spots
// and are added up as "unresolved" so the sentence has one number to act on.
func resolutionLimitation(r scg.ResolutionCounts) string {
	resolved := r.Resolved + r.ResolvedBestEffort
	unresolved := r.Ambiguous + r.Dynamic + r.External + r.Unsupported
	total := resolved + unresolved + r.Builtin
	return fmt.Sprintf(
		"the call graph resolved %d of %d call site(s) and left %d unresolved (ambiguous %d, dynamic %d, external %d, unsupported %d); no call edge is recorded for an unresolved call site, so reachability through it is unknown",
		resolved, total, unresolved, r.Ambiguous, r.Dynamic, r.External, r.Unsupported)
}

// boundLimitations sorts, de-duplicates and caps the list. Sorting makes the task
// byte-identical between two builds of the same path, which is what lets a stored
// task be compared with a rebuilt one.
func boundLimitations(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > maxTaskLimitations {
		out = out[:maxTaskLimitations]
	}
	return out
}

// BuildTask assembles the whole task from a claimed path.
//
// Every field the orchestrator hands an adapter is filled here, and the task is
// validated before it leaves: a builder that can emit a task ValidateTask rejects
// would turn a wiring bug into a run that fails after its lease was taken.
func (f *AgentFacts) BuildTask(ctx context.Context, p path.Path, policy agent.ExplorationPolicy) (agent.Task, error) {
	if f == nil {
		return agent.Task{}, errors.New("graph: agent facts are not configured")
	}
	if err := ctx.Err(); err != nil {
		return agent.Task{}, err
	}
	if strings.TrimSpace(p.ID) == "" {
		return agent.Task{}, fmt.Errorf("%w: the path to build a task for has no id", ErrInvalidArgument)
	}
	if strings.TrimSpace(p.SnapshotID) == "" {
		return agent.Task{}, fmt.Errorf("%w: path %s has no snapshot id", ErrInvalidArgument, p.ID)
	}
	build := f.build()

	// The policy arrives from the orchestrator, but the allowlist is the builder's:
	// the list advertised to the agent has to be the list the registry can execute
	// and the gate will enforce.
	policy = policy.Normalize()
	policy.AllowedTools = append([]string(nil), build.AllowedTools...)
	policy = policy.Normalize()

	symbolIDs, files := pathSliceSelectors(p)
	sections, err := f.CodeSlice(ctx, agent.SliceRequest{
		SnapshotID:  p.SnapshotID,
		PathID:      p.ID,
		SymbolIDs:   symbolIDs,
		Files:       files,
		MaxLines:    build.MaxSliceLines,
		MaxSections: build.MaxSliceSections,
	})
	if err != nil {
		return agent.Task{}, fmt.Errorf("graph: build the code slice of path %s: %w", p.ID, err)
	}
	evidence, err := f.evidenceRefs(ctx, p, build.MaxEvidenceRefs)
	if err != nil {
		return agent.Task{}, fmt.Errorf("graph: build the evidence refs of path %s: %w", p.ID, err)
	}
	limitations, err := f.TaskLimitations(ctx, p.SnapshotID)
	if err != nil {
		return agent.Task{}, fmt.Errorf("graph: collect the limitations of path %s: %w", p.ID, err)
	}

	task := agent.Task{
		SchemaVersion:       agent.SchemaVersion,
		SnapshotID:          p.SnapshotID,
		PathID:              p.ID,
		AuditID:             p.AuditID,
		SecurityGoal:        securityGoal(p),
		PathSummary:         pathSummary(p),
		SourceSinkRefs:      sourceSinkRefs(p),
		MinimalCodeSlice:    sections,
		EvidenceRefs:        evidence,
		UnresolvedQuestions: copyStrings(p.OpenQuestions),
		Exploration:         policy,
		Budget:              agent.Budget{TimeoutSeconds: policy.TimeoutSeconds, TokenBudget: policy.TokenBudget},
		Limitations:         limitations,
		CreatedAt:           agent.NowString(f.now()),
	}
	if store, ok := f.Graph.Store.(storage.FullStore); ok {
		known, _, err := store.ListFindings(verify.FindingQuery{SnapshotID: p.SnapshotID, Limit: 40})
		if err != nil {
			return agent.Task{}, fmt.Errorf("graph: shared findings: %w", err)
		}
		for _, finding := range known {
			if finding.AuditID == p.AuditID {
				continue
			}
			title := []rune(finding.Title)
			if len(title) > 500 {
				title = title[:500]
			}
			task.PriorFindings = append(task.PriorFindings, agent.PriorFinding{
				FindingID: finding.ID, AuditID: finding.AuditID, Title: string(title),
				Status: string(finding.Status), Severity: verify.NormalizeSeverity(finding.Severity),
				SupportingEvidenceIDs:    append([]string(nil), finding.Supporting[:min(8, len(finding.Supporting))]...),
				ContradictingEvidenceIDs: append([]string(nil), finding.Contradicting[:min(8, len(finding.Contradicting))]...),
				InconclusiveEvidenceIDs:  append([]string(nil), finding.Inconclusive[:min(8, len(finding.Inconclusive))]...),
			})
			if len(task.PriorFindings) == 20 {
				break
			}
		}
	}
	if task.MinimalCodeSlice == nil {
		task.MinimalCodeSlice = []agent.SliceSection{}
	}
	if task.EvidenceRefs == nil {
		task.EvidenceRefs = []agent.EvidenceRef{}
	}
	if task.UnresolvedQuestions == nil {
		task.UnresolvedQuestions = []string{}
	}
	if err := agent.ValidateTask(task); err != nil {
		return agent.Task{}, fmt.Errorf("graph: the task built for path %s is not deliverable: %w", p.ID, err)
	}
	return task, nil
}

// sourceSinkRefs copies the ends of the path and everything the path cites.
func sourceSinkRefs(p path.Path) agent.SourceSinkRefs {
	return agent.SourceSinkRefs{
		EntryNodeID:   p.EntryNodeID,
		EntrySubject:  p.EntrySubject,
		TargetNodeID:  p.TargetNodeID,
		TargetSubject: p.TargetSubject,
		Inputs:        copyStrings(p.Inputs),
		Controls:      copyStrings(p.Controls),
		Assets:        copyStrings(p.Assets),
		Boundaries:    copyStrings(p.Boundaries),
		SCGRefs:       copyStrings(p.SCGRefs),
		ASGRefs:       copyStrings(p.ASGRefs),
	}
}

// securityGoal states what the run is for: the path's objectives when it has any,
// and a goal derived from the two ends when it does not. ValidateTask rejects an
// empty goal, and a path is always worth one sentence about its ends.
func securityGoal(p path.Path) string {
	if objectives := dedupeStrings(p.Objectives); len(objectives) > 0 {
		return strings.Join(objectives, "; ")
	}
	return fmt.Sprintf("establish whether attacker-controlled input reaches the sensitive operation %s from the entry point %s",
		firstNonEmpty(p.TargetSubject, p.TargetNodeID),
		firstNonEmpty(p.EntrySubject, p.EntryNodeID))
}

// pathSummary renders the path as one sentence a model can read without resolving
// ids. Every id has a subject fallback, so the sentence never contains an empty
// slot.
func pathSummary(p path.Path) string {
	boundaries := "none recorded"
	if len(p.Boundaries) > 0 {
		boundaries = strings.Join(p.Boundaries, ", ")
	}
	status := firstNonEmpty(string(p.PathStatus), string(p.Status), "unrecorded")
	return fmt.Sprintf("entry point %s reaches sensitive operation %s over %d hop(s); path status %s; trust boundaries: %s",
		firstNonEmpty(p.EntrySubject, p.EntryNodeID),
		firstNonEmpty(p.TargetSubject, p.TargetNodeID),
		p.Depth, status, boundaries)
}

// pathSliceSelectors picks the symbols the slice should read: the symbol ids of
// the path's SCG refs and of its resolved call steps, plus the files those call
// steps touch.
//
// The refs are filtered by the "sym-" prefix rather than passed whole because a
// path's SCG refs also name call sites and edges, and asking the slice service for
// a call-site id would only produce a skip notice. The prefix convention is the
// same one the ASG reader already relies on.
func pathSliceSelectors(p path.Path) (symbols, files []string) {
	for _, ref := range p.SCGRefs {
		if strings.HasPrefix(ref, "sym-") {
			symbols = append(symbols, ref)
		}
	}
	for _, step := range p.Steps {
		if step.Layer != "scg" {
			continue
		}
		for _, id := range []string{step.From, step.To} {
			if strings.HasPrefix(id, "sym-") {
				symbols = append(symbols, id)
			}
		}
		if file := strings.TrimSpace(step.File); file != "" {
			files = append(files, file)
		}
	}
	return dedupeStrings(symbols), dedupeStrings(files)
}

// evidenceRefs turns the path's cited facts into the evidence a task arrives with.
//
// The two ends come first so they survive the bound, and a ref that cannot be
// resolved is kept by id rather than dropped: dropping it would hide evidence. No
// location is ever invented — File and Line are filled only from a resolved node,
// symbol or call site.
func (f *AgentFacts) evidenceRefs(ctx context.Context, p path.Path, max int) ([]agent.EvidenceRef, error) {
	if max <= 0 {
		max = agent.DefaultBuildOptions().MaxEvidenceRefs
	}
	out := make([]agent.EvidenceRef, 0, max)
	seen := map[string]bool{}
	add := func(ref agent.EvidenceRef) {
		if ref.ID == "" || seen[ref.ID] || len(out) >= max {
			return
		}
		seen[ref.ID] = true
		out = append(out, ref)
	}
	addEnd := func(id, subject string) error {
		ref, ok, err := f.asgEvidence(ctx, p.SnapshotID, id)
		if err != nil {
			return err
		}
		if ok {
			add(ref)
			return nil
		}
		// The node could not be resolved, but the path still names it: keeping the
		// id is honest, inventing a location would not be.
		add(agent.EvidenceRef{Kind: agent.EvidenceStatic, ID: id, Summary: firstNonEmpty(subject, id)})
		return nil
	}
	if err := addEnd(p.EntryNodeID, p.EntrySubject); err != nil {
		return nil, err
	}
	if err := addEnd(p.TargetNodeID, p.TargetSubject); err != nil {
		return nil, err
	}
	for _, id := range p.ASGRefs {
		ref, ok, err := f.asgEvidence(ctx, p.SnapshotID, id)
		if err != nil {
			return nil, err
		}
		if ok {
			add(ref)
		}
	}
	for _, id := range p.SCGRefs {
		ref, ok, err := f.scgEvidence(ctx, p.SnapshotID, id)
		if err != nil {
			return nil, err
		}
		if ok {
			add(ref)
		}
	}
	return out, nil
}

// asgEvidence resolves one attack-surface node. A node of another snapshot, or a
// snapshot without an attack surface, is "not resolvable" and not an error: the
// caller falls back to the id.
func (f *AgentFacts) asgEvidence(ctx context.Context, snapshotID, nodeID string) (agent.EvidenceRef, bool, error) {
	if f == nil || f.ASG == nil || strings.TrimSpace(nodeID) == "" {
		return agent.EvidenceRef{}, false, nil
	}
	view, err := f.ASG.Node(ctx, snapshotID, nodeID)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return agent.EvidenceRef{}, false, cerr
		}
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, ErrNoASG) {
			return agent.EvidenceRef{}, false, nil
		}
		return agent.EvidenceRef{}, false, err
	}
	return agent.EvidenceRef{
		Kind:    agent.EvidenceStatic,
		ID:      nodeID,
		Summary: firstNonEmpty(view.Node.Subject, view.Node.Label, nodeID),
		File:    view.Node.File,
		Line:    view.Node.Line,
	}, true, nil
}

// scgEvidence resolves one source-graph reference: a symbol, a call site, or an
// edge the path crosses. An unclassified reference is reported by id.
func (f *AgentFacts) scgEvidence(ctx context.Context, snapshotID, refID string) (agent.EvidenceRef, bool, error) {
	refID = strings.TrimSpace(refID)
	if refID == "" {
		return agent.EvidenceRef{}, false, nil
	}
	if f.Graph == nil {
		return agent.EvidenceRef{Kind: agent.EvidenceStatic, ID: refID, Summary: refID}, true, nil
	}
	switch {
	case strings.HasPrefix(refID, "sym-"):
		sym, _, err := f.Graph.Symbol(ctx, snapshotID, refID, Options{})
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return agent.EvidenceRef{}, false, cerr
			}
			if errors.Is(err, storage.ErrNotFound) {
				return agent.EvidenceRef{}, false, nil
			}
			return agent.EvidenceRef{}, false, err
		}
		return agent.EvidenceRef{
			Kind: agent.EvidenceSource, ID: refID,
			Summary: firstNonEmpty(sym.QualifiedName, refID),
			File:    sym.File, Line: sym.StartLine,
		}, true, nil
	case strings.HasPrefix(refID, "cs-"):
		site, err := f.Graph.GetCallSite(ctx, snapshotID, refID)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return agent.EvidenceRef{}, false, cerr
			}
			if errors.Is(err, storage.ErrNotFound) {
				return agent.EvidenceRef{}, false, nil
			}
			return agent.EvidenceRef{}, false, err
		}
		summary := "call site"
		if strings.TrimSpace(site.CalleeText) != "" {
			summary = "call to " + site.CalleeText
		}
		if site.Resolution != "" {
			summary += " (" + string(site.Resolution) + ")"
		}
		return agent.EvidenceRef{
			Kind: agent.EvidenceSource, ID: refID, Summary: summary,
			File: site.File, Line: site.Line,
		}, true, nil
	default:
		return agent.EvidenceRef{Kind: agent.EvidenceStatic, ID: refID, Summary: refID}, true, nil
	}
}

// sliceWindow is one emitted file window, kept so a second symbol cannot repeat
// source that was already handed to the agent.
type sliceWindow struct {
	file       string
	start, end int
}

func coveredByWindow(windows []sliceWindow, file string, start, end int) bool {
	for _, w := range windows {
		if w.file == file && w.start <= start && end <= w.end {
			return true
		}
	}
	return false
}

// sliceSkipReason explains why one symbol produced no section. A missing row and a
// missing tree mean different things to the agent, so they read differently.
func sliceSkipReason(id string, err error) string {
	reason := capRunes(err.Error(), maxSkipNoteChars)
	if errors.Is(err, storage.ErrNotFound) {
		reason = "not a symbol of this snapshot"
	}
	return id + " (" + reason + ")"
}

// cutRunes cuts content at a rune boundary. Slicing the string by bytes would
// split a multi-byte rune, and the JSON encoder would then replace the halves with
// replacement characters — losing exactly the code the agent asked for.
func cutRunes(content string, limit int) (string, bool) {
	if limit <= 0 || utf8.RuneCountInString(content) <= limit {
		return content, false
	}
	count := 0
	for i := range content {
		if count == limit {
			return content[:i], true
		}
		count++
	}
	return content, false
}

// capRunes bounds a free-text note without splitting a rune.
func capRunes(value string, limit int) string {
	cut, _ := cutRunes(value, limit)
	return cut
}

func copyStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
