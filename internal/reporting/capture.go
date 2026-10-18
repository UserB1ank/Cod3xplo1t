package reporting

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

var ErrMissingEvidence = errors.New("report: evidence is missing, corrupt or outside scope")
var ErrChanged = errors.New("report: selected data changed during capture; retry")

type Store interface {
	findings.Store
	path.Store
	artifact.Index
	publication.Store
	GetSnapshot(context.Context, string) (*repository.Snapshot, error)
}

type Request struct {
	APIVersion        string        `json:"api_version"`
	SnapshotID        string        `json:"snapshot_id"`
	TaskID            string        `json:"task_id,omitempty"`
	ViewID            string        `json:"view_id"`
	KnowledgeRevision string        `json:"knowledge_revision,omitempty"`
	Format            string        `json:"format"`
	IncludeCandidates bool          `json:"include_candidates"`
	MaxFindings       int           `json:"max_findings,omitempty"`
	MaxPaths          int           `json:"max_paths,omitempty"`
	Budget            plugin.Budget `json:"budget,omitempty"`
}

type Service struct {
	Store     Store
	Knowledge *knowledge.Reader
	Artifacts artifact.Store
	Host      *plugin.Host
}

func (s *Service) Create(ctx context.Context, project string, request Request) (plugin.Invocation, error) {
	if request.APIVersion != "codexploit/v1" || request.ViewID == "" || request.SnapshotID == "" || (request.Format != "md" && request.Format != "json" && request.Format != "sarif") {
		return plugin.Invocation{}, plugin.ErrInvalid
	}
	if request.MaxFindings == 0 {
		request.MaxFindings = 2000
	}
	if request.MaxPaths == 0 {
		request.MaxPaths = 10000
	}
	if request.MaxFindings < 1 || request.MaxFindings > 10000 || request.MaxPaths < 1 || request.MaxPaths > 20000 {
		return plugin.Invocation{}, plugin.ErrInvalid
	}
	if request.Budget.MaxInputBytes == 0 {
		request.Budget.MaxInputBytes = 64 << 20
	}
	if request.Budget.TimeoutSeconds == 0 {
		request.Budget.TimeoutSeconds = 60
	}
	if request.Budget.MaxInputBytes < 1 || request.Budget.MaxInputBytes > 256<<20 || request.Budget.TimeoutSeconds < 1 || request.Budget.TimeoutSeconds > 120 {
		return plugin.Invocation{}, plugin.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(request.Budget.TimeoutSeconds)*time.Second)
	defer cancel()
	scope, err := s.Store.ArtifactScope(ctx, project, request.SnapshotID)
	if err != nil {
		return plugin.Invocation{}, plugin.ErrNotFound
	}
	settings := Settings{Format: request.Format, TaskID: request.TaskID, ViewID: request.ViewID, KnowledgeRevision: request.KnowledgeRevision, IncludeCandidates: request.IncludeCandidates, CapturedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if settings.KnowledgeRevision == "" {
		settings.KnowledgeRevision = "rev-0"
	}
	first, err := s.collect(ctx, scope, settings, request.MaxFindings, request.MaxPaths, request.Budget.MaxInputBytes)
	if err != nil {
		return plugin.Invocation{}, err
	}
	// Compare full versioned inputs across two complete reads. An actively
	// changing ledger is a conflict, never a silently mixed or truncated report.
	second, err := s.collect(ctx, scope, settings, request.MaxFindings, request.MaxPaths, request.Budget.MaxInputBytes)
	if err != nil {
		return plugin.Invocation{}, err
	}
	raw, err := json.Marshal(first)
	if err != nil {
		return plugin.Invocation{}, err
	}
	check, err := json.Marshal(second)
	if err != nil {
		return plugin.Invocation{}, err
	}
	if !bytes.Equal(raw, check) {
		return plugin.Invocation{}, ErrChanged
	}
	if int64(len(raw)) > request.Budget.MaxInputBytes {
		return plugin.Invocation{}, plugin.ErrBudget
	}
	configRaw, _ := json.Marshal(first.Settings)
	var configValue any
	_ = json.Unmarshal(configRaw, &configValue)
	config, _ := json.Marshal(configValue)
	id := "report-" + rand.Text()
	ref := artifact.Ref{ID: "artifact-" + id + "-input", Kind: "discovery.findings", Scope: scope, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Bytes: int64(len(raw)), MediaType: "application/json", SchemaID: InputSchema, Producer: artifact.Producer{PluginID: PluginID, PluginVersion: Version, InvocationID: id, TaskID: request.TaskID, ConfigDigest: fmt.Sprintf("%x", sha256.Sum256(config))}}
	ref, err = s.Artifacts.Put(ctx, ref, bytes.NewReader(raw), request.Budget.MaxInputBytes)
	if err != nil {
		return plugin.Invocation{}, err
	}
	return s.Host.Execute(ctx, plugin.Request{APIVersion: "codexploit/v1", ID: id, PluginID: PluginID, PluginVersion: Version, PackageDigest: packageDigest(), Scope: scope, Inputs: []artifact.Ref{ref}, Config: config, Budget: request.Budget})
}

func (s *Service) collect(ctx context.Context, scope artifact.Scope, settings Settings, maxFindings, maxPaths int, maxBytes int64) (Capture, error) {
	// Bound accumulation before serializing the complete input. The final byte
	// check still accounts for envelope, array and map punctuation exactly.
	var accumulated int64
	take := func(value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		accumulated += int64(len(raw))
		if accumulated > maxBytes {
			return plugin.ErrBudget
		}
		return nil
	}
	view, err := s.Knowledge.Describe(ctx, knowledge.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID}, settings.ViewID)
	if err != nil {
		return Capture{}, err
	}
	snapshot, err := s.Store.GetSnapshot(ctx, scope.SnapshotID)
	if err != nil {
		return Capture{}, err
	}
	capture := Capture{APIVersion: "codexploit/v1", Scope: scope, Commit: snapshot.Commit, Settings: settings, View: view, Tasks: []path.Audit{}, Paths: []path.Path{}, Groups: []Group{}, Evidence: map[string][]verify.Evidence{}, Artifacts: []artifact.Ref{}, Limitations: []string{"Graph versions and the captured finding ledger are separate pins; a historical graph revision does not restore historical verdicts", "Call reachability does not establish taint flow; control presence does not establish effectiveness or ordering"}}
	settings.Counts = map[string]int{"confirmed": 0, "candidate": 0, "refuted": 0, "inconclusive": 0, "blocked": 0, "high": 0, "medium": 0, "low": 0, "ungraded": 0}
	capture.Settings = settings
	revisionProducers := map[artifact.Producer]bool{}
	if settings.KnowledgeRevision != "rev-0" {
		document, err := s.Store.GetKnowledgeRevision(ctx, publication.Scope{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID}, settings.KnowledgeRevision)
		if err != nil {
			return Capture{}, err
		}
		capture.Revision = &document.Revision
		for _, fact := range document.Facts {
			for _, observation := range fact.Observations {
				revisionProducers[observation.Producer] = true
			}
		}
	}
	if settings.TaskID != "" {
		task, err := s.Store.GetAudit(settings.TaskID)
		if err != nil || task.SnapshotID != scope.SnapshotID {
			return Capture{}, plugin.ErrNotFound
		}
		capture.Tasks = append(capture.Tasks, *task)
	} else {
		for offset := 0; ; offset += 500 {
			if err := ctx.Err(); err != nil {
				return Capture{}, err
			}
			tasks, total, err := s.Store.ListAudits(path.AuditQuery{ProjectID: scope.ProjectID, SnapshotID: scope.SnapshotID, Limit: 500, Offset: offset})
			if err != nil {
				return Capture{}, err
			}
			if total > 1000 {
				return Capture{}, plugin.ErrBudget
			}
			capture.Tasks = append(capture.Tasks, tasks...)
			if offset+len(tasks) >= total {
				break
			}
			if len(tasks) == 0 {
				return Capture{}, ErrChanged
			}
		}
	}
	sort.Slice(capture.Tasks, func(i, j int) bool { return capture.Tasks[i].ID < capture.Tasks[j].ID })
	if err := take(capture.Tasks); err != nil {
		return Capture{}, err
	}
	for _, task := range capture.Tasks {
		// Stale tasks remain in the coverage manifest, with their own versions.
		if task.SCGVersion != view.Layers[knowledge.LayerSCG].Version || task.ASGVersion != view.Layers[knowledge.LayerASG].Version {
			capture.Limitations = append(capture.Limitations, "Task "+task.ID+" uses different graph layer versions; its paths retain those original versions")
		}
		for offset := 0; ; offset += 500 {
			if err := ctx.Err(); err != nil {
				return Capture{}, err
			}
			paths, total, err := s.Store.ListPaths(path.PathQuery{AuditID: task.ID, Sort: "path_id", Limit: 500, Offset: offset})
			if err != nil {
				return Capture{}, err
			}
			if total > maxPaths || len(capture.Paths)+len(paths) > maxPaths {
				return Capture{}, plugin.ErrBudget
			}
			if err := take(paths); err != nil {
				return Capture{}, err
			}
			capture.Paths = append(capture.Paths, paths...)
			if offset+len(paths) >= total {
				break
			}
			if len(paths) == 0 {
				return Capture{}, ErrChanged
			}
		}
	}
	service := findings.NewService(s.Store)
	pathIDs := map[string]bool{}
	for _, p := range capture.Paths {
		pathIDs[p.ID] = true
	}
	for offset := 0; ; offset += 1000 {
		page, err := service.List(ctx, findings.ListQuery{ProjectID: scope.ProjectID, TaskID: settings.TaskID, Limit: 1000, Offset: offset})
		if err != nil {
			return Capture{}, err
		}
		if page.Truncated {
			return Capture{}, plugin.ErrBudget
		}
		for _, group := range page.Groups {
			if group.Finding.SnapshotID != scope.SnapshotID || (!settings.IncludeCandidates && group.Finding.Status == verify.FindingCandidate) {
				continue
			}
			if len(capture.Groups) >= maxFindings {
				return Capture{}, plugin.ErrBudget
			}
			item := Group{Finding: group.Finding, Members: group.Members, Fingerprint: group.Fingerprint, FingerprintVersion: group.FingerprintVersion, Observations: group.Observations, SeverityAudit: []findings.SeverityAudit{}}
			item.Finding.Severity = verify.NormalizeSeverity(item.Finding.Severity)
			item.ObservationMembership = map[string]string{}
			for i := range item.Members {
				item.Members[i].Severity = verify.NormalizeSeverity(item.Members[i].Severity)
				member := item.Members[i]
				if member.PathID != "" && !pathIDs[member.PathID] {
					p, err := s.Store.GetPath(member.PathID)
					if err != nil || p.SnapshotID != scope.SnapshotID {
						return Capture{}, ErrMissingEvidence
					}
					if len(capture.Paths) >= maxPaths {
						return Capture{}, plugin.ErrBudget
					}
					capture.Paths = append(capture.Paths, *p)
					if err := take(p); err != nil {
						return Capture{}, err
					}
					pathIDs[p.ID] = true
				}
				audits, err := s.Store.ListFindingSeverityAudits(member.ID)
				if err != nil {
					return Capture{}, err
				}
				item.SeverityAudit = append(item.SeverityAudit, audits...)
				item.Finding.Supporting = union(item.Finding.Supporting, member.Supporting)
				item.Finding.Contradicting = union(item.Finding.Contradicting, member.Contradicting)
				item.Finding.Inconclusive = union(item.Finding.Inconclusive, member.Inconclusive)
			}
			for _, observation := range item.Observations {
				if observation.Scope != scope {
					return Capture{}, ErrMissingEvidence
				}
				item.Finding.Supporting = union(item.Finding.Supporting, observation.EvidenceRefs)
				item.Finding.Limitations = union(item.Finding.Limitations, observation.Limitations)
				membership := "not_selected"
				if capture.Revision != nil {
					membership = "outside_revision"
					if revisionProducers[observation.Producer] {
						membership = "included"
					}
				}
				item.ObservationMembership[observation.ID] = membership
			}
			if (item.Finding.Status == verify.FindingConfirmed && len(item.Finding.Supporting) == 0) || (item.Finding.Status == verify.FindingRefuted && len(item.Finding.Contradicting) == 0) {
				return Capture{}, ErrMissingEvidence
			}
			sort.Slice(item.Members, func(i, j int) bool { return item.Members[i].ID < item.Members[j].ID })
			sort.Slice(item.Observations, func(i, j int) bool { return item.Observations[i].ID < item.Observations[j].ID })
			sort.Slice(item.SeverityAudit, func(i, j int) bool { return item.SeverityAudit[i].ID < item.SeverityAudit[j].ID })
			ids := union(union(item.Finding.Supporting, item.Finding.Contradicting), item.Finding.Inconclusive)
			for _, id := range ids {
				if err := ctx.Err(); err != nil {
					return Capture{}, err
				}
				evidence, err := s.Store.GetEvidence(id)
				if errors.Is(err, verify.ErrNotFound) {
					ref, err := s.Artifacts.Stat(ctx, scope, id, 64<<20)
					if err != nil {
						return Capture{}, ErrMissingEvidence
					}
					capture.Artifacts = append(capture.Artifacts, ref)
					// This is a reference envelope, not a fabricated source quote.
					raw, _ := json.Marshal(ref)
					evidence = &verify.Evidence{ID: id, Kind: verify.EvidenceArtifact, Tool: ref.Producer.PluginID, ToolVersion: ref.Producer.PluginVersion, SnapshotID: scope.SnapshotID, Content: string(raw), ContentHash: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}
				} else if err != nil {
					return Capture{}, err
				}
				if evidence.SnapshotID != scope.SnapshotID || evidence.ContentHash != fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(evidence.Content))) {
					return Capture{}, ErrMissingEvidence
				}
				if err := take(evidence); err != nil {
					return Capture{}, err
				}
				capture.Evidence[item.Finding.ID] = append(capture.Evidence[item.Finding.ID], *evidence)
			}
			if err := take(item); err != nil {
				return Capture{}, err
			}
			capture.Groups = append(capture.Groups, item)
			settings.Counts[string(item.Finding.Status)]++
			grade := item.Finding.Severity
			if grade == "" {
				grade = "ungraded"
			}
			settings.Counts[grade]++
		}
		if offset+len(page.Groups) >= page.Total {
			break
		}
		if len(page.Groups) == 0 {
			return Capture{}, ErrChanged
		}
	}
	sort.Slice(capture.Groups, func(i, j int) bool { return capture.Groups[i].Fingerprint < capture.Groups[j].Fingerprint })
	sort.Slice(capture.Paths, func(i, j int) bool { return capture.Paths[i].ID < capture.Paths[j].ID })
	if _, err := s.Knowledge.Describe(ctx, view.Scope, view.ID); err != nil {
		return Capture{}, err
	}
	return capture, nil
}

func union(a, b []string) []string {
	out := append([]string(nil), a...)
	seen := map[string]bool{}
	for _, value := range out {
		seen[value] = true
	}
	for _, value := range b {
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	sort.Strings(out)
	return out
}
