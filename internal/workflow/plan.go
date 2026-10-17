package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

const CompilerVersion = "1.0.0"

type CompileRequest struct {
	APIVersion        string   `json:"api_version"`
	SnapshotID        string   `json:"snapshot_id"`
	Inputs            []string `json:"inputs"`
	Language          string   `json:"language"`
	KnowledgeRevision string   `json:"knowledge_revision,omitempty"`
	MaxInputBytes     int64    `json:"max_input_bytes,omitempty"`
}
type KnowledgePin struct {
	Revision string `json:"revision"`
	Digest   string `json:"digest"`
}
type PlanBody struct {
	APIVersion      string         `json:"api_version"`
	CompilerVersion string         `json:"compiler_version"`
	Scope           artifact.Scope `json:"scope"`
	Workflow        Record         `json:"workflow"`
	Inputs          []artifact.Ref `json:"inputs"`
	Language        string         `json:"language"`
	Knowledge       KnowledgePin   `json:"knowledge"`
	MaxInputBytes   int64          `json:"max_input_bytes"`
	Nodes           []CompiledNode `json:"nodes"`
}
type Plan struct {
	PlanBody
	ID        string    `json:"plan_id"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
}
type PlanRepository interface {
	ListWorkflowPlans(context.Context, string, string, string, int) ([]Plan, error)
	PutWorkflowPlan(context.Context, Plan) (Plan, error)
	GetWorkflowPlan(context.Context, string, string) (Plan, error)
}
type Scopes interface {
	ArtifactScope(context.Context, string, string) (artifact.Scope, error)
}
type Knowledge interface {
	KnowledgeHead(context.Context, publication.Scope) (string, error)
	GetKnowledgeRevision(context.Context, publication.Scope, string) (publication.RevisionDocument, error)
}
type ValidationError struct {
	Diagnostics []Diagnostic `json:"diagnostics"`
}

func (e *ValidationError) Error() string { return ErrInvalid.Error() }
func (e *ValidationError) Unwrap() error { return ErrInvalid }
func invalid(path, code, message string) error {
	return &ValidationError{[]Diagnostic{{path, code, message}}}
}

// Compile verifies roots and fixes every version. It never invokes a plugin.
func (c *Compiler) Compile(ctx context.Context, project, id, version string, req CompileRequest) (Plan, error) {
	if req.APIVersion != "codexploit/v1" {
		return Plan{}, invalid("/api_version", "schema", "Expected codexploit/v1")
	}
	if req.MaxInputBytes == 0 {
		req.MaxInputBytes = 64 << 20
	}
	if req.MaxInputBytes < 1 || req.MaxInputBytes > 256<<20 {
		return Plan{}, invalid("/max_input_bytes", "budget", "Input budget must be 1–268435456 bytes")
	}
	record, err := c.Workflows.Get(ctx, project, id, version)
	if err != nil {
		return Plan{}, err
	}
	raw, _ := json.Marshal(record.Spec)
	validation, err := c.Validate(ctx, raw)
	if err != nil {
		return Plan{}, err
	}
	if !validation.Valid {
		return Plan{}, &ValidationError{validation.Diagnostics}
	}
	scope, err := c.Scopes.ArtifactScope(ctx, project, req.SnapshotID)
	if err != nil {
		return Plan{}, ErrNotFound
	}
	if req.Language == "" || len(req.Language) > 100 {
		return Plan{}, invalid("/language", "language", "Declare the language for this plan")
	}
	for _, node := range validation.Nodes {
		i := 0
		for position, candidate := range record.Spec.Nodes {
			if candidate.ID == node.ID {
				i = position
				break
			}
		}
		supported := false
		for _, lang := range node.Plugin.Manifest.Languages {
			if lang == req.Language || lang == "*" {
				supported = true
			}
		}
		if !supported {
			return Plan{}, invalid(fmt.Sprintf("/nodes/%d/plugin_version", i), "language", "Plugin does not support the declared language")
		}
	}
	if len(req.Inputs) > len(record.Spec.Inputs) {
		return Plan{}, invalid("/inputs", "ambiguous_input", "Provide exactly one artifact for each declared root type")
	}
	roots := map[string]artifact.Ref{}
	var total int64
	for i, id := range req.Inputs {
		ref, err := c.Artifacts.Stat(ctx, scope, id, req.MaxInputBytes-total)
		if err != nil {
			return Plan{}, invalid(fmt.Sprintf("/inputs/%d", i), "input_unavailable", "Root artifact is missing, corrupt, outside scope or exceeds the input budget")
		}
		total += ref.Bytes
		if total > req.MaxInputBytes {
			return Plan{}, invalid("/inputs", "budget", "Root artifacts exceed the input budget")
		}
		allowed := false
		for _, kind := range record.Spec.Inputs {
			if kind == ref.Kind {
				allowed = true
			}
		}
		if !allowed {
			return Plan{}, invalid(fmt.Sprintf("/inputs/%d", i), "input_type", "Artifact kind is not a declared root input")
		}
		if _, ok := roots[ref.Kind]; ok {
			return Plan{}, invalid("/inputs", "ambiguous_input", "Multiple artifacts have the same root type")
		}
		roots[ref.Kind] = ref
	}
	inputs := make([]artifact.Ref, 0, len(record.Spec.Inputs))
	for _, kind := range record.Spec.Inputs {
		ref, ok := roots[kind]
		if !ok {
			return Plan{}, invalid("/inputs", "missing_input", "No artifact supplied for "+kind)
		}
		inputs = append(inputs, ref)
	}
	for _, node := range validation.Nodes {
		for _, binding := range node.Inputs {
			if binding.Source != "root" {
				continue
			}
			ref := roots[binding.Kind]
			if ref.SchemaID != binding.SchemaID || (binding.ProducerPlugin != "" && ref.Producer.PluginID != binding.ProducerPlugin) {
				return Plan{}, invalid("/inputs", "input_schema", "Root artifact schema or producer is incompatible with the installed adapter")
			}
		}
	}
	knowledgeScope := publication.Scope{ProjectID: project, SnapshotID: scope.SnapshotID}
	revision := req.KnowledgeRevision
	if revision == "" || revision == "latest" {
		revision, err = c.Knowledge.KnowledgeHead(ctx, knowledgeScope)
		if err != nil {
			return Plan{}, ErrNotFound
		}
	}
	pin := KnowledgePin{Revision: revision, Digest: Digest([]byte("rev-0"))}
	if revision != "rev-0" {
		doc, err := c.Knowledge.GetKnowledgeRevision(ctx, knowledgeScope, revision)
		if err != nil {
			return Plan{}, invalid("/knowledge_revision", "revision_missing", "Knowledge revision is not available in this snapshot")
		}
		pin.Digest = doc.Revision.Digest
	}
	body := PlanBody{APIVersion: "codexploit/v1", CompilerVersion: CompilerVersion, Scope: scope, Workflow: record, Inputs: inputs, Language: req.Language, Knowledge: pin, MaxInputBytes: req.MaxInputBytes, Nodes: validation.Nodes}
	canonical, err := json.Marshal(body)
	if err != nil {
		return Plan{}, err
	}
	digest := Digest(canonical)
	return c.Plans.PutWorkflowPlan(ctx, Plan{PlanBody: body, ID: "plan-" + digest[:32], Digest: digest, CreatedAt: time.Now().UTC()})
}
func (c *Compiler) Get(ctx context.Context, project, id string) (Plan, error) {
	return c.Plans.GetWorkflowPlan(ctx, project, id)
}

func (c *Compiler) ListPlans(ctx context.Context, project, snapshot, cursor string, limit int) ([]Plan, error) {
	if limit < 1 || limit > 100 || len(cursor) > 100 {
		return nil, ErrInvalid
	}
	if _, err := c.Scopes.ArtifactScope(ctx, project, snapshot); err != nil {
		return nil, ErrNotFound
	}
	return c.Plans.ListWorkflowPlans(ctx, project, snapshot, cursor, limit)
}
