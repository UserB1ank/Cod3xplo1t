// Package reporting captures real scoped data and renders immutable documents.
package reporting

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

const PluginID = "builtin.reporter"
const Version = "1.0.0"
const InputSchema = "codexploit/report-input/v1"

//go:embed report.go capture.go
var implementation embed.FS

type Settings struct {
	Format            string         `json:"format"`
	TaskID            string         `json:"task_id,omitempty"`
	ViewID            string         `json:"view_id"`
	KnowledgeRevision string         `json:"knowledge_revision"`
	IncludeCandidates bool           `json:"include_candidates"`
	CapturedAt        string         `json:"captured_at"`
	Counts            map[string]int `json:"counts"`
}

type Group struct {
	Finding               verify.Finding           `json:"finding"`
	Members               []verify.Finding         `json:"members"`
	Fingerprint           string                   `json:"fingerprint"`
	FingerprintVersion    string                   `json:"fingerprint_version"`
	ObservationMembership map[string]string        `json:"observation_membership"`
	Observations          []findings.Observation   `json:"observations"`
	SeverityAudit         []findings.SeverityAudit `json:"severity_audit"`
}

type Capture struct {
	Reporter    *Renderer                    `json:"reporter,omitempty"`
	Input       *artifact.Ref                `json:"input,omitempty"`
	APIVersion  string                       `json:"api_version"`
	Scope       artifact.Scope               `json:"scope"`
	Commit      string                       `json:"commit"`
	Settings    Settings                     `json:"selection"`
	View        *knowledge.View              `json:"view"`
	Revision    *publication.Revision        `json:"knowledge_revision,omitempty"`
	Tasks       []path.Audit                 `json:"tasks"`
	Paths       []path.Path                  `json:"paths"`
	Groups      []Group                      `json:"groups"`
	Evidence    map[string][]verify.Evidence `json:"evidence"`
	Artifacts   []artifact.Ref               `json:"artifact_evidence"`
	Limitations []string                     `json:"limitations"`
}

type Renderer struct {
	PluginID      string `json:"plugin_id"`
	Version       string `json:"plugin_version"`
	PackageDigest string `json:"package_digest"`
	InvocationID  string `json:"invocation_id"`
	ConfigDigest  string `json:"config_digest"`
}

func packageDigest() string {
	var raw []byte
	for _, name := range []string{"report.go", "capture.go"} {
		data, _ := implementation.ReadFile(name)
		raw = append(raw, data...)
	}
	raw = append(raw, []byte(plugin.BuiltinPackageDigest()+verify.ReportImplementationDigest()+runtime.Version())...)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func Executor() plugin.Executor {
	manifest := json.RawMessage(`{"api_version":"codexploit/v1","id":"builtin.reporter","version":"1.0.0","name":"Fixed report exporter","description":"Render saved findings and evidence without changing verdicts.","kind":"reporter","languages":["any"],"runtime":{"kind":"builtin"},"consumes":["discovery.findings"],"produces":["report.document"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","properties":{"format":{"enum":["md","json","sarif"]},"task_id":{"type":"string"},"view_id":{"type":"string"},"knowledge_revision":{"type":"string"},"include_candidates":{"type":"boolean"},"captured_at":{"type":"string"},"counts":{"type":"object","additionalProperties":{"type":"integer","minimum":0}}},"required":["format","view_id","knowledge_revision","include_candidates","captured_at","counts"],"additionalProperties":false}}`)
	return plugin.Executor{Manifest: manifest, PackageDigest: packageDigest(), InputSchemas: []string{InputSchema}, Run: render, NativeSchema: "codexploit/report-document/v1", DocumentMediaType: func(inv plugin.Invocation) string {
		var config Settings
		_ = json.Unmarshal(inv.Request.Config, &config)
		if config.Format == "md" {
			return "text/markdown; charset=utf-8"
		}
		if config.Format == "sarif" {
			return "application/sarif+json"
		}
		return "application/json"
	}}
}

func render(ctx context.Context, inv plugin.Invocation, inputs [][]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(inputs) != 1 {
		return nil, plugin.ErrInvalid
	}
	var capture Capture
	var config Settings
	if json.Unmarshal(inputs[0], &capture) != nil || json.Unmarshal(inv.Request.Config, &config) != nil || capture.APIVersion != "codexploit/v1" || capture.Scope != inv.Request.Scope {
		return nil, plugin.ErrInvalid
	}
	a, _ := json.Marshal(config)
	b, _ := json.Marshal(capture.Settings)
	if string(a) != string(b) {
		return nil, plugin.ErrInvalid
	}
	capture.Reporter = &Renderer{PluginID: PluginID, Version: Version, PackageDigest: inv.Request.PackageDigest, InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest}
	capture.Input = &inv.Request.Inputs[0]
	now, err := time.Parse(time.RFC3339Nano, config.CapturedAt)
	if err != nil {
		return nil, plugin.ErrInvalid
	}
	items := make([]verify.Finding, 0, len(capture.Groups))
	for _, group := range capture.Groups {
		items = append(items, group.Finding)
	}
	raw, err := verify.RenderReport(items, capture.Evidence, verify.ReportOptions{Format: config.Format, Title: "Codexploit fixed report", AuditID: config.TaskID, SnapshotID: capture.Scope.SnapshotID, IncludeCandidates: config.IncludeCandidates, MaxFindings: -1, Now: func() time.Time { return now }})
	if err != nil {
		return nil, err
	}
	if config.Format == "md" {
		var summary strings.Builder
		fmt.Fprintf(&summary, "\n## Fixed scope\n\n- project: %s\n- source: %s\n- snapshot: %s\n- commit: %s\n- shared knowledge: %s\n- captured finding ledger: %s\n- candidates included: %t\n- reporter: %s@%s\n- package digest: %s\n- input digest: %s\n", capture.Scope.ProjectID, capture.Scope.SourceID, capture.Scope.SnapshotID, capture.Commit, config.KnowledgeRevision, config.CapturedAt, config.IncludeCandidates, PluginID, Version, inv.Request.PackageDigest, inv.Request.Inputs[0].SHA256)
		summary.WriteString("\n## Coverage and unresolved questions\n\n")
		for _, task := range capture.Tasks {
			coverage, _ := json.Marshal(task.Coverage)
			fmt.Fprintf(&summary, "- task `%s`, SCG `%s`, ASG `%s`: %s\n", task.ID, task.SCGVersion, task.ASGVersion, coverage)
			for _, limitation := range task.Limitations {
				fmt.Fprintf(&summary, "  - %s\n", strings.Join(strings.Fields(limitation), " "))
			}
		}
		for _, p := range capture.Paths {
			if len(p.OpenQuestions) == 0 && len(p.Limitations) == 0 {
				continue
			}
			fmt.Fprintf(&summary, "\n### Path `%s` · %s\n\n", p.ID, p.PathKind)
			for _, question := range p.OpenQuestions {
				fmt.Fprintf(&summary, "- unresolved: %s\n", strings.Join(strings.Fields(question), " "))
			}
			for _, limitation := range p.Limitations {
				fmt.Fprintf(&summary, "- limitation: %s\n", strings.Join(strings.Fields(limitation), " "))
			}
		}
		for _, limitation := range capture.Limitations {
			fmt.Fprintf(&summary, "\n- %s\n", limitation)
		}
		raw = append(raw, []byte(summary.String())...)
		metadata, err := json.MarshalIndent(capture, "", "  ")
		if err != nil {
			return nil, err
		}
		raw = append(raw, []byte("\n## Fixed input, provenance, coverage and open questions\n\n````json\n")...)
		raw = append(raw, metadata...)
		raw = append(raw, []byte("\n````\n")...)
	} else {
		var document map[string]any
		if json.Unmarshal(raw, &document) != nil {
			return nil, plugin.ErrInvalid
		}
		if config.Format == "sarif" {
			runs := document["runs"].([]any)
			run := runs[0].(map[string]any)
			run["properties"] = map[string]any{"capture": capture}
			byID := map[string]verify.Finding{}
			for _, item := range items {
				byID[item.ID] = item
			}
			for _, rawResult := range run["results"].([]any) {
				properties := rawResult.(map[string]any)["properties"].(map[string]any)
				finding := byID[properties["finding_id"].(string)]
				if finding.Severity != "" {
					properties["severity"] = finding.Severity
				}
				for _, p := range capture.Paths {
					if p.ID == finding.PathID {
						properties["path_kind"] = p.PathKind
						properties["open_questions"] = p.OpenQuestions
						break
					}
				}
			}
		} else {
			document["capture"] = capture
		}
		raw, err = json.MarshalIndent(document, "", "  ")
		if err != nil {
			return nil, err
		}
		raw = append(raw, '\n')
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}
