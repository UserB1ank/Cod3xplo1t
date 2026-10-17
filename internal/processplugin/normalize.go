package processplugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
)

var scannerAlertsSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	load := func(name string) (*jsonschema.Schema, error) {
		raw, err := contracts.Files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, err
		}
		return &schema, nil
	}
	schema, err := load("scanner-alerts.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, plugin.ErrInvalid
		}
		return load(path.Base(uri.Path))
	}})
})

const (
	defaultMaxAlerts = 200
	maxAlertTitle    = 200
	maxAlertMessage  = 1000
	maxAlertEvidence = 20
)

type scannerConfig struct {
	MaxAlerts int `json:"max_alerts"`
}

// Normalize binds raw scanner alerts to the verified invocation and emits only
// candidate observations. It never invents a path, a taint step or a verdict.
func Normalize(inv plugin.Invocation, native artifact.Ref, raw []byte) (plugin.DiscoveryDocument, error) {
	if int64(len(raw)) > wire.MaxReportBytes {
		return plugin.DiscoveryDocument{}, plugin.ErrBudget
	}
	var report wire.ScannerReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: decode", plugin.ErrInvalid)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: trailing", plugin.ErrInvalid)
	}
	if report.Format != wire.ScannerReportFormat {
		return plugin.DiscoveryDocument{}, plugin.ErrUnsupported
	}
	schema, err := scannerAlertsSchema()
	if err != nil {
		return plugin.DiscoveryDocument{}, plugin.ErrInvalid
	}
	var rawValue any
	if json.Unmarshal(raw, &rawValue) != nil || schema.Validate(rawValue) != nil {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: native report does not satisfy scanner-alerts.schema.json", plugin.ErrInvalid)
	}
	if report.Scope != inv.Request.Scope || native.Scope != inv.Request.Scope {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: scope", plugin.ErrInvalid)
	}
	if native.SHA256 != digest(raw) || native.Bytes != int64(len(raw)) || native.Producer.InvocationID != inv.ID {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: native", plugin.ErrInvalid)
	}
	expectedProducer := artifact.Producer{
		PluginID:      inv.Request.PluginID,
		PluginVersion: inv.Request.PluginVersion,
		InvocationID:  inv.ID,
		ConfigDigest:  inv.ConfigDigest,
	}
	if native.Producer != expectedProducer || native.Kind != "scanner.alerts" || native.SchemaID != "codexploit/scanner-alerts/v1" {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: producer", plugin.ErrInvalid)
	}
	if report.Tool.ID != inv.Request.PluginID || report.Tool.Version != inv.Request.PluginVersion || report.Tool.Ruleset == "" || len(report.Tool.Ruleset) > 160 {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: tool", plugin.ErrInvalid)
	}
	if !report.Capabilities.Alerts {
		return plugin.DiscoveryDocument{}, plugin.ErrUnsupported
	}
	if report.Capabilities.DataFlow || report.Capabilities.CallReachability || report.Capabilities.Network != "none" {
		return plugin.DiscoveryDocument{}, plugin.ErrUnsupported
	}
	if err := validCoverage(report.Coverage); err != nil {
		return plugin.DiscoveryDocument{}, err
	}
	if len(report.Limitations) > 20 {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: limitations", plugin.ErrInvalid)
	}
	for _, limitation := range report.Limitations {
		if len(limitation) > 1000 {
			return plugin.DiscoveryDocument{}, fmt.Errorf("%w: limitation-length", plugin.ErrInvalid)
		}
	}
	config := scannerConfig{MaxAlerts: defaultMaxAlerts}
	if len(inv.Request.Config) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(inv.Request.Config))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil || config.MaxAlerts < 0 || config.MaxAlerts > 500 {
			return plugin.DiscoveryDocument{}, fmt.Errorf("%w: config", plugin.ErrInvalid)
		}
	}
	if config.MaxAlerts == 0 {
		config.MaxAlerts = defaultMaxAlerts
	}
	if len(report.Alerts) > config.MaxAlerts || len(report.Alerts) > 500 {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: scanner returned more alerts than its approved budget", plugin.ErrInvalid)
	}

	candidates := make([]plugin.Candidate, 0, len(report.Alerts))
	seen := map[string]bool{}
	for _, alert := range report.Alerts {
		if err := validAlert(alert); err != nil {
			return plugin.DiscoveryDocument{}, fmt.Errorf("%w: alert %s", plugin.ErrInvalid, alert.ID)
		}
		if seen[alert.ID] {
			return plugin.DiscoveryDocument{}, fmt.Errorf("%w: duplicate %s", plugin.ErrInvalid, alert.ID)
		}
		seen[alert.ID] = true
		limitations := append([]string{}, alert.Limitations...)
		limitations = append(limitations,
			"Rule "+alert.RuleID+"@"+alert.RuleVersion+" reported this location",
			"Alert location only; the tool did not establish taint flow, control effectiveness or exploitability")
		message := strings.TrimSpace(alert.Message)
		if message != "" {
			limitations = append(limitations, message)
		}
		for _, evidence := range alert.Evidence {
			limitations = append(limitations, "Tool evidence: "+evidence)
		}
		candidates = append(candidates, plugin.Candidate{
			ID:           "obs-" + digest([]byte(inv.ID + "\x00" + alert.ID))[:32],
			Status:       "candidate",
			Title:        "[" + alert.RuleID + "] " + alert.Title,
			SeverityHint: alert.SeverityHint,
			PathRefs:     []string{},
			EvidenceRefs: []string{native.ID},
			File:         alert.File,
			Line:         alert.Line,
			Limitations:  limitations,
		})
	}
	limitations := append([]string{}, report.Limitations...)
	limitations = append(limitations, "Scanner results are candidate observations; no confirmed finding or severity assessment was written")
	if report.Coverage.Truncated {
		limitations = append(limitations, "The scanner reported truncated coverage")
	}
	document := plugin.DiscoveryDocument{
		APIVersion:     "codexploit/v1",
		Kind:           "security.facts",
		Scope:          report.Scope,
		Producer:       native.Producer,
		Inputs:         inv.Request.Inputs,
		NativeArtifact: native,
		CanonicalIDs:   []string{},
		Nodes:          []asg.Node{},
		Edges:          []asg.Edge{},
		Coverage:       report.Coverage,
		Limitations:    limitations,
		Paths:          []plugin.DiscoveryPath{},
		Candidates:     candidates,
	}
	if err := plugin.ValidateDiscovery(document); err != nil {
		return plugin.DiscoveryDocument{}, fmt.Errorf("%w: discovery %v", plugin.ErrInvalid, err)
	}
	return document, nil
}

func validCoverage(coverage plugin.Coverage) error {
	if coverage.InputFiles < 0 || coverage.ParsedFiles < 0 || coverage.PartialFiles < 0 || coverage.UnparsedFiles < 0 || coverage.UnhandledFiles < 0 || coverage.DescriptorFiles < 0 || coverage.InputBytes < 0 {
		return plugin.ErrInvalid
	}
	if coverage.ParsedFiles+coverage.PartialFiles+coverage.UnparsedFiles+coverage.UnhandledFiles+coverage.DescriptorFiles > coverage.InputFiles {
		return plugin.ErrInvalid
	}
	return nil
}

func validAlert(alert wire.ScannerAlert) error {
	if !validScannerID(alert.ID, 160) || !validRuleID(alert.RuleID) || alert.RuleVersion == "" || len(alert.RuleVersion) > 32 {
		return plugin.ErrInvalid
	}
	if alert.Title == "" || len(alert.Title) > maxAlertTitle || len(alert.Message) > maxAlertMessage {
		return plugin.ErrInvalid
	}
	if alert.SeverityHint != "high" && alert.SeverityHint != "medium" && alert.SeverityHint != "low" {
		return plugin.ErrInvalid
	}
	if !validSourcePath(alert.File) || alert.Line < 1 || (alert.EndLine != 0 && alert.EndLine < alert.Line) || alert.Column < 0 {
		return plugin.ErrInvalid
	}
	if len(alert.Evidence) > maxAlertEvidence || len(alert.Limitations) > 20 {
		return plugin.ErrInvalid
	}
	for _, evidence := range alert.Evidence {
		if len(evidence) > 500 {
			return plugin.ErrInvalid
		}
	}
	for _, limitation := range alert.Limitations {
		if len(limitation) > 1000 {
			return plugin.ErrInvalid
		}
	}
	return nil
}

func validScannerID(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for i, r := range value {
		alnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if i == 0 && !alnum {
			return false
		}
		if !alnum && r != '.' && r != '_' && r != ':' && r != '-' {
			return false
		}
	}
	return true
}

func validRuleID(value string) bool {
	if value == "" || len(value) > 64 || !((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validSourcePath(file string) bool {
	if file == "" || len(file) > 512 || strings.ContainsAny(file, "\\\x00\n\r:") || strings.HasPrefix(file, "/") {
		return false
	}
	cleaned := path.Clean(file)
	return cleaned == file && cleaned != "." && !strings.HasPrefix(cleaned, "../") && !strings.Contains(cleaned, "/../")
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
