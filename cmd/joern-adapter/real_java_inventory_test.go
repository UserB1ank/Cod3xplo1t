package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/pkg/pluginsdk"
)

// This test is opt-in because it requires the sealed Linux Joern package. The
// container supplies real Java parsing and CPGs; only orchestration crosses the
// process boundary.
func TestRealDockerJoernCatalogsJavaSinksAndPartitionsFlows(t *testing.T) {
	container := os.Getenv("JOERN_TEST_DOCKER_CONTAINER")
	sourcePackage := os.Getenv("JOERN_TEST_DOCKER_SOURCE_PACKAGE")
	if container == "" || sourcePackage == "" {
		t.Skip("set JOERN_TEST_DOCKER_CONTAINER and JOERN_TEST_DOCKER_SOURCE_PACKAGE")
	}
	arch := strings.TrimSpace(dockerText(t, container, "uname", "-m"))
	goarch := map[string]string{"aarch64": "arm64", "x86_64": "amd64"}[arch]
	if goarch == "" {
		t.Skipf("unsupported container architecture %s", arch)
	}
	host := t.TempDir()
	adapter := filepath.Join(host, "joern-adapter")
	build := exec.Command("go", "build", "-trimpath", "-o", adapter, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux adapter: %v %s", err, out)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	instance := "/data/codexploit-joern-real-" + suffix
	jobs := instance
	dockerRun(t, "exec", container, "mkdir", "-p", instance+"/bin", instance+"/scripts", jobs)
	t.Cleanup(func() {
		_ = exec.Command("docker", "exec", container, "rm", "-rf", instance).Run()
	})
	dockerRun(t, "exec", container, "ln", "-s", sourcePackage+"/vendor", instance+"/vendor")
	dockerCopy(t, adapter, container+":"+instance+"/bin/joern-adapter")
	for _, name := range []string{"taint.sc", "export.sc"} {
		dockerCopy(t, filepath.Join("..", "..", "plugins", "joern", name), container+":"+instance+"/scripts/"+name)
	}
	for _, name := range []string{"rules.json", "java-sinks.json", "frontends.json"} {
		dockerCopy(t, filepath.Join("..", "..", "plugins", "joern", name), container+":"+instance+"/"+name)
	}
	sourceArchive := tarTree(t, filepath.Join("testdata", "java_catalog"))

	parseRequest := pluginsdk.JobRequest{
		APIVersion: "codexploit/file-job/v2", InvocationID: "real-java-parse", PluginID: "codexploit.joern",
		PluginVersion: adapterVersion, OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs",
		Config: json.RawMessage(`{"frontend":"JAVASRC","heap_mib":2048}`),
		Budget: pluginsdk.Budget{TimeoutSeconds: 300, MaxInputBytes: 64 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 8},
		Inputs: []pluginsdk.LocalInput{{
			ArtifactID: "source-java", Port: "source", Kind: "source.snapshot",
			SchemaID: "codexploit/source-tar/v1", Path: "source.tar",
			Bytes: int64(len(sourceArchive)), SHA256: digest(sourceArchive),
		}},
	}
	dockerRun(t, "exec", container, "mkdir", "-p", jobs+"/parse-job")
	dockerExtractFiles(t, container, jobs+"/parse-job", map[string][]byte{
		"source.tar":   sourceArchive,
		"request.json": mustJSON(t, parseRequest),
	})
	dockerAdapter(t, container, instance+"/bin/joern-adapter", jobs+"/parse-job/request.json", jobs+"/parse-job/result.json")
	dockerCopy(t, container+":"+jobs+"/parse-job", filepath.Join(host, "parse-result"))
	parseResult := readJobResult(t, filepath.Join(host, "parse-result", "result.json"))
	if parseResult.Status != "PARTIAL" || len(parseResult.Outputs) < 2 {
		t.Fatalf("parse result: %+v", parseResult)
	}
	codeOutput, cpgOutput := jobOutput(t, parseResult, "code"), jobOutput(t, parseResult, "cpg")
	codeRaw, err := os.ReadFile(filepath.Join(host, "parse-result", "outputs", codeOutput.Path))
	if err != nil {
		t.Fatal(err)
	}
	cpgRaw, err := os.ReadFile(filepath.Join(host, "parse-result", "outputs", cpgOutput.Path))
	if err != nil {
		t.Fatal(err)
	}
	codeRaw = bindNativeMappings(t, codeRaw, "cpg-java")
	codeDocument := mustJSON(t, map[string]any{"data": json.RawMessage(codeRaw)})

	taintRequest := pluginsdk.JobRequest{
		APIVersion: "codexploit/file-job/v2", InvocationID: "real-java-taint", PluginID: "codexploit.joern",
		PluginVersion: adapterVersion, OperationID: "taint", Stage: pluginsdk.Semantic, OutputDirectory: "outputs",
		Config: json.RawMessage(`{"max_flows":100,"max_call_depth":6,"heap_mib":2048}`),
		Budget: pluginsdk.Budget{TimeoutSeconds: 300, MaxInputBytes: 64 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 8},
		Inputs: []pluginsdk.LocalInput{
			{ArtifactID: "source-java", Port: "source", Kind: "source.snapshot", SchemaID: "codexploit/source-tar/v1", Path: "source.tar", Bytes: int64(len(sourceArchive)), SHA256: digest(sourceArchive)},
			{ArtifactID: "code-java", Port: "code", Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Path: "code.json", Bytes: int64(len(codeDocument)), SHA256: digest(codeDocument)},
			{ArtifactID: "cpg-java", Port: "cpg", Kind: "tool.native", SchemaID: "joern/cpg/v1", Path: "cpg.bin", Bytes: int64(len(cpgRaw)), SHA256: digest(cpgRaw)},
		},
	}
	dockerRun(t, "exec", container, "mkdir", "-p", jobs+"/taint-job")
	dockerExtractFiles(t, container, jobs+"/taint-job", map[string][]byte{
		"source.tar":   sourceArchive,
		"code.json":    codeDocument,
		"cpg.bin":      cpgRaw,
		"request.json": mustJSON(t, taintRequest),
	})
	dockerAdapter(t, container, instance+"/bin/joern-adapter", jobs+"/taint-job/request.json", jobs+"/taint-job/result.json")
	dockerCopy(t, container+":"+jobs+"/taint-job", filepath.Join(host, "taint-result"))
	taintResult := readJobResult(t, filepath.Join(host, "taint-result", "result.json"))
	if taintResult.Status != "PARTIAL" {
		if raw, err := os.ReadFile(filepath.Join(host, "taint-result", "work", "flows-0.json")); err == nil {
			var report flowReport
			unmarshalErr := json.Unmarshal(raw, &report)
			for i := range report.Sinks {
				report.Sinks[i].CPG = "cpg-java"
			}
			for i := range report.Flows {
				report.Flows[i].CPG = "cpg-java"
			}
			var code codeData
			codeErr := json.Unmarshal(codeRaw, &code)
			_, factsErr := securityFacts(report, code)
			t.Logf("native unmarshal=%v code=%v facts=%v sinks=%d flows=%d", unmarshalErr, codeErr, factsErr, len(report.Sinks), len(report.Flows))
			for i, match := range report.Sinks {
				t.Logf("sink[%d]=%s category=%s cpg=%q node=%q evidence=%s priority=%v", i, match.RuleID, match.Category, match.CPG, match.Node.ID, match.Evidence, match.Priority)
			}
			for i, flow := range report.Flows {
				t.Logf("flow[%d]=%s cpg=%q catalog=%v nodes=%d", i, flow.RuleID, flow.CPG, flow.SinkCatalogIDs, len(flow.Nodes))
			}
		}
		if entries, err := os.ReadDir(filepath.Join(host, "taint-result", "work")); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") {
					if data, err := os.ReadFile(filepath.Join(host, "taint-result", "work", entry.Name())); err == nil {
						size := len(data)
						if len(data) > 2000 {
							data = data[:2000]
						}
						t.Logf("work/%s (%d bytes): %s", entry.Name(), size, data)
					}
				}
			}
		}
		t.Fatalf("taint result: %+v", taintResult)
	}
	flowRaw, err := os.ReadFile(filepath.Join(host, "taint-result", "outputs", jobOutput(t, taintResult, "flows").Path))
	if err != nil {
		t.Fatal(err)
	}
	var report flowReport
	if json.Unmarshal(flowRaw, &report) != nil || report.Catalog.ID != "java-sink-catalog" || len(report.Catalog.Digest) != 64 {
		t.Fatalf("native flow report: %s", flowRaw)
	}
	partitionStatuses := map[string]string{}
	partitionCandidates := map[string]int{}
	for _, partition := range report.Partitions {
		partitionStatuses[partition.ID] = partition.Status
		partitionCandidates[partition.ID] = partition.CandidateSinks
		switch partition.Status {
		case "complete", "truncated", "pending":
		default:
			t.Errorf("partition %s has invalid status %q", partition.ID, partition.Status)
		}
	}
	for _, want := range []string{
		"catalog:process_execution", "catalog:deserialization", "catalog:expression_injection",
		"catalog:jndi", "catalog:xxe", "catalog:sql_execution", "catalog:template_injection",
	} {
		if partitionStatuses[want] == "" {
			t.Errorf("partition %s is absent from the persisted ledger", want)
		}
		if partitionCandidates[want] == 0 {
			t.Errorf("partition %s did not record catalogue candidates", want)
		}
	}
	ids := map[string]bool{}
	for _, sink := range report.Sinks {
		ids[sink.RuleID] = true
	}
	flowRules := map[string]bool{}
	for _, flow := range report.Flows {
		flowRules[flow.RuleID] = true
	}
	for _, want := range []string{
		"java.process.runtime-exec",
		"java.deserialization.object-input", "java.deserialization.xml-decoder",
		"java.expression.spel",
		"java.jndi.initial-context-lookup", "java.jndi.context-lookup",
		"java.xxe.document-builder", "java.sql.statement-execute-query",
		"java.sql.mybatis-sqlsession-select", "java.sql.hibernate-session-query",
		"java.template.freemarker-get-template", "java.template.spring-process",
	} {
		if !ids[want] {
			t.Errorf("real Java CPG missed inventory entry %s", want)
		}
	}
	for _, want := range []string{
		"catalog:process_execution", "catalog:deserialization", "catalog:expression_injection",
		"catalog:jndi", "catalog:xxe", "catalog:sql_execution", "catalog:template_injection",
	} {
		if !flowRules[want] {
			t.Errorf("high-risk partition %s produced no real flow; rules=%v", want, flowRules)
		}
	}
	if ids["java.sql.statement-execute"] && len(report.Sinks) < 6 {
		t.Errorf("inventory is suspiciously narrow: %+v", ids)
	}
	securityRaw, err := os.ReadFile(filepath.Join(host, "taint-result", "outputs", jobOutput(t, taintResult, "security").Path))
	if err != nil {
		t.Fatal(err)
	}
	var security struct {
		Sinks   []map[string]any
		Ruleset map[string]any
	}
	if json.Unmarshal(securityRaw, &security) != nil || len(security.Sinks) < 6 || security.Ruleset["catalog_digest"] != report.Catalog.Digest {
		t.Fatalf("security inventory: %s", securityRaw)
	}
	limitedRequest := taintRequest
	limitedRequest.InvocationID = "real-java-taint-limited"
	limitedRequest.OutputDirectory = "limited-outputs"
	limitedRequest.Config = json.RawMessage(`{"max_flows":4,"max_call_depth":6,"heap_mib":2048}`)
	dockerRun(t, "exec", container, "mkdir", "-p", jobs+"/limited-taint-job")
	dockerExtractFiles(t, container, jobs+"/limited-taint-job", map[string][]byte{
		"source.tar":   sourceArchive,
		"code.json":    codeDocument,
		"cpg.bin":      cpgRaw,
		"request.json": mustJSON(t, limitedRequest),
	})
	dockerAdapter(t, container, instance+"/bin/joern-adapter", jobs+"/limited-taint-job/request.json", jobs+"/limited-taint-job/result.json")
	dockerCopy(t, container+":"+jobs+"/limited-taint-job", filepath.Join(host, "limited-taint-result"))
	limitedResult := readJobResult(t, filepath.Join(host, "limited-taint-result", "result.json"))
	if limitedResult.Status != "PARTIAL" {
		t.Fatalf("limited partition result: %+v", limitedResult)
	}
	limitedRaw, err := os.ReadFile(filepath.Join(host, "limited-taint-result", "limited-outputs", jobOutput(t, limitedResult, "flows").Path))
	if err != nil {
		t.Fatal(err)
	}
	var limited flowReport
	if json.Unmarshal(limitedRaw, &limited) != nil || !limited.Truncated {
		t.Fatalf("limited partition report: %s", limitedRaw)
	}
	if limited.CatalogSinkMatchCount < limited.CatalogSinkNodeCount || limited.CatalogSinkNodeCount == 0 {
		t.Fatalf("deduplicated sink counts = %+v", limited)
	}
	catalogBudget, fallbackBudget := 0, 0
	pending := 0
	for _, partition := range limited.Partitions {
		switch partition.Kind {
		case "catalog":
			catalogBudget += partition.FlowBudget
		case "fallback":
			fallbackBudget += partition.FlowBudget
		}
		if partition.Status == "pending" || partition.Status == "truncated" {
			pending++
		}
	}
	if catalogBudget > 3 || fallbackBudget > 1 || pending == 0 {
		t.Fatalf("80/20 partition budgets were not preserved: catalog=%d fallback=%d pending=%d", catalogBudget, fallbackBudget, pending)
	}
	securityDocument := mustJSON(t, map[string]any{"data": json.RawMessage(securityRaw)})
	pathsRequest := pluginsdk.JobRequest{
		APIVersion: "codexploit/file-job/v2", InvocationID: "real-java-paths", PluginID: "codexploit.joern",
		PluginVersion: adapterVersion, OperationID: "paths", Stage: pluginsdk.PathGenerate, OutputDirectory: "outputs",
		Config: json.RawMessage(`{}`),
		Budget: pluginsdk.Budget{TimeoutSeconds: 60, MaxInputBytes: 64 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 4},
		Inputs: []pluginsdk.LocalInput{
			{ArtifactID: "code-java", Port: "code", Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Path: "code.json", Bytes: int64(len(codeDocument)), SHA256: digest(codeDocument)},
			{ArtifactID: "security-java", Port: "security", Kind: "security.facts", SchemaID: "codexploit/security-facts/v2", Path: "security.json", Bytes: int64(len(securityDocument)), SHA256: digest(securityDocument)},
			{ArtifactID: "flows-java", Port: "flows", Kind: "tool.native", SchemaID: "codexploit/native-bytes/v1", Path: "flows.json", Bytes: int64(len(flowRaw)), SHA256: digest(flowRaw)},
		},
	}
	dockerRun(t, "exec", container, "mkdir", "-p", jobs+"/paths-job")
	dockerExtractFiles(t, container, jobs+"/paths-job", map[string][]byte{
		"code.json":     codeDocument,
		"security.json": securityDocument,
		"flows.json":    flowRaw,
		"request.json":  mustJSON(t, pathsRequest),
	})
	dockerAdapter(t, container, instance+"/bin/joern-adapter", jobs+"/paths-job/request.json", jobs+"/paths-job/result.json")
	dockerCopy(t, container+":"+jobs+"/paths-job", filepath.Join(host, "paths-result"))
	pathsResult := readJobResult(t, filepath.Join(host, "paths-result", "result.json"))
	if pathsResult.Status != "PARTIAL" {
		t.Fatalf("paths result: %+v", pathsResult)
	}
	pathsRaw, err := os.ReadFile(filepath.Join(host, "paths-result", "outputs", jobOutput(t, pathsResult, "paths").Path))
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Paths []struct {
			ID           string   `json:"id"`
			PriorityHint float64  `json:"priority_hint"`
			Limitations  []string `json:"limitations"`
		}
	}
	if json.Unmarshal(pathsRaw, &generated) != nil || len(generated.Paths) == 0 {
		t.Fatalf("generated paths: %s", pathsRaw)
	}
	maxHint := 0.0
	for _, path := range generated.Paths {
		if path.PriorityHint > maxHint {
			maxHint = path.PriorityHint
		}
		joined := strings.Join(path.Limitations, " ")
		if !strings.Contains(joined, "java.") || !strings.Contains(joined, report.Catalog.Digest) {
			t.Errorf("path %s does not pin its catalogue rule and digest: %v", path.ID, path.Limitations)
		}
	}
	if maxHint == 0 {
		t.Fatalf("catalogue priority was not propagated to paths: %s", pathsRaw)
	}

	pathsDocument := mustJSON(t, map[string]any{"data": json.RawMessage(pathsRaw)})
	enhanceRequest := pluginsdk.JobRequest{
		APIVersion: "codexploit/file-job/v2", InvocationID: "real-java-enhance", PluginID: "codexploit.joern",
		PluginVersion: adapterVersion, OperationID: "enhance", Stage: pluginsdk.PathEnhance, OutputDirectory: "outputs",
		Config: json.RawMessage(`{}`),
		Budget: pluginsdk.Budget{TimeoutSeconds: 60, MaxInputBytes: 64 << 20, MaxOutputBytes: 64 << 20, MaxOutputFiles: 4},
		Inputs: []pluginsdk.LocalInput{{ArtifactID: "paths-java", Port: "paths", Kind: "discovery.paths", SchemaID: "codexploit/discovery-paths/v2", Path: "paths.json", Bytes: int64(len(pathsDocument)), SHA256: digest(pathsDocument)}},
	}
	dockerRun(t, "exec", container, "mkdir", "-p", jobs+"/enhance-job")
	dockerExtractFiles(t, container, jobs+"/enhance-job", map[string][]byte{
		"paths.json":   pathsDocument,
		"request.json": mustJSON(t, enhanceRequest),
	})
	dockerAdapter(t, container, instance+"/bin/joern-adapter", jobs+"/enhance-job/request.json", jobs+"/enhance-job/result.json")
	dockerCopy(t, container+":"+jobs+"/enhance-job", filepath.Join(host, "enhance-result"))
	enhanceResult := readJobResult(t, filepath.Join(host, "enhance-result", "result.json"))
	selectionRaw, err := os.ReadFile(filepath.Join(host, "enhance-result", "outputs", jobOutput(t, enhanceResult, "selection").Path))
	if err != nil {
		t.Fatal(err)
	}
	var selection struct {
		Version  string `json:"scoring_version"`
		Selected []struct {
			ID      string   `json:"path_id"`
			Score   float64  `json:"score"`
			Reasons []string `json:"reason_codes"`
		} `json:"selected"`
	}
	if json.Unmarshal(selectionRaw, &selection) != nil || selection.Version != "joern.static-support/v2" || len(selection.Selected) == 0 {
		t.Fatalf("selection: %s", selectionRaw)
	}
	if !slices.Contains(selection.Selected[0].Reasons, "catalog_priority") || selection.Selected[0].Score < 1+maxHint/2-0.000001 {
		t.Fatalf("high-risk catalogue path was not ordered first: %s", selectionRaw)
	}
}

func TestRealDockerJoernParsesSpringSourceDirectory(t *testing.T) {
	container := os.Getenv("JOERN_TEST_DOCKER_CONTAINER")
	sourcePackage := os.Getenv("JOERN_TEST_DOCKER_SOURCE_PACKAGE")
	sourceDirectory := os.Getenv("JOERN_TEST_DOCKER_SOURCE_DIRECTORY")
	if container == "" || sourcePackage == "" || sourceDirectory == "" {
		t.Skip("set JOERN_TEST_DOCKER_CONTAINER, JOERN_TEST_DOCKER_SOURCE_PACKAGE and JOERN_TEST_DOCKER_SOURCE_DIRECTORY")
	}
	arch := strings.TrimSpace(dockerText(t, container, "uname", "-m"))
	goarch := map[string]string{"aarch64": "arm64", "x86_64": "amd64"}[arch]
	if goarch == "" {
		t.Skipf("unsupported container architecture %s", arch)
	}
	host := t.TempDir()
	adapter := filepath.Join(host, "joern-adapter")
	build := exec.Command("go", "build", "-trimpath", "-o", adapter, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux adapter: %v %s", err, out)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	instance := "/data/codexploit-joern-spring-" + suffix
	job := instance + "/spring-parse"
	dockerRun(t, "exec", container, "mkdir", "-p", instance+"/bin", instance+"/scripts", job+"/outputs", job+"/work")
	t.Cleanup(func() {
		_ = exec.Command("docker", "exec", container, "rm", "-rf", instance).Run()
	})
	dockerRun(t, "exec", container, "ln", "-s", sourcePackage+"/vendor", instance+"/vendor")
	dockerCopy(t, adapter, container+":"+instance+"/bin/joern-adapter")
	for _, name := range []string{"taint.sc", "export.sc"} {
		dockerCopy(t, filepath.Join("..", "..", "plugins", "joern", name), container+":"+instance+"/scripts/"+name)
	}
	for _, name := range []string{"rules.json", "java-sinks.json", "frontends.json"} {
		dockerCopy(t, filepath.Join("..", "..", "plugins", "joern", name), container+":"+instance+"/"+name)
	}
	request := pluginsdk.JobRequest{
		APIVersion: "codexploit/file-job/v2", InvocationID: "real-spring-parse", PluginID: "codexploit.joern",
		PluginVersion: adapterVersion, OperationID: "parse", Stage: pluginsdk.Parse, OutputDirectory: "outputs",
		Config: json.RawMessage(`{"frontend":"JAVASRC","heap_mib":4096}`),
		Budget: pluginsdk.Budget{TimeoutSeconds: 900, MaxInputBytes: 500 << 20, MaxOutputBytes: 512 << 20, MaxOutputFiles: 16},
		Inputs: []pluginsdk.LocalInput{{
			ArtifactID: "spring-source", Port: "source", Kind: "source.snapshot",
			SchemaID: "codexploit/source-directory/v1", Path: sourceDirectory,
			Bytes: 64 << 20, SHA256: strings.Repeat("0", 64),
		}},
	}
	dockerExtractFiles(t, container, job, map[string][]byte{"request.json": mustJSON(t, request)})
	dockerAdapter(t, container, instance+"/bin/joern-adapter", job+"/request.json", job+"/result.json")
	result := dockerJobResult(t, container, job+"/result.json")
	if result.Status != "PARTIAL" || len(result.Outputs) < 2 {
		t.Fatalf("Spring parse did not retain real outputs: %+v", result)
	}
	var seen, analyzed, skipped, failed int64
	if result.Coverage.Seen != nil {
		seen = *result.Coverage.Seen
	}
	if result.Coverage.Analyzed != nil {
		analyzed = *result.Coverage.Analyzed
	}
	if result.Coverage.Skipped != nil {
		skipped = *result.Coverage.Skipped
	}
	if result.Coverage.Failed != nil {
		failed = *result.Coverage.Failed
	}
	if seen < 11000 || analyzed < 5000 || failed == 0 || skipped+failed != seen-analyzed {
		failedExamples := dockerCodeFailureExamples(t, container, job, result)
		t.Fatalf("Spring parse did not consume the source inventory: seen=%d analyzed=%d skipped=%d failed=%d unit=%q truncated=%t reasons=%v failures=%v", seen, analyzed, skipped, failed, result.Coverage.Unit, result.Coverage.Truncated, result.Coverage.Reasons, failedExamples)
	}
}

func dockerText(t *testing.T, container string, args ...string) string {
	t.Helper()
	command := exec.Command("docker", append([]string{"exec", container}, args...)...)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s: %v %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func dockerRun(t *testing.T, args ...string) {
	t.Helper()
	command := exec.Command("docker", args...)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("docker %s: %v %s", strings.Join(args, " "), err, out)
	}
}

func dockerCopy(t *testing.T, source, target string) {
	t.Helper()
	dockerRun(t, "cp", source, target)
}

func dockerAdapter(t *testing.T, container, binary, request, response string) {
	t.Helper()
	command := exec.Command("docker", "exec", container, binary, "--request", request, "--response", response)
	out, err := command.CombinedOutput()
	if err == nil {
		return
	}
	listing := dockerTextAllow(container, "find", filepath.Dir(strings.TrimPrefix(request, container+":")), "-maxdepth", "2", "-type", "f", "-print")
	result := dockerTextAllow(container, "cat", response)
	t.Fatalf("adapter %s: %v\noutput=%s\nfiles=%s\nresult=%s", filepath.Base(binary), err, out, listing, result)
}

func dockerTextAllow(container string, args ...string) string {
	out, _ := exec.Command("docker", append([]string{"exec", "-u", "0", container}, args...)...).CombinedOutput()
	return string(out)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readJobResult(t *testing.T, path string) pluginsdk.JobResult {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result pluginsdk.JobResult
	if json.Unmarshal(raw, &result) != nil {
		t.Fatalf("invalid job result: %s", raw)
	}
	return result
}

func dockerJobResult(t *testing.T, container, path string) pluginsdk.JobResult {
	t.Helper()
	command := exec.Command("docker", "exec", container, "cat", path)
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("read job result: %v", err)
	}
	var result pluginsdk.JobResult
	if json.Unmarshal(raw, &result) != nil {
		t.Fatalf("invalid container job result: %s", raw)
	}
	return result
}

func dockerCodeFailureExamples(t *testing.T, container, job string, result pluginsdk.JobResult) []string {
	t.Helper()
	output := jobOutput(t, result, "code")
	command := exec.Command("docker", "exec", container, "cat", job+"/outputs/"+output.Path)
	raw, err := command.Output()
	if err != nil {
		return []string{"code output unavailable"}
	}
	type fileStatus struct {
		Path   string `json:"path"`
		Status string `json:"parse_status"`
		Reason string `json:"reason"`
	}
	var document struct {
		Files []fileStatus `json:"files"`
		Data  struct {
			Files []fileStatus `json:"files"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return []string{"invalid code output"}
	}
	files := document.Files
	if len(files) == 0 {
		files = document.Data.Files
	}
	examples := []string{}
	for _, file := range files {
		if file.Status == "unparsed" && len(examples) < 8 {
			examples = append(examples, file.Path+" ("+file.Reason+")")
		}
	}
	return examples
}

func jobOutput(t *testing.T, result pluginsdk.JobResult, port string) pluginsdk.LocalOutput {
	t.Helper()
	for _, output := range result.Outputs {
		if output.Port == port {
			return output
		}
	}
	t.Fatalf("result has no %s output: %+v", port, result.Outputs)
	return pluginsdk.LocalOutput{}
}

func tarTree(t *testing.T, root string) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(&tar.Header{Name: filepath.ToSlash(name), Mode: 0444, Size: int64(len(body))}); err != nil {
			return err
		}
		_, err = writer.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func dockerExtractFiles(t *testing.T, container, destination string, files map[string][]byte) {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for name, body := range files {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("docker", "exec", "-i", container, "tar", "-xf", "-", "-C", destination)
	command.Stdin = bytes.NewReader(archive.Bytes())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("extract job files: %v %s", err, out)
	}
}

func bindNativeMappings(t *testing.T, raw []byte, artifactID string) []byte {
	t.Helper()
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("invalid code facts")
	}
	mappings, ok := document["native_id_mappings"].([]any)
	if !ok || len(mappings) == 0 {
		t.Fatal("code facts have no native mappings")
	}
	for _, rawMapping := range mappings {
		mapping, ok := rawMapping.(map[string]any)
		if !ok {
			t.Fatal("invalid native mapping")
		}
		mapping["native_artifact_ref"] = artifactID
	}
	out, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
